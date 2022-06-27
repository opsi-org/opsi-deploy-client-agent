# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
windows deployment module

This module contains the class WindowsDeployThread and related methods.
"""

from contextlib import contextmanager
import shutil
import re
import os
import logging
import tempfile
from typing import Generator
import pypsexec.client  # type: ignore[import]
from pypsexec.exceptions import SCMRException  # type: ignore[import]

from opsicommon.logging import logger  # type: ignore[import]
from opsicommon.types import forceUnicode  # type: ignore[import]

from opsideployclientagent.common import DeployThread, execute, FiletransferUnsuccessful


class WindowsDeployThread(DeployThread):
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self,
		host,
		backend,
		username,
		password,
		finalize_action="start_service",
		deployment_method="hostname",
		stop_on_ping_failure=True,
		skip_existing_client=False,
		mount_with_smbclient=True,
		keep_client_on_failure=False,
		additional_client_settings=None,
		depot=None,
		group=None,
		install_timeout=None,
	):
		DeployThread.__init__(
			self,
			host,
			backend,
			username,
			password,
			finalize_action,
			deployment_method,
			stop_on_ping_failure,
			skip_existing_client,
			mount_with_smbclient,
			keep_client_on_failure,
			additional_client_settings,
			depot,
			group,
			install_timeout,
		)

		self.mount_point = None
		self.mounted_oca_dir = None

	@contextmanager
	def establish_connection(self, host) -> Generator[pypsexec.client.Client, None, None]:
		psexec_connection: pypsexec.client.Client = None
		try:
			host = forceUnicode(host)
			username = forceUnicode(self.username)
			password = forceUnicode(self.password)

			match = re.search(r"^([^\\\\]+)\\\\+([^\\\\]+)$", username)
			if match:
				username = match.group(1) + r"\\" + match.group(2)
			psexec_connection = pypsexec.client.Client(host, username=username, password=password)  # TODO: encrypt=False for win7
			psexec_connection.connect()
			psexec_connection.create_service()
			yield psexec_connection
		finally:
			if psexec_connection:
				psexec_connection.cleanup()
				try:
					psexec_connection.remove_service()
				# see https://github.com/jborean93/pypsexec/issues/16
				except SCMRException as exc:
					if exc.return_code != 1072:  # ERROR_SERVICE_MARKED_FOR_DELETE
						raise
				psexec_connection.disconnect()

	def psexec(self, command, host=None, timeout=None):
		host = host or self.network_address
		arguments = f"/c {command}"
		with self.establish_connection(host) as connection:
			stdout, stderr, rc = connection.run_executable("cmd.exe", arguments=arguments, timeout_seconds=timeout)
			logger.debug("stdout:\n%s", stdout)
			logger.debug("stderr:\n%s", stderr)
			return rc

	def copy_data(self):
		logger.notice("Copying installation files")
		try:
			if self.mount_with_smbclient:
				logger.debug('Installing using smbclient.')
				return self.copy_data_smbclient()
			logger.debug('Installing using server-side mount.')
			return self.copy_data_serverside_mount()
		except Exception as error:  # pylint: disable=broad-except
			logger.error("Failed to copy installation files: %s", error, exc_info=True)
			raise FiletransferUnsuccessful from error

	def copy_data_smbclient(self):
		credentials = self.username + "%" + self.password.replace("'", "'\"'\"'")
		debug_param = " -d 9" if logger.isEnabledFor(logging.DEBUG) else ""
		smbclient_cmd = shutil.which('smbclient')
		if not smbclient_cmd:
			logger.critical("Unable to find 'smbclient'.")
			raise RuntimeError("Command 'smbclient' not found in PATH")

		cmd = (
			f"{smbclient_cmd} -m SMB3{debug_param} //{self.network_address}/c$ -U '{credentials}'"
			" -c 'prompt; recurse;"
			" md opsi.org; cd opsi.org; md log; md tmp; cd tmp; deltree opsi-client-agent_inst; md opsi-client-agent_inst;"
			" cd opsi-client-agent_inst; mput files; mput setup.opsiscript; mput oca-installation-helper.exe; exit;'"
		)
		execute(cmd)
		return "c:\\opsi.org\\tmp\\opsi-client-agent_inst"

	def copy_data_serverside_mount(self):
		self.mount_point = tempfile.TemporaryDirectory().name  # pylint: disable=consider-using-with

		logger.notice("Mounting c$ share")
		mount_cmd = shutil.which("mount")
		if not mount_cmd:
			logger.critical("Unable to find 'mount'.")
			raise RuntimeError("Command 'mount' not found in PATH")
		try:
			password = self.password.replace("'", "'\"'\"'")
			try:
				execute(
					f"{mount_cmd} -t cifs -o'username={self.username},password={password}' //{self.network_address}/c$ {self.mount_point}",
					timeout=15,
				)
			except Exception as err:  # pylint: disable=broad-except
				logger.info("Failed to mount clients c$ share: %s, retrying with port 139", err)
				execute(
					f"{mount_cmd} -t cifs -o'port=139,username={self.username},password={password}' //{self.network_address}/c$ {self.mount_point}",
					timeout=15,
				)
		except Exception as err:  # pylint: disable=broad-except
			raise Exception(
				f"Failed to mount c$ share: {err}\n"
				"Perhaps you have to disable the firewall or simple file sharing on the windows machine (folder options)?"
			) from err

		logger.notice("Copying installation files")
		self.mounted_oca_dir = os.path.join(self.mount_point, "opsi.org", "tmp", "opsi-client-agent_inst")
		os.makedirs(self.mounted_oca_dir, exist_ok=True)

		shutil.copytree("files", self.mounted_oca_dir)
		shutil.copytree("custom", self.mounted_oca_dir)
		shutil.copy("setup.opsiscript", self.mounted_oca_dir)
		shutil.copy("oca-installation-helper.exe", self.mounted_oca_dir)
		return "c:\\opsi.org\\tmp\\opsi-client-agent_inst"

	def run_installation(self, remote_folder):
		logger.info("Deploying from path %s", remote_folder)
		install_command = (
			f"{remote_folder}/oca-installation-helper.exe"
			f" --service-address {self._get_service_address(self.host_object.id)}"
			f" --service-username {self.host_object.id}"
			f" --service-password {self.host_object.opsiHostKey}"
			f" --client-id {self.host_object.id}"
			f" --no-gui --non-interactive"
		)
		self._set_client_agent_to_installing(self.host_object.id, self.product_id)
		logger.notice("Running installation script...")
		try:
			self.psexec(install_command, timeout=self.install_timeout)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Failed to install %s: %s", self.product_id, err)
			raise

	def finalize(self):
		cmd = ""
		if self.finalize_action == "reboot":
			logger.notice("Rebooting machine %s", self.network_address)
			cmd = r'"shutdown.exe" /r /t 30 /c "opsi-client-agent installed - reboot"'
		elif self.finalize_action == "shutdown":
			logger.notice("Shutting down machine %s", self.network_address)
			cmd = r'"shutdown.exe" /s /t 30 /c "opsi-client-agent installed - shutdown"'
		# start_service is performed as last action of the setup.opsiscript
		# default case is do nothing
		if cmd:
			try:
				# finalization is not allowed to take longer than 2 minutes
				self.psexec(cmd, timeout=120)
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to %s on %s: %s", self.finalize_action, self.network_address, err)

	def cleanup(self, remote_folder):
		logger.notice("Cleaning up")

		if self.mounted_oca_dir:  # in case of serverside mount
			try:
				shutil.rmtree(self.mounted_oca_dir)
			except OSError as err:
				logger.debug("Removing %s failed: %s", self.mounted_oca_dir, err, exc_info=True)
		elif remote_folder:  # in case of smbclient
			try:
				cmd = f'cmd.exe /C "rmdir /s /q {remote_folder}'
				# cleanup is not allowed to take longer than 2 minutes
				self.psexec(cmd, timeout=120)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Removing %s failed: %s", remote_folder, err, exc_info=True)

		if self.mount_point:
			try:
				execute(f"umount {self.mount_point}")
			except Exception as err:  # pylint: disable=broad-except
				logger.warning("Unmounting %s failed: %s", self.mount_point, err, exc_info=True)
			try:
				os.rmdir(self.mount_point)
			except OSError as err:
				logger.debug("Removing %s failed: %s", self.mount_point, err, exc_info=True)

	def ask_host_for_hostname(self, host):
		# preferably host should be an ip
		try:
			output = self.psexec('cmd.exe /C "echo %COMPUTERNAME%"', host=host)
			for line in output:
				if line.strip():
					if "unknown parameter" in line.lower():
						continue

					host_id = line.strip()
					break
		except Exception as err:
			logger.debug("Name lookup via psexec failed: %s", err)
			raise ValueError(f"Can't find name for IP {host}: {err}") from err

		logger.debug("Lookup of IP returned hostname %s", host_id)
		return host_id
