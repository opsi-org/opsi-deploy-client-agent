# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
windows deployment module

This module contains the class WindowsDeployThread and related methods.
"""

import shutil
import re
import os
import logging
import tempfile

from opsicommon.logging import logger
from opsicommon.types import forceUnicode

from opsideployclientagent.common import DeployThread, execute


def winexe(cmd, host, username, password, timeout=None):
	cmd = forceUnicode(cmd)
	host = forceUnicode(host)
	username = forceUnicode(username)
	password = forceUnicode(password)

	match = re.search(r'^([^\\\\]+)\\\\+([^\\\\]+)$', username)
	if match:
		username = match.group(1) + r'\\' + match.group(2)

	try:
		executable = execute("which winexe")[0]
	except Exception as err:  # pylint: disable=broad-except
		logger.critical(
			"Unable to find 'winexe'. Please install 'opsi-windows-support' "
			"through your operating systems package manager!"
		)
		raise RuntimeError("Missing 'winexe'") from err

	try:
		logger.info('Winexe Version: %s', execute(f'{executable} -V')[0])
	except Exception as err:  # pylint: disable=broad-except
		logger.warning("Failed to get version: %s", err)

	credentials=username + '%' + password.replace("'", "'\"'\"'")
	if logger.isEnabledFor(logging.DEBUG):
		return execute(f"{executable} -d 9 -U '{credentials}' //{host} '{cmd}'", timeout=timeout)
	return execute(f"{executable} -U '{credentials}' //{host} '{cmd}'", timeout=timeout)

class WindowsDeployThread(DeployThread):
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, host, backend, username, password, finalize_action="start_service",
		deployment_method="hostname", stop_on_ping_failure=True,
		skip_existing_client=False, mount_with_smbclient=True,
		keep_client_on_failure=False, additional_client_settings=None,
		depot=None, group=None, install_timeout=None
	):
		DeployThread.__init__(
			self, host, backend, username, password, finalize_action,
			deployment_method, stop_on_ping_failure,
			skip_existing_client, mount_with_smbclient, keep_client_on_failure,
			additional_client_settings, depot, group, install_timeout
		)

		self.mount_point = None
		self.mounted_oca_dir = None


	def copy_data(self):
		logger.notice("Copying installation files")
		if self.mount_with_smbclient:
			logger.debug('Installing using client-side mount.')
			return self.copy_data_clientside_mount()
		logger.debug('Installing using server-side mount.')
		return self.copy_data_serverside_mount()


	def copy_data_clientside_mount(self):
		credentials=self.username + '%' + self.password.replace("'", "'\"'\"'")
		debug_param = " -d 9" if logger.isEnabledFor(logging.DEBUG) else ""
		smbclient_cmd = execute("which smbclient")[0]
		cmd = (
			f"{smbclient_cmd} -m SMB3{debug_param} //{self.network_address}/c$ -U '{credentials}'"
			" -c 'prompt; recurse;"
			" md opsi.org; cd opsi.org; md log; md tmp; cd tmp; deltree opsi-client-agent_inst; md opsi-client-agent_inst;"
			" cd opsi-client-agent_inst; mput files; mput setup.opsiscript; mput oca-installation-helper.exe; exit;'"
		)
		execute(cmd)
		return "c:\\opsi.org\\tmp\\opsi-client-agent_inst"

	def copy_data_serverside_mount(self):
		self.mount_point = tempfile.TemporaryDirectory().name

		logger.notice("Mounting c$ share")
		mount_cmd = execute("which mount")[0]
		try:
			password = self.password.replace("'", "'\"'\"'")
			try:
				execute(f"{mount_cmd} -t cifs -o'username={self.username},password={password}' //{self.network_address}/c$ {self.mount_point}",
					timeout=15
				)
			except Exception as err:  # pylint: disable=broad-except
				logger.info("Failed to mount clients c$ share: %s, retrying with port 139", err)
				execute(f"{mount_cmd} -t cifs -o'port=139,username={self.username},password={password}' //{self.network_address}/c$ {self.mount_point}",
					timeout=15
				)
		except Exception as err:  # pylint: disable=broad-except
			raise Exception(
				f"Failed to mount c$ share: {err}\n"
				"Perhaps you have to disable the firewall or simple file sharing on the windows machine (folder options)?"
			) from err

		logger.notice("Copying installation files")
		self.mounted_oca_dir = os.path.join(self.mount_point, "opsi.org", "tmp", "opsi-client-agent_inst")
		os.makedirs(self.mounted_oca_dir, exist_ok=True)

		shutil.copytree('files', self.mounted_oca_dir)
		shutil.copytree('custom', self.mounted_oca_dir)
		shutil.copy('setup.opsiscript', self.mounted_oca_dir)
		shutil.copy('oca-installation-helper.exe', self.mounted_oca_dir)
		return "c:\\opsi.org\\tmp\\opsi-client-agent_inst"


	def run_installation(self, remote_folder):
		logger.info("deploying from path %s", remote_folder)
		self._test_winexe_connection()
		install_command = (
			f"{remote_folder}/oca-installation-helper.exe"
			f" --service-address {self._get_service_address(self.host_object.id)}"
			f" --service-username {self.host_object.id}"
			f" --service-password {self.host_object.opsiHostKey}"
			f" --client-id {self.host_object.id}"
			f" --no-gui --non-interactive"
		)
		self._set_client_agent_to_installing(self.host_object.id, self.product_id)
		logger.notice('Running installation script...')
		try:
			winexe(install_command, self.network_address, self.username, self.password, timeout=self.install_timeout)
		except Exception as err:  # pylint: disable=broad-except
			raise Exception(f"Failed to install {self.product_id}: {err}") from err


	def finalize(self):
		cmd = ""
		if self.finalize_action == "reboot":
			logger.notice("Rebooting machine %s", self.network_address)
			cmd = r'"shutdown.exe" /r /t 30 /c "opsi-client-agent installed - reboot"'
		elif self.finalize_action == "shutdown":
			logger.notice("Shutting down machine %s", self.network_address)
			cmd = r'"shutdown.exe" /s /t 30 /c "opsi-client-agent installed - shutdown"'
		elif self.finalize_action == "start_service":
			logger.notice("Starting opsiclientd on computer %s", self.network_address)
			cmd = 'net start opsiclientd'
		# default case is do nothing
		if cmd:
			try:
				winexe(cmd, self.network_address, self.username, self.password)
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to %s on %s: %s", self.finalize_action, self.network_address, err)


	def cleanup(self, remote_folder):
		logger.notice("Cleaning up")

		if self.mounted_oca_dir:	# in case of serverside mount
			try:
				shutil.rmtree(self.mounted_oca_dir)
			except OSError as err:
				logger.debug('Removing %s failed: %s', self.mounted_oca_dir, err, exc_info=True)
		elif remote_folder:			# in case of clientside mount
			try:
				cmd = f'cmd.exe /C "del /s /q {remote_folder} && rmdir /s /q {remote_folder}'
				winexe(cmd, self.network_address, self.username, self.password)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug('Removing %s failed: %s', remote_folder, err, exc_info=True)

		if self.mount_point:
			try:
				execute(f"umount {self.mount_point}")
			except Exception as err:  # pylint: disable=broad-except
				logger.warning('Unmounting %s failed: %s', self.mount_point, err, exc_info=True)
			try:
				os.rmdir(self.mount_point)
			except OSError as err:
				logger.debug('Removing %s failed: %s', self.mount_point, err, exc_info=True)


	def ask_host_for_hostname(self, host):
		# preferably host should be an ip
		try:
			output = winexe('cmd.exe /C "echo %COMPUTERNAME%"', host, self.username, self.password)
			for line in output:
				if line.strip():
					if 'unknown parameter' in line.lower():
						continue

					host_id = line.strip()
					break
		except Exception as err:
			logger.debug("Name lookup via winexe failed: %s", err)
			raise ValueError(f"Can't find name for IP {host}: {err}") from err

		logger.debug("Lookup of IP returned hostname %s", host_id)
		return host_id


	def _test_winexe_connection(self):
		logger.notice("Testing winexe")
		cmd = r'cmd.exe /C "del /s /q c:\\tmp\\opsi-client-agent_inst && rmdir /s /q c:\\tmp\\opsi-client-agent_inst || echo not found"'
		try:
			winexe(cmd, self.network_address, self.username, self.password)
		except Exception as err:  # pylint: disable=broad-except
			if 'NT_STATUS_LOGON_FAILURE' in str(err):
				logger.warning("Can't connect to %s: check your credentials", self.network_address)
			elif 'NT_STATUS_IO_TIMEOUT' in str(err):
				logger.warning("Can't connect to %s: firewall on client seems active", self.network_address)
			raise Exception(f"Failed to execute command {cmd} on host {self.network_address}: winexe error: {err}") from err
