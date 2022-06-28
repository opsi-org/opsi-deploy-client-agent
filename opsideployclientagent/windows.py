# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
windows deployment module

This module contains the class WindowsDeployThread and related methods.
"""

from contextlib import contextmanager
import time
import shutil
import re
import os
import logging
import tempfile
from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import]
from impacket.dcerpc.v5.dcom import wmi  # type: ignore[import]
from impacket.dcerpc.v5.dtypes import NULL  # type: ignore[import]
from opsicommon.logging import logger  # type: ignore[import]
from opsicommon.types import forceUnicode  # type: ignore[import]

from opsideployclientagent.common import DeployThread, execute, FiletransferUnsuccessful

PROCESS_CHECK_INTERVAL = 5  # seconds
PROCESS_MAX_TIMEOUT = 3600


def get_process(i_wbem_services, handle):
	try:
		i_enum_wbem_class_object = i_wbem_services.ExecQuery(f"SELECT * from Win32_Process where handle = {handle}")
		process_object = i_enum_wbem_class_object.Next(0xffffffff, 1)[0]
		# logger.debug(process_object.Name, process_object.Status, process_object.TerminationDate)
		return process_object
	except wmi.DCERPCSessionError:
		logger.debug("Process not found.")
		return None


@contextmanager
def dcom_connection(host, username, password):
	dcom = None
	try:
		logger.info("Establishing connection with dcom of host '%s'.", host)
		dcom = DCOMConnection(host, username=username, password=password, oxidResolver=True)

		i_wbem_level_1_login = wmi.IWbemLevel1Login(
			dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
		)
		i_wbem_services = i_wbem_level_1_login.NTLMLogin('//./root/cimv2', NULL, NULL)
		i_wbem_level_1_login.RemRelease()
		yield i_wbem_services
	except Exception as error:  # pylint: disable=broad-except
		logger.error("wmiexec failed: %s", error, exc_info=True)
	finally:
		if dcom:
			dcom.disconnect()


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

	def wmiexec(self, cmd, host=None, timeout=None):
		cmd = forceUnicode(cmd)
		timeout = timeout or PROCESS_MAX_TIMEOUT
		host = forceUnicode(host or self.network_address)
		username = forceUnicode(self.username)
		password = forceUnicode(self.password)

		match = re.search(r"^([^\\\\]+)\\\\+([^\\\\]+)$", username)
		if match:
			username = match.group(1) + r"\\" + match.group(2)

		with dcom_connection(host, username, password) as i_wbem_services:
			logger.debug("Getting win32_process object.")
			win32_process, _ = i_wbem_services.GetObject('Win32_Process')
			outputfile = "c:\\test.txt"
			logger.notice("Executing '%s' on host '%s'", cmd, host)
			logger.info("Timeout is %s seconds", timeout)
			prop = win32_process.Create(f'cmd.exe /Q /c {cmd} > {outputfile}', "c:\\", None).getProperties()

			process_object = get_process(i_wbem_services, prop['ProcessId']['value'])
			start_time = time.time()
			while time.time() - start_time < timeout:
				if not process_object:
					logger.debug("Finished process execution.")
					break
				logger.debug("Waiting for completion, time is %.2f s", time.time() - start_time)
				time.sleep(PROCESS_CHECK_INTERVAL)
				process_object = get_process(i_wbem_services, prop['ProcessId']['value'])
			else:
				logger.error("Process reached timeout, killing process.")
				process_object.Terminate(1)

		return ""  # TODO: collect outputfile and return content

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
			self.wmiexec(install_command, timeout=self.install_timeout)
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
				self.wmiexec(cmd, timeout=120)
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
				self.wmiexec(cmd, timeout=120)
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
			output = self.wmiexec("echo %COMPUTERNAME%", host=host)
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
