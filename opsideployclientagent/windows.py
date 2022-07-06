# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
windows deployment module

This module contains the class WindowsDeployThread and related methods.
"""

from contextlib import contextmanager
import time
import re
from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import]
from impacket.dcerpc.v5.dcom import wmi  # type: ignore[import]
from impacket.dcerpc.v5.dtypes import NULL  # type: ignore[import]
from opsicommon.logging import logger  # type: ignore[import]
from opsicommon.types import forceUnicode  # type: ignore[import]
import smbclient
# import shutil as smbshutil, register_session  # type: ignore[import]

from opsideployclientagent.common import DeployThread, FiletransferUnsuccessful

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
		logger.error("Could not open DCOM connection: %s", error, exc_info=True)
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
			keep_client_on_failure,
			additional_client_settings,
			depot,
			group,
			install_timeout,
		)

		self.mount_point = None
		self.mounted_oca_dir = None

	def get_connection_data(self, host):
		host = forceUnicode(host or self.network_address)
		username = forceUnicode(self.username)
		password = forceUnicode(self.password)

		match = re.search(r"^([^\\\\]+)\\\\+([^\\\\]+)$", username)
		if match:
			username = match.group(1) + r"\\" + match.group(2)
		return host, username, password

	def wmi_exec(self, cmd, host=None, timeout=None):
		cmd = forceUnicode(cmd)
		timeout = timeout or PROCESS_MAX_TIMEOUT
		host, username, password = self.get_connection_data(host)

		with dcom_connection(host, username, password) as i_wbem_services:
			logger.debug("Getting win32_process object.")
			win32_process, _ = i_wbem_services.GetObject('Win32_Process')
			logger.notice("Executing '%s' on host '%s'", cmd, host)
			logger.info("Timeout is %s seconds", timeout)
			prop = win32_process.Create(f'cmd.exe /Q /c {cmd}', "c:\\", None).getProperties()

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

	def wmi_query(self, query, host=None):
		host, username, password = self.get_connection_data(host)
		with dcom_connection(host, username, password) as i_wbem_services:
			query_result = i_wbem_services.ExecQuery(query)
			logger.notice("Querying '%s' on host '%s'", query, host)
			return query_result.Next(0xffffffff, 1)[0]

	def copy_data(self):
		logger.notice("Copying installation files")
		try:
			smbclient.register_session(server=self.network_address, username=self.username, password=self.password)
			remote_folder = rf"\\{self.network_address}\c$\opsi.org\tmp\opsi-client-agent_inst"
			if smbclient.shutil.isdir(remote_folder):
				smbclient.shutil.rmtree(remote_folder)
			smbclient.shutil.makedirs(remote_folder)
			smbclient.shutil.copytree("files", remote_folder)
			smbclient.shutil.copytree("custom", remote_folder)
			smbclient.shutil.copy("setup.opsiscript", remote_folder)
			smbclient.shutil.copy("oca-installation-helper.exe", remote_folder)
			return remote_folder
		except Exception as error:  # pylint: disable=broad-except
			logger.error("Failed to copy installation files: %s", error, exc_info=True)
			raise FiletransferUnsuccessful from error

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
			self.wmi_exec(install_command, timeout=self.install_timeout)
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
				self.wmi_exec(cmd, timeout=120)
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to %s on %s: %s", self.finalize_action, self.network_address, err)

	def cleanup(self, remote_folder):
		logger.notice("Cleaning up")
		try:
			register_session(server=self.network_address, username=self.username, password=self.password)
			if smbshutil.isdir(remote_folder):
				smbshutil.rmtree(remote_folder)
		except Exception as err:  # pylint: disable=broad-except
			logger.debug("Removing %s failed: %s", remote_folder, err, exc_info=True)

	def ask_host_for_hostname(self, host):
		# preferably host should be an ip
		try:
			result = self.wmi_query("SELECT * from Win32_ComputerSystem", host=host)
			if not result or not hasattr(result, "Name"):
				raise ValueError("Did not get Computer Name")
			logger.debug("Lookup of IP returned hostname %s", result.Name)
			return result.Name
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Name lookup via wmi query failed: %s", err)
			raise ValueError(f"Can't find name for IP {host}: {err}") from err
