# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
windows deployment module

This module contains the class WindowsDeployThread and related methods.
"""

import logging
import ntpath
import os
import re
import time
import warnings
from contextlib import contextmanager
from typing import Any

import smbclient  # type: ignore[import]
import smbclient.shutil  # type: ignore[import]
from impacket.dcerpc.v5 import transport, tsch  # type: ignore[import]
from impacket.dcerpc.v5.dcom import wmi  # type: ignore[import]
from impacket.dcerpc.v5.dcomrt import DCOMConnection  # type: ignore[import]
from impacket.dcerpc.v5.dtypes import NULL  # type: ignore[import]
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY  # type: ignore[import]
from opsicommon.logging import get_logger
from opsicommon.types import forceUnicode

from opsideployclientagent.common import DeployThread, FiletransferUnsuccessful, execute

logger = get_logger("opsi-deploy-client-agent")

PROCESS_CHECK_INTERVAL = 5  # seconds
PROCESS_MAX_TIMEOUT = 3600

for _logger in ("smbprotocol.open", "smbprotocol.tree"):
	smbclient_logger = logging.getLogger(_logger)
	smbclient_logger.debug = smbclient_logger.trace  # type: ignore[assignment,attr-defined]
	smbclient_logger.info = smbclient_logger.debug  # type: ignore[assignment]


def get_process(i_wbem_services: Any, handle: str) -> Any:
	try:
		i_enum_wbem_class_object = i_wbem_services.ExecQuery(f"SELECT * from Win32_Process where handle = {handle}")
		process_object = i_enum_wbem_class_object.Next(0xFFFFFFFF, 1)[0]
		# logger.debug(process_object.Name, process_object.Status, process_object.TerminationDate)
		return process_object
	except wmi.DCERPCSessionError:
		logger.debug("Process not found.")
		return None


@contextmanager
def dcom_connection(host: str, username: str, password: str) -> Any:
	dcom = None
	domain = ""
	if "\\" in username:
		domain, username = username.split("\\", 1)
		username = username.strip("\\")
	elif "@" in username:
		username, domain = username.split("@", 1)
	try:
		logger.info("Establishing connection with dcom of host '%s'.", host)
		dcom = DCOMConnection(host, domain=domain, username=username, password=password, oxidResolver=True)

		i_wbem_level_1_login = wmi.IWbemLevel1Login(dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login))
		i_wbem_services = i_wbem_level_1_login.NTLMLogin("//./root/cimv2", NULL, NULL)
		i_wbem_level_1_login.RemRelease()
		yield i_wbem_services
	except Exception as error:
		logger.error("Could not open DCOM connection: %s", error, exc_info=True)
	finally:
		if dcom:
			with warnings.catch_warnings():
				# dcom.disconnect closes sockets AFTER deleting the corresponding object -> python disapproves
				warnings.simplefilter("ignore", ResourceWarning)
				dcom.disconnect()


class WindowsDeployThread(DeployThread):
	def __init__(
		self,
		host,
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
	) -> None:
		DeployThread.__init__(
			self,
			host,
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

		self.remote_folder: str | None = None
		self.smbclient_cmd = None  # shutil.which("smbclient")

	def get_connection_data(self, host: str | None) -> tuple[str, str, str]:
		host = forceUnicode(host or self.network_address)
		username = forceUnicode(self.username)
		password = forceUnicode(self.password)

		match = re.search(r"^([^\\\\]+)\\\\+([^\\\\]+)$", username)
		if match:
			username = match.group(1) + r"\\" + match.group(2)
		return host, username, password

	def wmi_exec(self, cmd: str, host: str | None = None, timeout: int | None = None) -> None:
		# WMI exec requires to logon the given user.
		# This will fail in a lot of cases.
		# See https://www.sysadmins.lv/retired-msft-blogs/alejacma/win32processcreate-fails-if-user-profile-is-not-loaded.aspx
		cmd = forceUnicode(cmd)
		timeout = timeout or PROCESS_MAX_TIMEOUT
		host, username, password = self.get_connection_data(host)
		if not host:
			raise ValueError("No host name given.")

		with dcom_connection(host, username, password) as i_wbem_services:
			logger.debug("Getting win32_process object.")
			win32_process, _ = i_wbem_services.GetObject("Win32_Process")
			logger.notice("Executing '%s' on host '%s'", cmd, host)
			logger.info("Timeout is %s seconds", timeout)
			prop = win32_process.Create(f"cmd.exe /Q /c {cmd}", "c:\\", None).getProperties()
			if prop["ReturnValue"]["value"] != 0:
				error = {
					2: "Access denied",
					3: "Insufficient privilege",
					8: "Unknown failure",
					9: "Path not found",
					21: "Invalid parameter",
				}.get(prop["ReturnValue"]["value"], "Unknown error")
				raise RuntimeError(f"Failed to execute process: {error}")

			start_time = time.time()
			process_object = get_process(i_wbem_services, prop["ProcessId"]["value"])
			while time.time() - start_time < timeout:
				if not process_object:
					logger.notice("Installation process ended")
					break
				logger.debug("Waiting for completion, time is %.2f s", time.time() - start_time)
				time.sleep(PROCESS_CHECK_INTERVAL)
				process_object = get_process(i_wbem_services, prop["ProcessId"]["value"])
			else:
				logger.error("Process reached timeout, killing process")
				process_object.Terminate(1)

	def wmi_query(self, query: str, host: str | None = None) -> Any:
		host, username, password = self.get_connection_data(host)
		with dcom_connection(host, username, password) as i_wbem_services:
			query_result = i_wbem_services.ExecQuery(query)
			logger.notice("Querying '%s' on host '%s'", query, host)
			return query_result.Next(0xFFFFFFFF, 1)[0]

	def tsch_exec(self, cmd: str, host: str | None = None, timeout: int | None = None) -> None:
		cmd = forceUnicode(cmd)
		timeout = timeout or PROCESS_MAX_TIMEOUT
		host, username, password = self.get_connection_data(host)
		domain = ""
		if "\\" in username:
			domain, username = username.split("\\", 1)
			username = username.strip("\\")
		elif "@" in username:
			username, domain = username.split("@", 1)

		xml = f"""<?xml version="1.0" encoding="UTF-16"?>
		<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
			<Triggers>
				<TimeTrigger>
					<StartBoundary>2000-01-01T00:00:00</StartBoundary>
					<Enabled>true</Enabled>
				</TimeTrigger>
			</Triggers>
			<Principals>
				<Principal id="LocalSystem">
					<UserId>S-1-5-18</UserId>
					<RunLevel>HighestAvailable</RunLevel>
				</Principal>
			</Principals>
			<Settings>
				<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
				<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
				<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
				<AllowHardTerminate>true</AllowHardTerminate>
				<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
				<IdleSettings>
					<StopOnIdleEnd>true</StopOnIdleEnd>
					<RestartOnIdle>false</RestartOnIdle>
				</IdleSettings>
				<AllowStartOnDemand>true</AllowStartOnDemand>
				<Enabled>true</Enabled>
				<Hidden>true</Hidden>
				<RunOnlyIfIdle>false</RunOnlyIfIdle>
				<WakeToRun>false</WakeToRun>
				<ExecutionTimeLimit>P1D</ExecutionTimeLimit>
				<Priority>7</Priority>
			</Settings>
			<Actions Context="LocalSystem">
				<Exec>
					<Command>cmd.exe</Command>
					<Arguments>/Q /c {cmd}</Arguments>
				</Exec>
			</Actions>
		</Task>
		"""
		logger.debug("Scheduled task xml: %s", xml)

		string_binding = rf"ncacn_np:{host}[\pipe\atsvc]"
		rpctransport = transport.DCERPCTransportFactory(string_binding)
		rpctransport.set_credentials(domain=domain, username=username, password=password)

		dce = rpctransport.get_dce_rpc()
		dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		dce.connect()

		dce.bind(tsch.MSRPC_UUID_TSCHS)
		task_name = f"opsi-deploy-client-agent-{int(time.time())}"
		logger.info("Register scheduled task %r", task_name)
		tsch.hSchRpcRegisterTask(dce, f"\\{task_name}", xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
		try:
			resp = tsch.hSchRpcRun(dce, f"\\{task_name}")
			# resp.dump()
			guid = resp["pGuid"]
			logger.info("Scheduled task started")

			start_time = time.time()
			time.sleep(5)
			while time.time() - start_time < timeout:
				try:
					resp = tsch.hSchRpcGetInstanceInfo(dce, guid)
					time.sleep(1)
				except tsch.DCERPCSessionError as err:
					# SCHED_E_TASK_NOT_RUNNING
					logger.debug(err)
					logger.info("Scheduled task ended")
					break
			else:
				logger.error("Task reached timeout, stopping task")
				tsch.SchRpcStop(dce, f"\\{task_name}")
		finally:
			logger.info("Removing scheduled task %r", task_name)
			tsch.hSchRpcDelete(dce, f"\\{task_name}")
			dce.disconnect()

	def copy_data(self) -> None:
		target_os = self.wmi_query("SELECT * from Win32_OperatingSystem", host=self.network_address)
		if target_os and hasattr(target_os, "Version"):
			logger.info("Target os version: %s", target_os.Version)
		else:
			logger.warning("Did not get target os version.")

		logger.notice("Copying installation files")
		if self.smbclient_cmd:
			logger.info("Using smbclient to copy files")
			self.copy_data_smbclient()
			return
		logger.info("Using smbprotocol to copy files")
		self.copy_data_smbprotocol()

	def copy_data_smbclient(self) -> None:
		folder_name = f"opsi-deploy-client-agent-{int(time.time())}"
		self.remote_folder = rf"c:\opsi.org\tmp\{folder_name}"
		credentials = self.username + "%" + self.password.replace("'", "'\"'\"'")
		debug_param = " -d 9" if logger.isEnabledFor(logging.DEBUG) else ""
		execute(
			f"{self.smbclient_cmd} -m SMB3{debug_param} //{self.network_address}/c$ -U '{credentials}'"
			f" -c 'prompt; recurse; md opsi.org; cd opsi.org; md log; md tmp; cd tmp; md {folder_name};"
			f" cd {folder_name}; mput files; mput setup.opsiscript; mput oca-installation-helper.exe; exit;'"
		)
		self._remote_folder_created = True

	def copy_data_smbprotocol(self) -> None:
		self.remote_folder = rf"\\{self.network_address}\c$\opsi.org\tmp\opsi-deploy-client-agent-{int(time.time())}"

		def copy_dir(src_dir: str, dst_dir: str) -> None:
			"""Copy src_dir into dst_dir"""
			dst_dir = ntpath.join(dst_dir, os.path.basename(src_dir))
			smbclient.shutil.makedirs(dst_dir)
			for root, dirs, files in os.walk(src_dir):
				path = os.path.relpath(root, src_dir)
				nt_path = path.replace(os.sep, ntpath.sep)
				for dirname in dirs:
					dst = ntpath.join(dst_dir, nt_path, dirname)
					smbclient.shutil.makedirs(dst)
				for filename in files:
					src = os.path.join(root, filename)
					dst = ntpath.join(dst_dir, nt_path, filename)
					smbclient.shutil.copy2(src, dst)

		try:
			smbclient.register_session(server=self.network_address, username=self.username, password=self.password)
			log_folder = rf"\\{self.network_address}\c$\opsi.org\log"
			smbclient.shutil.makedirs(log_folder, exist_ok=True)
			smbclient.shutil.makedirs(self.remote_folder)
			self._remote_folder_created = True
			copy_dir("files", self.remote_folder)
			smbclient.shutil.copy2("setup.opsiscript", self.remote_folder)
			smbclient.shutil.copy2("oca-installation-helper.exe", self.remote_folder)
		except Exception as error:
			logger.error("Failed to copy installation files: %s", error, exc_info=True)
			raise FiletransferUnsuccessful from error
		finally:
			try:
				smbclient.delete_session(server=self.network_address)
			except Exception:
				pass

	def run_installation(self) -> None:
		if not self.remote_folder:
			raise ValueError("No remote folder given.")
		folder = re.sub(r".+c\$", r"c:\\", self.remote_folder)
		logger.info("Deploying from path %s", folder)
		if not self.host_object:
			raise ValueError("No valid host object found.")
		install_command = (
			rf"{folder}\oca-installation-helper.exe"
			r" --log-file c:\opsi.org\log\opsi-deploy-client-agent.log"
			f" --log-level debug"
			f" --service-address {self._get_service_address(self.host_object.id)}"
			f" --service-username {self.host_object.id}"
			f" --service-password {self.host_object.opsiHostKey}"
			f" --client-id {self.host_object.id}"
			" --no-gui --non-interactive"
		)
		self._set_client_agent_to_installing(self.host_object.id, self.product_id)
		logger.notice("Running installation script...")
		try:
			self.tsch_exec(install_command, timeout=self.install_timeout)
		except Exception as err:
			logger.error("Failed to install %s: %s", self.product_id, err)
			raise

	def finalize(self) -> None:
		cmd = ""
		if self.finalize_action == "reboot":
			logger.notice("Rebooting machine %s", self.network_address)
			cmd = r'shutdown.exe /r /t 30 /c "opsi-client-agent installed - reboot"'
		elif self.finalize_action == "shutdown":
			logger.notice("Shutting down machine %s", self.network_address)
			cmd = r'shutdown.exe /s /t 30 /c "opsi-client-agent installed - shutdown"'
		# start_service is performed as last action of the setup.opsiscript
		# default case is do nothing
		if cmd:
			try:
				self.tsch_exec(cmd, timeout=30)
			except Exception as err:
				logger.error("Failed to %s on %s: %s", self.finalize_action, self.network_address, err)

	def cleanup_files_smbclient(self) -> None:
		credentials = self.username + "%" + self.password.replace("'", "'\"'\"'")
		debug_param = " -d 9" if logger.isEnabledFor(logging.DEBUG) else ""
		execute(
			f"{self.smbclient_cmd} -m SMB3{debug_param} //{self.network_address}/c$ -U '{credentials}'"
			f" -c 'prompt; recurse; deltree {self.remote_folder}; exit;'"
		)

	def cleanup_files_smbprotocol(self) -> None:
		smbclient.register_session(server=self.network_address, username=self.username, password=self.password)
		if smbclient.shutil.isdir(self.remote_folder):
			logger.info("Deleting remote folder: %s", self.remote_folder)
			smbclient.shutil.rmtree(self.remote_folder)

	def cleanup(self) -> None:
		logger.notice("Cleaning up")
		if not self.remote_folder or not self._remote_folder_created:
			return
		try:
			if self.smbclient_cmd:
				logger.info("Using smbclient to cleanup files")
				self.cleanup_files_smbclient()
			else:
				logger.info("Using smbprotocol to cleanup files")
				self.cleanup_files_smbprotocol()
		except Exception as err:
			logger.error("Cleanup failed: %s", err)
		finally:
			try:
				smbclient.delete_session(server=self.network_address)
			except Exception:
				pass

	def ask_host_for_hostname(self, host: str) -> str:
		# preferably host should be an ip
		try:
			result = self.wmi_query("SELECT * from Win32_ComputerSystem", host=host)
			if not result or not hasattr(result, "Name"):
				raise ValueError("Did not get Computer Name")
			logger.debug("Lookup of IP returned hostname %s", result.Name)
			return result.Name
		except Exception as err:
			logger.warning("Name lookup via wmi query failed: %s", err)
			raise ValueError(f"Can't find name for IP {host}: {err}") from err
