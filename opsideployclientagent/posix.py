# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
posix deployment module

This module contains the class PosixDeployThread and related methods.
"""

import sys
import os
import re
from contextlib import closing, contextmanager
import paramiko  # type: ignore[import]

from opsicommon.logging import logger  # type: ignore[import]

from opsideployclientagent.common import DeployThread, FiletransferUnsuccessful


class SSHRemoteExecutionException(Exception):
	pass


class PosixDeployThread(DeployThread):
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self,
		host,
		backend,
		username,
		password,
		target_os,
		finalize_action="start_service",
		deployment_method="hostname",
		stop_on_ping_failure=True,
		skip_existing_client=False,
		keep_client_on_failure=False,
		additional_client_settings=None,
		depot=None,
		group=None,
		ssh_policy=paramiko.WarningPolicy,
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

		self.target_os = target_os
		self._ssh_connection = None
		self._ssh_policy = ssh_policy
		self.credentialsfile = None

	def copy_data(self):
		self.remote_folder = os.path.join("/tmp", "opsi-client-agent")
		if getattr(sys, "frozen", False):
			local_folder = os.path.dirname(os.path.abspath(sys.executable))  # for running as executable
		else:
			local_folder = os.path.dirname(os.path.abspath(__file__))  # for running from python

		self._execute_via_ssh("rm -rf /tmp/opsi-client-agent")  # clean up previous run
		logger.notice("Copying installation scripts...")
		try:
			self._copy_over_ssh(os.path.join(local_folder, 'files'), self.remote_folder)
			if not os.path.exists(os.path.join(local_folder, 'custom')):
				os.makedirs(os.path.join(local_folder, 'custom'))
			self._copy_over_ssh(os.path.join(local_folder, 'custom'), self.remote_folder)
			self._copy_over_ssh(os.path.join(local_folder, 'setup.opsiscript'), os.path.join(self.remote_folder, 'setup.opsiscript'))
			self._copy_over_ssh(os.path.join(local_folder, 'oca-installation-helper'), os.path.join(self.remote_folder, 'oca-installation-helper'))
		except Exception as error:
			logger.error("Failed to copy installation files: %s", error, exc_info=True)
			raise FiletransferUnsuccessful from error

	def run_installation(self):
		if self.target_os == "linux":
			self._execute_via_ssh(f"chmod +x {self.remote_folder}/files/opsi-script/opsi-*")
		elif self.target_os == "macos":
			self._execute_via_ssh(f"chmod +x {self.remote_folder}/files/opsi-script.app/Contents/MacOS/opsi-*")
		self._execute_via_ssh(f"chmod +x {self.remote_folder}/oca-installation-helper")

		install_command = (
			f"{self.remote_folder}/oca-installation-helper"
			f" --service-address {self._get_service_address(self.host_object.id)}"
			f" --service-username {self.host_object.id}"
			f" --service-password {self.host_object.opsiHostKey}"
			f" --client-id {self.host_object.id}"
			f" --no-gui --non-interactive"
		)
		if self.username != "root":
			credentialsfile = os.path.join(self.remote_folder, ".credentials")
			logger.notice("Writing credentialsfile %s", credentialsfile)
			self._execute_via_ssh(f"touch {credentialsfile}")
			self._execute_via_ssh(f"chmod 600 {credentialsfile}")
			self._execute_via_ssh(f"echo '{self.password}' > {credentialsfile}")
			self._execute_via_ssh(f'echo "\n" >> {credentialsfile}')
			self.credentialsfile = credentialsfile

		self._set_client_agent_to_installing(self.host_object.id, self.product_id)
		logger.notice("Running installation script...")
		logger.info("Executing %s", install_command)
		self._execute_via_ssh(install_command, timeout=self.install_timeout)

	def finalize(self):
		# remove credentialsfile in 1min time window between call and execution of reboot/shutdown
		cmd = ""
		# TODO: shutdown blocks on macos until it is concluded -> error
		if self.finalize_action == "reboot":
			logger.notice("Rebooting machine %s", self.network_address)
			cmd = r"shutdown -r +1 & disown"
		elif self.finalize_action == "shutdown":
			logger.notice("Shutting down machine %s", self.network_address)
			cmd = r"shutdown -h +1 & disown"
		# start_service is performed as last action of the setup.opsiscript
		# default case is do nothing
		if cmd:
			try:
				# finalization is not allowed to take longer than 2 minutes
				self._execute_via_ssh(cmd, timeout=120)
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to %s on %s: %s", self.finalize_action, self.network_address, err)

	def cleanup(self):
		try:
			if self.remote_folder:
				# remote_folder includes credentialsfile if any
				# Cleanup is not allowed to take longer than 2 minutes
				self._execute_via_ssh(f"rm -rf {self.remote_folder}", timeout=120)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Cleanup failed: %s", err)

		if self._ssh_connection is not None:
			try:
				self._ssh_connection.close()
			except Exception as err:  # pylint: disable=broad-except
				logger.trace("Closing SSH connection failed: %s", err)

	def ask_host_for_hostname(self, host):
		if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(self._ssh_policy())
			ssh.connect(host, "22", self.username, self.password)
			_, stdout, _ = ssh.exec_command("hostname -f")
			host_id = stdout.readlines()[0].encode("ascii", "ignore").strip()
			logger.info("resolved FQDN: %s (type %s)", host_id, type(host_id))
		if host_id:
			return host_id
		raise ValueError(f"invalid host {host}")

	def _execute_via_ssh(self, command, timeout=None):
		"""
		Executing a command via SSH.

		Will return the output of stdout and stderr in one iterable object.
		:raises SSHRemoteExecutionException: if exit code is not 0.
		"""
		self._connect_via_ssh()

		if self.credentialsfile:
			if "&" in command:
				parts = command.split("&", 1)
				command = f"sudo --stdin -- {parts[0]} < {self.credentialsfile} &{parts[1]}"
			else:
				command = f"sudo --stdin -- {command} < {self.credentialsfile}"
		logger.info("Executing on remote: %s", command)

		with closing(self._ssh_connection.get_transport().open_session(timeout=timeout)) as channel:
			channel.set_combine_stderr(True)

			channel.exec_command(command)
			exit_code = channel.recv_exit_status()
			out = channel.makefile("rb", -1).read().decode("utf-8", "replace")

		logger.debug("Exit code was: %s", exit_code)
		if exit_code:
			logger.debug("Command output: ")
			logger.debug(out)
			raise SSHRemoteExecutionException(f"Executing {command} on remote client failed! Got exit code {exit_code}")
		return out

	def _connect_via_ssh(self):
		if self._ssh_connection is not None:
			return

		self._ssh_connection = paramiko.SSHClient()
		self._ssh_connection.load_system_host_keys()
		self._ssh_connection.set_missing_host_key_policy(self._ssh_policy())

		logger.debug("Connecting via SSH...")
		self._ssh_connection.connect(hostname=self.network_address, username=self.username, password=self.password)

	def _copy_over_ssh(self, local_path, remote_path):
		@contextmanager
		def change_directory(path):
			current_dir = os.getcwd()
			os.chdir(path)
			yield
			os.chdir(current_dir)

		def create_folder_if_missing(path):
			try:
				ftp_connection.mkdir(path)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Can't create %s on remote: %s", path, err)

		self._connect_via_ssh()

		with closing(self._ssh_connection.open_sftp()) as ftp_connection:
			if not os.path.exists(local_path):
				raise ValueError(f"Can't find local path '{local_path}'")

			if os.path.isfile(local_path):
				ftp_connection.put(local_path, remote_path)
				return

			create_folder_if_missing(remote_path)
			# The following stunt is necessary to get results in 'dirpath'
			# that can be easily used for folder creation on the remote.
			with change_directory(os.path.join(local_path, "..")):
				directory_to_walk = os.path.basename(local_path)
				for dirpath, _, filenames in os.walk(directory_to_walk):
					create_folder_if_missing(os.path.join(remote_path, dirpath))

					for filename in filenames:
						local = os.path.join(dirpath, filename)
						remote = os.path.join(remote_path, dirpath, filename)

						logger.trace("Copying %s -> %s", local, remote)
						ftp_connection.put(local, remote)
