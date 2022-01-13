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
import socket
from contextlib import closing, contextmanager

from opsicommon.logging import logger, secret_filter
from opsicommon.types import forceUnicodeLower

from opsideployclientagent.common import DeployThread, SkipClientException, SKIP_MARKER, getProductId

try:
	import paramiko	# type: ignore
	AUTO_ADD_POLICY = paramiko.AutoAddPolicy
	WARNING_POLICY = paramiko.WarningPolicy
	REJECT_POLICY = paramiko.RejectPolicy
except ImportError:
	paramiko = None
	AUTO_ADD_POLICY = None
	WARNING_POLICY = None
	REJECT_POLICY = None

class SSHRemoteExecutionException(Exception):
	pass

class PosixDeployThread(DeployThread):
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, host, backend, username, password, shutdown, reboot, startService,
		target_os, deploymentMethod="hostname", stopOnPingFailure=True,
		skipExistingClient=False, mountWithSmbclient=True,
		keepClientOnFailure=False, additionalClientSettings=None,
		depot=None, group=None, sshPolicy=WARNING_POLICY
	):

		DeployThread.__init__(self, host, backend, username, password, shutdown,
		reboot, startService, deploymentMethod, stopOnPingFailure,
		skipExistingClient, mountWithSmbclient, keepClientOnFailure,
		additionalClientSettings, depot, group)

		self.target_os = target_os
		self._sshConnection = None
		self._sshPolicy = sshPolicy

	def run(self):
		self._installWithSSH()

	def _installWithSSH(self):  # pylint: disable=too-many-locals,too-many-branches,too-many-statements
		logger.debug('Installing with files copied to client via scp.')
		host = forceUnicodeLower(self.host)
		hostId = ''
		hostObj = None
		remoteFolder = os.path.join('/tmp', 'opsi-client-agent')
		try:
			hostId = self._getHostId(host)
			self._checkIfClientShouldBeSkipped(hostId)

			logger.notice("Starting deployment to host %s", hostId)
			hostObj = self._prepareDeploymentToHost(hostId)

			if getattr(sys, 'frozen', False):
				localFolder = os.path.dirname(os.path.abspath(sys.executable))		# for running as executable
			else:
				localFolder = os.path.dirname(os.path.abspath(__file__))			# for running from python

			product_id = getProductId()
			credentialsfile=None
			try:
				logger.notice("Copying installation scripts...")
				self._executeViaSSH("rm -rf /tmp/opsi-client-agent")				# clean up previous run
				self._copyDirectoryOverSSH(os.path.join(localFolder, 'files'), remoteFolder)
				if not os.path.exists(os.path.join(localFolder, 'custom')):
					os.makedirs(os.path.join(localFolder, 'custom'))
				self._copyDirectoryOverSSH(os.path.join(localFolder, 'custom'), remoteFolder)
				self._copyFileOverSSH(os.path.join(localFolder, 'setup.opsiscript'), os.path.join(remoteFolder, 'setup.opsiscript'))

				if self.target_os == "linux":
					opsiscript = "/tmp/opsi-client-agent/files/opsi-script/opsi-script"
				elif self.target_os == "macos":
					opsiscript = "/tmp/opsi-client-agent/files/opsi-script.app/Contents/MacOS/opsi-script"
				else:
					raise ValueError(f"invalid target os {self.target_os}")

				logger.debug("Will use: %s", opsiscript)
				self._executeViaSSH(f"chmod +x {opsiscript}")

				service_address = self._getServiceAddress(hostObj.id)

				secret_filter.add_secrets(hostObj.opsiHostKey)
				installCommand = (
					f"{opsiscript} /tmp/opsi-client-agent/setup.opsiscript"
					" /var/log/opsi-script/opsi-client-agent.log -servicebatch"
					f" -productid {product_id}"
					f" -opsiservice {service_address}"
					f" -clientid {hostObj.id}"
					f" -username {hostObj.id}"
					f" -password {hostObj.opsiHostKey}"
					f" -parameter noreboot"
				)
				if self.username != 'root':
					credentialsfile = os.path.join(remoteFolder, '.credentials')
					logger.notice("Writing credentialsfile %s", credentialsfile)
					self._executeViaSSH(f"touch {credentialsfile}")
					self._executeViaSSH(f"chmod 600 {credentialsfile}")
					self._executeViaSSH(f"echo '{self.password}' > {credentialsfile}")
					self._executeViaSSH(f'echo "\n" >> {credentialsfile}')

				self._setClientAgentToInstalling(hostObj.id, product_id)
				logger.notice('Running installation script...')
				logger.info('Executing %s', installCommand)
				self._executeViaSSH(installCommand, credentialsfile=credentialsfile)
				self.finalize(credentialsfile=credentialsfile)
			finally:
				try:
					if credentialsfile:
						self._executeViaSSH(f"rm -f {credentialsfile}")
				except Exception:  # pylint: disable=broad-except
					logger.error("Cleanup failed")

			self.evaluate_success(hostObj.id)	#throws Exception if fail
			logger.notice("opsi-client-agent successfully installed on %s", hostId)
			self.success = True
		except SkipClientException:
			logger.notice("Skipping host %s", hostId)
			self.success = SKIP_MARKER
			return
		except (Exception, paramiko.SSHException) as err:  # pylint: disable=broad-except
			logger.error("Deployment to %s failed: %s", self.host, err)
			self.success = False

			if self._clientCreatedByScript and hostObj and not self.keepClientOnFailure:
				self._removeHostFromBackend(hostObj)

			if self._sshConnection is not None:
				try:
					self._sshConnection.close()
				except Exception as err:  # pylint: disable=broad-except
					logger.trace("Closing SSH connection failed: %s", err)
		finally:
			try:
				if self._sshConnection.get_transport():
					# If no session could be opened, there is no need to delete remote stuff
					self._executeViaSSH(f"rm -rf {remoteFolder}")
			except (Exception, paramiko.SSHException) as err:  # pylint: disable=broad-except
				logger.error(err)

	def finalize(self, credentialsfile=None):
		if self.reboot or self.shutdown:
			#TODO: shutdown blocks on macos until it is concluded -> error
			if self.reboot:
				logger.notice("Rebooting machine %s", self.networkAddress)
				cmd = r'shutdown -r +1 & disown'
			else:	# self.shutdown must be set
				logger.notice("Shutting down machine %s", self.networkAddress)
				cmd = r'shutdown -h +1 & disown'
			try:
				self._executeViaSSH(cmd, credentialsfile=credentialsfile)
			except Exception as err:  # pylint: disable=broad-except
				if self.reboot:
					logger.error("Failed to reboot computer: %s", err)
				else:
					logger.error("Failed to shutdown computer: %s", err)
		elif self.startService:
			try:
				logger.notice("Starting opsiclientd on machine %s", self.networkAddress)
				if self.target_os == "linux":
					self._executeViaSSH("systemctl start opsiclientd", credentialsfile=credentialsfile)
				elif self.target_os == "macos":
					self._executeViaSSH("launchctl load /Library/LaunchDaemons/org.opsi.opsiclientd.plist", credentialsfile=credentialsfile)
				else:
					raise ValueError(f"invalid target os {self.target_os}")

			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to start opsiclientd on %s: %s", self.networkAddress, err)


	def _getHostId(self, host):
		hostId = None
		try:
			hostId = super()._getHostId(host)
		except socket.herror:
			logger.warning("Resolving hostName failed, attempting to resolve fqdn via ssh connection to ip")
			if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', host):
				ssh = paramiko.SSHClient()
				ssh.set_missing_host_key_policy(self._sshPolicy())
				ssh.connect(host, "22", self.username, self.password)
				_, stdout, _ = ssh.exec_command("hostname -f")
				hostId = stdout.readlines()[0].encode('ascii','ignore').strip()
				logger.info("resolved FQDN: %s (type %s)", hostId, type(hostId))
		if hostId:
			return hostId
		raise ValueError(f"invalid host {host}")

	def _executeViaSSH(self, command, credentialsfile=None):
		"""
		Executing a command via SSH.

		Will return the output of stdout and stderr in one iterable object.
		:raises SSHRemoteExecutionException: if exit code is not 0.
		"""
		self._connectViaSSH()

		if credentialsfile:
			if "&" in command:
				parts = command.split("&", 1)
				command = f"sudo --stdin -- {parts[0]} < {credentialsfile} &{parts[1]}"
			else:
				command = f"sudo --stdin -- {command} < {credentialsfile}"
		logger.debug("Executing on remote: %s", command)

		with closing(self._sshConnection.get_transport().open_session()) as channel:
			channel.set_combine_stderr(True)
			channel.settimeout(None)  # blocking until completion of command

			channel.exec_command(command)
			exitCode = channel.recv_exit_status()
			out = channel.makefile("rb", -1).read().decode("utf-8", "replace")

		logger.debug("Exit code was: %s", exitCode)

		if exitCode:
			logger.debug("Command output: ")
			logger.debug(out)
			raise SSHRemoteExecutionException(
				f"Executing {command} on remote client failed! Got exit code {exitCode}"
			)

		return out

	def _getTargetArchitecture(self):
		logger.debug("Checking architecture of client...")
		output = self._executeViaSSH('uname -m')
		if "64" not in output:
			return "32"
		return "64"

	def _connectViaSSH(self):
		if self._sshConnection is not None:
			return

		self._sshConnection = paramiko.SSHClient()
		self._sshConnection.load_system_host_keys()
		self._sshConnection.set_missing_host_key_policy(self._sshPolicy())

		logger.debug("Connecting via SSH...")
		self._sshConnection.connect(
			hostname=self.networkAddress,
			username=self.username,
			password=self.password
		)

	def _copyFileOverSSH(self, localPath, remotePath):
		self._connectViaSSH()

		with closing(self._sshConnection.open_sftp()) as ftpConnection:
			ftpConnection.put(localPath, remotePath)

	def _copyDirectoryOverSSH(self, localPath, remotePath):
		@contextmanager
		def changeDirectory(path):
			currentDir = os.getcwd()
			os.chdir(path)
			yield
			os.chdir(currentDir)

		def createFolderIfMissing(path):
			try:
				ftpConnection.mkdir(path)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug("Can't create %s on remote: %s", path, err)

		self._connectViaSSH()

		with closing(self._sshConnection.open_sftp()) as ftpConnection:
			createFolderIfMissing(remotePath)

			if not os.path.exists(localPath):
				raise ValueError(f"Can't find local path '{localPath}'")

			# The following stunt is necessary to get results in 'dirpath'
			# that can be easily used for folder creation on the remote.
			with changeDirectory(os.path.join(localPath, '..')):
				directoryToWalk = os.path.basename(localPath)
				for dirpath, _, filenames in os.walk(directoryToWalk):
					createFolderIfMissing(os.path.join(remotePath, dirpath))

					for filename in filenames:
						local = os.path.join(dirpath, filename)
						remote = os.path.join(remotePath, dirpath, filename)

						logger.trace("Copying %s -> %s", local, remote)
						ftpConnection.put(local, remote)
