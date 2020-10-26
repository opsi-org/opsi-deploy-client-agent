import sys
import os
from contextlib import closing, contextmanager

from OPSI.Util.File import IniFile
from OPSI.Util import randomString
from OPSI.Types import forceUnicode, forceUnicodeLower
from OPSI.System import copy, execute
from OPSI.Object import ProductOnClient

from .common import logger, DeployThread, SkipClientException, SKIP_MARKER

try:
	import paramiko
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

class LinuxDeployThread(DeployThread):
	def __init__(self, host, backend, username, password, shutdown, reboot, startService,
		deploymentMethod="hostname", stopOnPingFailure=True,
		skipExistingClient=False, mountWithSmbclient=True,
		keepClientOnFailure=False, additionalClientSettings=None,
		depot=None, group=None, sshPolicy=WARNING_POLICY):

		DeployThread.__init__(self, host, backend, username, password, shutdown,
		reboot, startService, deploymentMethod, stopOnPingFailure,
		skipExistingClient, mountWithSmbclient, keepClientOnFailure,
		additionalClientSettings, depot, group)

		self._sshConnection = None
		self._sshPolicy = sshPolicy

	def run(self):
		self._installWithSSH()

	def _installWithSSH(self):
		logger.debug('Installing with files copied to client via scp.')
		host = forceUnicodeLower(self.host)
		hostId = u''
		hostObj = None
		try:
			hostId = self._getHostId(host)
			self._checkIfClientShouldBeSkipped(hostId)

			logger.notice(u"Starting deployment to host %s", hostId)
			hostObj = self._prepareDeploymentToHost(hostId)
			self._executeViaSSH("echo 'it works'")

			if getattr(sys, 'frozen', False):
				localFolder = os.path.dirname(os.path.abspath(sys.executable))		# for running as executable
			else:
				localFolder = os.path.dirname(os.path.abspath(__file__))			# for running from python
			logger.notice(u"Patching config.ini")
			configIniName = u'{random}_config.ini'.format(random=randomString(10))
			configIniPath = os.path.join('/tmp', configIniName)
			copy(os.path.join(localFolder, u'files', u'opsi', u'cfg', u'config.ini'), configIniPath)
			configFile = IniFile(configIniPath)
			config = configFile.parse()
			if not config.has_section('shareinfo'):
				config.add_section('shareinfo')
			config.set('shareinfo', 'pckey', hostObj.opsiHostKey)
			if not config.has_section('general'):
				config.add_section('general')
			config.set('general', 'dnsdomain', u'.'.join(hostObj.id.split('.')[1:]))
			configFile.generate(config)
			logger.debug("Generated config.")
			remoteFolder = os.path.join('/tmp', 'opsi-linux-client-agent')

			try:
				logger.notice("Copying installation scripts...")
				self._copyDirectoryOverSSH(
					os.path.join(localFolder, 'files'),
					remoteFolder
				)

				logger.debug("Copying config for client...")
				self._copyFileOverSSH(configIniPath, os.path.join(remoteFolder, 'files', 'opsi', 'cfg', 'config.ini'))

				logger.debug("Checking architecture of client...")
				remoteArch = self._getTargetArchitecture()
				if not remoteArch:
					raise RuntimeError("Could not get architecture of client.")

				opsiscript = "/tmp/opsi-linux-client-agent/files/opsi/opsi-script/{arch}/opsi-script-nogui".format(arch=remoteArch)
				logger.debug("Will use: %s", opsiscript)
				self._executeViaSSH("chmod +x {0}".format(opsiscript))

				installCommand = "{0} -batch /tmp/opsi-linux-client-agent/files/opsi/setup.opsiscript /var/log/opsi-client-agent/opsi-script/opsi-client-agent.log -PARAMETER REMOTEDEPLOY".format(opsiscript)
				nonrootExecution = self.username != 'root'
				if nonrootExecution:
					credentialsfile = os.path.join(remoteFolder, '.credentials')
					self._executeViaSSH("touch {credfile}".format(credfile=credentialsfile))
					self._executeViaSSH("chmod 600 {credfile}".format(credfile=credentialsfile))
					self._executeViaSSH("echo '{password}' > {credfile}".format(password=self.password, credfile=credentialsfile))
					self._executeViaSSH('echo "\n" >> {credfile}'.format(password=self.password, credfile=credentialsfile))
					installCommand = "sudo --stdin -- {command} < {credfile}".format(command=installCommand, credfile=credentialsfile)

				try:
					logger.notice('Running installation script...')
					self._executeViaSSH(installCommand)
				except Exception:
					if nonrootExecution:
						self._executeViaSSH("rm -f {credfile}".format(credfile=credentialsfile))

					raise

				logger.debug("Testing if folder was created...")
				self._executeViaSSH("test -d /etc/opsi-client-agent/")
				logger.debug("Testing if config can be found...")
				checkCommand = "test -e /etc/opsi-client-agent/opsiclientd.conf"
				if nonrootExecution:
					# This call is executed with sudo, because etc/opsi-client-agent belongs to root:root
					checkCommand = "sudo --stdin -- {command} < {credfile}".format(command=checkCommand, credfile=credentialsfile)
				self._executeViaSSH(checkCommand)

				logger.debug("Testing if executable was found...")
				self._executeViaSSH("test -e /usr/bin/opsiclientd -o -e /usr/bin/opsi-script-nogui")
			finally:
				try:
					os.remove(configIniPath)
				except OSError as error:
					logger.debug("Removing %s failed: %s", configIniPath, error)

				try:
					self._executeViaSSH("rm -rf {tempfolder}".format(tempfolder=remoteFolder))
				except (Exception, paramiko.SSHException) as error:
					logger.error(error)

			logger.notice(u"opsi-linux-client-agent successfully installed on %s", hostId)
			self.success = True
			self._setOpsiClientAgentToInstalled(hostId)
			self._finaliseInstallation()
		except SkipClientException:
			logger.notice(u"Skipping host %s", hostId)
			self.success = SKIP_MARKER
			return
		except (Exception, paramiko.SSHException) as error:
			logger.error(u"Deployment to %s failed: %s", self.host, error)
			self.success = False
			if 'Incompatible ssh peer (no acceptable kex algorithm)' in forceUnicode(error):
				logger.error('Please install paramiko v1.15.1 or newer.')

			if self._clientCreatedByScript and hostObj and not self.keepClientOnFailure:
				self._removeHostFromBackend(hostObj)

			if self._sshConnection is not None:
				try:
					self._sshConnection.close()
				except Exception as error:
					logger.debug2("Closing SSH connection failed: %s", error)

	def _executeViaSSH(self, command):
		"""
		Executing a command via SSH.

		Will return the output of stdout and stderr in one iterable object.
		:raises SSHRemoteExecutionException: if exit code is not 0.
		"""
		self._connectViaSSH()

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
					u"Executing {0!r} on remote client failed! "
					u"Got exit code {1}".format(command, exitCode)
				)

			return out

	def _getTargetArchitecture(self):
		logger.debug("Checking architecture of client...")
		output = self._executeViaSSH('uname -m')
		if "64" not in output:
			return "32"
		else:
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
			except Exception as error:
				logger.debug("Can't create %s on remote: %s", path, error)

		self._connectViaSSH()

		with closing(self._sshConnection.open_sftp()) as ftpConnection:
			createFolderIfMissing(remotePath)

			if not os.path.exists(localPath):
				raise ValueError("Can't find local path '{0}'".format(localPath))

			# The following stunt is necessary to get results in 'dirpath'
			# that can be easily used for folder creation on the remote.
			with changeDirectory(os.path.join(localPath, '..')):
				directoryToWalk = os.path.basename(localPath)
				for dirpath, _, filenames in os.walk(directoryToWalk):
					createFolderIfMissing(os.path.join(remotePath, dirpath))

					for filename in filenames:
						local = os.path.join(dirpath, filename)
						remote = os.path.join(remotePath, dirpath, filename)

						logger.debug2("Copying %s -> %s", local, remote)
						ftpConnection.put(local, remote)

	def _finaliseInstallation(self):
		if self.reboot:
			logger.notice(u"Rebooting machine %s", self.networkAddress)
			try:
				self._executeViaSSH("shutdown -r 1 & disown")
			except Exception as error:
				logger.error(u"Failed to reboot computer: %s", error)
		elif self.shutdown:
			logger.notice(u"Shutting down machine %s", self.networkAddress)
			try:
				self._executeViaSSH("shutdown -h 1 & disown")
			except Exception as error:
				logger.error(u"Failed to shutdown computer: %s", error)
		elif self.startService:
			try:
				self._executeViaSSH("service opsiclientd restart")
			except Exception as error:
				logger.error("Failed to restart opsiclientd on %s: %s", self.networkAddress, error)

	def _setOpsiClientAgentToInstalled(self, hostId):
		poc = ProductOnClient(
			productType=u'LocalbootProduct',
			clientId=hostId,
			productId=u'opsi-linux-client-agent',
			installationStatus=u'installed',
			actionResult=u'successful'
		)
		self.backend.productOnClient_updateObjects([poc])