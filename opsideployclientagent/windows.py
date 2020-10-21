import time
import socket
import shutil
import re
import os

from OPSI.Util.File import IniFile
from OPSI.Util import randomString
from OPSI.Types import forceHostId, forceIPAddress, forceUnicode, forceUnicodeLower
from OPSI.System import copy, execute, getFQDN, umount, which

from .common import DeployThread, SkipClientException, SKIP_MARKER

def winexe(cmd, host, username, password):
	cmd = forceUnicode(cmd)
	host = forceUnicode(host)
	username = forceUnicode(username)
	password = forceUnicode(password)

	match = re.search('^([^\\\\]+)\\\\+([^\\\\]+)$', username)
	if match:
		username = match.group(1) + u'\\' + match.group(2)

	try:
		executable = which('winexe')
	except Exception:
		logger.critical(
			"Unable to find 'winexe'. Please install 'opsi-windows-support' "
			"through your operating systems package manager!"
		)
		raise RuntimeError("Missing 'winexe'")

	try:
		logger.info(u'Winexe Version: %s', ''.join(execute('{winexe} -V'.format(winexe=executable))))
	except Exception as versionError:
		logger.warning(u"Failed to get version: %s", versionError)

	return execute(u"{winexe} -U '{credentials}' //{host} '{command}'".format(
		winexe=executable,
		credentials=username + '%' + password.replace("'", "'\"'\"'"),
		host=host,
		command=cmd)
	)

class WindowsDeployThread(DeployThread):
	def __init__(self, host, backend, username, password, shutdown, reboot, startService,
			deploymentMethod="hostname", stopOnPingFailure=True,
			skipExistingClient=False, mountWithSmbclient=True,
			keepClientOnFailure=False, additionalClientSettings=None,
			depot=None, group=None):

		DeployThread.__init__(self, host, backend, username, password, shutdown,
			reboot, startService, deploymentMethod, stopOnPingFailure,
			skipExistingClient, mountWithSmbclient, keepClientOnFailure,
			additionalClientSettings, depot, group)

	def run(self):
		if self.mountWithSmbclient:
			self._installWithSmbclient()
		else:
			self._installWithServersideMount()

	def _installWithSmbclient(self):
		logger.debug('Installing using client-side mount.')
		host = forceUnicodeLower(self.host)
		hostId = u''
		hostObj = None
		try:
			hostId = self._getHostId(host)
			self._checkIfClientShouldBeSkipped(hostId)

			logger.notice(u"Starting deployment to host %s", hostId)
			hostObj = self._prepareDeploymentToHost(hostId)
			self._testWinexeConnection()

			logger.notice(u"Patching config.ini")
			configIniName = u'{random}_config.ini'.format(random=randomString(10))
			copy(os.path.join(u'files', u'opsi', u'cfg', u'config.ini'), '/tmp/{0}'.format(configIniName))
			configFile = IniFile('/tmp/{0}'.format(configIniName))
			config = configFile.parse()
			if not config.has_section('shareinfo'):
				config.add_section('shareinfo')
			config.set('shareinfo', 'pckey', hostObj.opsiHostKey)
			if not config.has_section('general'):
				config.add_section('general')
			config.set('general', 'dnsdomain', u'.'.join(hostObj.id.split('.')[1:]))
			configFile.generate(config)

			try:
				logger.notice(u"Copying installation files")
				cmd = u"{smbclient} -m SMB3 //{address}/c$ -U '{credentials}' -c 'prompt; recurse; md tmp; cd tmp; md opsi-client-agent_inst; cd opsi-client-agent_inst; mput files; mput utils; cd files\\opsi\\cfg; lcd /tmp; put {config} config.ini; exit;'".format(
					smbclient=which('smbclient'),
					address=self.networkAddress,
					credentials=self.username + '%' + self.password.replace("'", "'\"'\"'"),
					config=configIniName
				)
				execute(cmd)

				logger.notice(u"Installing opsi-client-agent")
				cmd = u'c:\\tmp\\opsi-client-agent_inst\\files\\opsi\\opsi-winst\\winst32.exe /batch c:\\tmp\\opsi-client-agent_inst\\files\\opsi\\setup.opsiscript c:\\tmp\\opsi-client-agent.log /PARAMETER REMOTEDEPLOY'
				for trynum in (1, 2):
					try:
						winexe(cmd, self.networkAddress, self.username, self.password)
						break
					except Exception as error:
						if trynum == 2:
							raise Exception(u"Failed to install opsi-client-agent: {0}".format(error))
						logger.info(u"Winexe failure %s, retrying", error)
						time.sleep(2)
			finally:
				os.remove('/tmp/{0}'.format(configIniName))

				try:
					cmd = u'cmd.exe /C "del /s /q c:\\tmp\\opsi-client-agent_inst && rmdir /s /q c:\\tmp\\opsi-client-agent_inst"'
					winexe(cmd, self.networkAddress, self.username, self.password)
				except Exception as error:
					logger.error(error)

			logger.notice(u"opsi-client-agent successfully installed on %s", hostId)
			self.success = True
			self._setOpsiClientAgentToInstalled(hostId)
			self._finaliseInstallation()
		except SkipClientException:
			logger.notice(u"Skipping host %s", hostId)
			self.success = SKIP_MARKER
			return
		except Exception as error:
			logger.error(u"Deployment to %s failed: %s", self.host, error)
			self.success = False
			if self._clientCreatedByScript and hostObj and not self.keepClientOnFailure:
				self._removeHostFromBackend(hostObj)

	def _getHostId(self, host):
		if self.deploymentMethod == 'ip':
			ip = forceIPAddress(host)
			try:
				(hostname, _, _) = socket.gethostbyaddr(ip)
				host = hostname
			except socket.herror as error:
				logger.debug("Lookup for %s failed: %s", ip, error)

				try:
					output = winexe(u'cmd.exe /C "echo %COMPUTERNAME%"', ip, self.username, self.password)
					for line in output:
						if line.strip():
							if 'ignoring unknown parameter' in line.lower() or 'unknown parameter encountered' in line.lower():
								continue

							host = line.strip()
							break
				except Exception as error:
					logger.debug("Name lookup via winexe failed: %s", error)
					raise Exception("Can't find name for IP {0}: {1}".format(ip, error))

			logger.debug(u"Lookup of IP returned hostname %s", host)

		host = host.replace('_', '-')

		if host.count(u'.') < 2:
			hostBefore = host
			try:
				host = socket.getfqdn(socket.gethostbyname(host))

				try:
					if ip == forceIPAddress(host):  # Lookup did not succeed
						# Falling back to hopefully valid hostname
						host = hostBefore
				except ValueError:
					pass  # no IP - great!
				except NameError:
					pass  # no deployment via IP
			except socket.gaierror as error:
				logger.debug("Lookup of %s failed.", host)

		logger.debug(u"Host is now: %s", host)
		if host.count(u'.') < 2:
			hostId = forceHostId(u'{hostname}.{domain}'.format(hostname=host, domain=u'.'.join(getFQDN().split(u'.')[1:])))
		else:
			hostId = forceHostId(host)

		logger.info("Got hostId %s", hostId)
		return hostId

	def _testWinexeConnection(self):
		logger.notice(u"Testing winexe")
		cmd = u'cmd.exe /C "del /s /q c:\\tmp\\opsi-client-agent_inst && rmdir /s /q c:\\tmp\\opsi-client-agent_inst || echo not found"'
		for trynum in (1, 2):
			try:
				winexe(cmd, self.networkAddress, self.username, self.password)
				break
			except Exception as error:
				if 'NT_STATUS_LOGON_FAILURE' in forceUnicode(error):
					logger.warning("Can't connect to %s: check your credentials", self.networkAddress)
				elif 'NT_STATUS_IO_TIMEOUT' in forceUnicode(error):
					logger.warning("Can't connect to %s: firewall on client seems active", self.networkAddress)

				if trynum == 2:
					raise Exception(u"Failed to execute command on host {0!r}: winexe error: {1}".format(self.networkAddress, error))
				logger.info(u"Winexe failure %s, retrying", error)
				time.sleep(2)

	def _finaliseInstallation(self):
		if self.reboot or self.shutdown:
			if self.reboot:
				logger.notice(u"Rebooting machine %s", self.networkAddress)
				cmd = u'"%ProgramFiles%\\opsi.org\\opsi-client-agent\\utilities\\shutdown.exe" /L /R /T:20 "opsi-client-agent installed - reboot" /Y /C'
			elif self.shutdown:
				logger.notice(u"Shutting down machine %s", self.networkAddress)
				cmd = u'"%ProgramFiles%\\opsi.org\\opsi-client-agent\\utilities\\shutdown.exe" /L /T:20 "opsi-client-agent installed - shutdown" /Y /C'

			try:
				pf = None
				for const in ('%ProgramFiles(x86)%', '%ProgramFiles%'):
					try:
						lines = winexe(u'cmd.exe /C "echo {0}"'.format(const), self.networkAddress, self.username, self.password)
					except Exception as error:
						logger.warning(error)
						continue

					for line in lines:
						line = line.strip()
						if 'unavailable' in line:
							continue
						pf = line

					if pf and pf != const:
						break

					pf = None

				if not pf:
					raise Exception(u"Failed to get program files path")

				logger.info(u"Program files path is %s", pf)
				winexe(cmd.replace(u'%ProgramFiles%', pf), self.networkAddress, self.username, self.password)
			except Exception as error:
				if self.reboot:
					logger.error(u"Failed to reboot computer: %s", error)
				else:
					logger.error(u"Failed to shutdown computer: %s", error)
		elif self.startService:
			try:
				winexe(u'net start opsiclientd', self.networkAddress, self.username, self.password)
			except Exception as error:
				logger.error("Failed to start opsiclientd on %s: %s", self.networkAddress, error=error)

	def _installWithServersideMount(self):
		logger.debug('Installing using server-side mount.')
		host = forceUnicodeLower(self.host)
		hostId = u''
		hostObj = None
		mountDir = u''
		instDir = u''
		try:
			hostId = self._getHostId(host)
			self._checkIfClientShouldBeSkipped(hostId)

			logger.notice(u"Starting deployment to host %s", hostId)
			hostObj = self._prepareDeploymentToHost(hostId)
			self._testWinexeConnection()

			mountDir = os.path.join(u'/tmp', u'mnt_' + randomString(10))
			os.makedirs(mountDir)

			logger.notice(u"Mounting c$ share")
			try:
				try:
					execute(u"{mount} -t cifs -o'username={username},password={password}' //{address}/c$ {target}".format(
							mount=which('mount'),
							username=self.username,
							password=self.password.replace("'", "'\"'\"'"),
							address=self.networkAddress,
							target=mountDir
							),
						timeout=15
					)
				except Exception as error:
					logger.info(u"Failed to mount clients c$ share: %s, retrying with port 139", error)
					execute(u"{mount} -t cifs -o'port=139,username={username},password={password}' //{address}/c$ {target}".format(
							mount=which('mount'),
							username=self.username,
							password=self.password.replace("'", "'\"'\"'"),
							address=self.networkAddress,
							target=mountDir
						),
						timeout=15
					)
			except Exception as error:
				raise Exception(u"Failed to mount c$ share: {0}\nPerhaps you have to disable the firewall or simple file sharing on the windows machine (folder options)?".format(error))

			logger.notice(u"Copying installation files")
			instDirName = u'opsi_{random}'.format(random=randomString(10))
			instDir = os.path.join(mountDir, instDirName)
			os.makedirs(instDir)

			copy(u'files', instDir)
			copy(u'utils', instDir)

			logger.notice(u"Patching config.ini")
			configFile = IniFile(os.path.join(instDir, u'files', u'opsi', u'cfg', u'config.ini'))
			config = configFile.parse()
			if not config.has_section('shareinfo'):
				config.add_section('shareinfo')
			config.set('shareinfo', 'pckey', hostObj.opsiHostKey)
			if not config.has_section('general'):
				config.add_section('general')
			config.set('general', 'dnsdomain', u'.'.join(hostObj.id.split('.')[1:]))
			configFile.generate(config)

			logger.notice(u"Installing opsi-client-agent")
			if not os.path.exists(os.path.join(mountDir, 'tmp')):
				os.makedirs(os.path.join(mountDir, 'tmp'))
			cmd = u'c:\\{0}\\files\\opsi\\opsi-winst\\winst32.exe /batch c:\\{0}\\files\\opsi\\setup.opsiscript c:\\tmp\\opsi-client-agent.log /PARAMETER REMOTEDEPLOY'.format(instDirName)
			for trynum in (1, 2):
				try:
					winexe(cmd, self.networkAddress, self.username, self.password)
					break
				except Exception as error:
					if trynum == 2:
						raise Exception(u"Failed to install opsi-client-agent: {0}".format(error))
					logger.info(u"Winexe failure %s, retrying", error)
					time.sleep(2)

			logger.notice(u"opsi-client-agent successfully installed on %s", hostId)
			self.success = True
			self._setOpsiClientAgentToInstalled(hostId)
			self._finaliseInstallation()
		except SkipClientException:
			logger.notice(u"Skipping host %s", hostId)
			self.success = SKIP_MARKER
			return
		except Exception as error:
			self.success = False
			logger.error(u"Deployment to %s failed: %s", self.host, error)
			if self._clientCreatedByScript and hostObj and not self.keepClientOnFailure:
				self._removeHostFromBackend(hostObj)
		finally:
			if instDir or mountDir:
				logger.notice(u"Cleaning up")

			if instDir:
				try:
					shutil.rmtree(instDir)
				except OSError as err:
					logger.debug('Removing %s failed: %s', instDir, err)

			if mountDir:
				try:
					umount(mountDir)
				except Exception as err:
					logger.warning('Unmounting %s failed: %s', mountDir, err)

				try:
					os.rmdir(mountDir)
				except OSError as err:
					logger.debug('Removing %s failed: %s', instDir, err)
