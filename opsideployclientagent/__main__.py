# -*- coding: utf-8 -*-

# This tool is part of the desktop management solution opsi
# (open pc server integration) http://www.opsi.org
# Copyright (C) 2007-2019 uib GmbH <info@uib.de>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
opsi-deploy-client-agent

This script can be used to deploy the opsi-client-agent to systems
that are already running an operating system that has not been
installed via opsi.

:copyright: uib GmbH <info@uib.de>
:author: Jan Schneider <j.schneider@uib.de>
:author: Niko Wenselowski <n.wenselowski@uib.de>
:license: GNU Affero General Public License version 3
"""

import argparse
import getpass
import os
import re
import shutil
import socket
import sys
import threading
import time

from contextlib import closing, contextmanager

from OPSI.Backend.BackendManager import BackendManager
from OPSI.Logger import Logger, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_WARNING
from OPSI.Object import OpsiClient, ProductOnClient
from OPSI.System import copy, execute, getFQDN, umount, which
from OPSI.Types import (
	forceHostId, forceInt, forceIPAddress, forceUnicode, forceUnicodeLower)
from OPSI.Util import randomString
from OPSI.Util.File import IniFile

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

from . import __version__


SKIP_MARKER = 'clientskipped'


logger = Logger()


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


class SkipClientException(Exception):
	pass


class SSHRemoteExecutionException(Exception):
	pass


class DeployThread(threading.Thread):
	def __init__(self, host, backend, username, password, shutdown, reboot, startService,
				deploymentMethod="auto", stopOnPingFailure=True,
				skipExistingClient=False, mountWithSmbclient=True,
				keepClientOnFailure=False, additionalClientSettings=None,
				depot=None, group=None):

		threading.Thread.__init__(self)

		self.success = False

		self.host = host
		self.backend = backend
		self.username = username
		self.password = password
		self.shutdown = shutdown
		self.reboot = reboot
		self.startService = startService
		self.stopOnPingFailure = stopOnPingFailure
		self.skipExistingClient = skipExistingClient
		self.mountWithSmbclient = mountWithSmbclient

		deploymentMethod = forceUnicodeLower(deploymentMethod)
		if deploymentMethod == "auto":
			self._detectDeploymentMethod()
		else:
			self.deploymentMethod = deploymentMethod

		if self.deploymentMethod not in ("hostname", "ip", "fqdn"):
			raise ValueError("Invalid deployment method: {0}".format(deploymentMethod))

		self.keepClientOnFailure = keepClientOnFailure
		self._clientCreatedByScript = None
		self._networkAddress = None

		self.additionalClientSettings = additionalClientSettings
		self.depot = depot
		self.group = group

	def _detectDeploymentMethod(self):
		if '.' not in self.host:
			logger.debug("No dots in host. Assuming hostname.")
			self.deploymentMethod = "hostname"
			return

		try:
			forceIPAddress(self.host)
			logger.debug("Valid IP found.")
			self.deploymentMethod = "ip"
		except ValueError:
			logger.debug("Not a valid IP. Assuming FQDN.")
			self.deploymentMethod = "fqdn"

	def _getHostId(self, host):
		if self.deploymentMethod == 'ip':
			ip = forceIPAddress(host)
			try:
				(hostname, _, _) = socket.gethostbyaddr(ip)
				host = hostname
			except socket.herror as error:
				logger.debug(u"Lookup for %s failed: %s", ip, error)
				logger.warning(u"Could not get a hostname for %s. This is needed to create a FQDN for the client in opsi.", ip)
				logger.info(u"Without a working reverse DNS you can use the file '/etc/hosts' for working around this.")
				raise error

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

	def _checkIfClientShouldBeSkipped(self, hostId):
		if self.backend.host_getIdents(type='OpsiClient', id=hostId) and self.skipExistingClient:
			raise SkipClientException("Client {0} exists.".format(hostId))

		if self.backend.host_getObjects(type=['OpsiConfigserver', 'OpsiDepotserver'], id=hostId):
			logger.warning("Tried to deploy to existing opsi server %s. Skipping!", hostId)
			raise SkipClientException("Not deploying to server {0}.".format(hostId))

	def _prepareDeploymentToHost(self, hostId):
		hostName = hostId.split('.')[0]
		ipAddress = self._getIpAddress(hostId, hostName)
		self._pingClient(ipAddress)
		self._setNetworkAddress(hostId, hostName, ipAddress)

		self._createHostIfNotExisting(hostId, ipAddress)
		return self.backend.host_getObjects(type='OpsiClient', id=hostId)[0]

	def _getIpAddress(self, hostId, hostName):
		if self.deploymentMethod == 'ip':
			return forceIPAddress(self.host)

		logger.notice(u"Querying for ip address of host %s", hostId)
		ipAddress = u''
		logger.info(u"Getting host %s by name", hostId)
		try:
			ipAddress = socket.gethostbyname(hostId)
		except Exception as error:
			logger.warning(u"Failed to get ip address for host %s by syscall: %s", hostId, error)

		if ipAddress:
			logger.notice(u"Got ip address %s from syscall", ipAddress)
		else:
			logger.info(u"Executing 'nmblookup %s#20'", hostName)
			for line in execute(u"nmblookup {0}#20".format(hostName)):
				match = re.search("^(\d+\.\d+\.\d+\.\d+)\s+{0}<20>".format(hostName), line, re.IGNORECASE)
				if match:
					ipAddress = match.group(1)
					break
			if ipAddress:
				logger.notice(u"Got ip address %s from netbios lookup", ipAddress)
			else:
				raise Exception(u"Failed to get ip address for host {0!r}".format(hostName))

		return ipAddress

	def _pingClient(self, ipAddress):
		logger.notice(u"Pinging host %s ...", ipAddress)
		alive = False
		try:
			for line in execute(u"ping -q -c2 {address}".format(address=ipAddress)):
				match = re.search("\s+(\d+)%\s+packet\s+loss", line)
				if match and (forceInt(match.group(1)) < 100):
					alive = True
		except Exception as error:
			logger.error(error)

		if alive:
			logger.notice(u"Host %s is up", ipAddress)
		elif self.stopOnPingFailure:
			raise Exception(u"No ping response received from {0}".format(ipAddress))
		else:
			logger.warning(u"No ping response received from %s", ipAddress)

	def _createHostIfNotExisting(self, hostId, ipAddress):
		if not self.backend.host_getIdents(type='OpsiClient', id=hostId):
			logger.notice(u"Getting hardware ethernet address of host %s", hostId)
			mac = self._getMacAddress(ipAddress)
			if not mac:
				logger.warning(u"Failed to get hardware ethernet address for IP %s", ipAddress)

			clientConfig = {
				"id": hostId,
				"hardwareAddress": mac,
				"ipAddress": ipAddress,
				"description": u"",
				"notes": u"Created by opsi-deploy-client-agent at {0}".format(
					time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
				)
			}
			if self.additionalClientSettings:
				clientConfig.update(self.additionalClientSettings)
				logger.debug("Updated config now is: %s", clientConfig)

			logger.notice(u"Creating client %s", hostId)
			self.backend.host_createObjects([OpsiClient(**clientConfig)])
			self._clientCreatedByScript = True
			self._putClientIntoGroup(hostId)
			self._assignClientToDepot(hostId)

	def _putClientIntoGroup(self, clientId):
		groupId = self.group
		if not groupId:
			return

		mapping = {
			"type": "ObjectToGroup",
			"groupType": "HostGroup",
			"groupId": groupId,
			"objectId": clientId,
		}
		try:
			self.backend.objectToGroup_createObjects([mapping])
			logger.notice(u"Added %s to group %s", clientId, groupId)
		except Exception as creationError:
			logger.warning(u"Adding %s to group %s failed: %s", clientId, groupId, creationError)

	def _assignClientToDepot(self, clientId):
		depot = self.depot
		if not depot:
			return

		depotAssignment = {
			"configId": "clientconfig.depot.id",
			"values": [depot],
			"objectId": clientId,
			"type": "ConfigState",
		}
		try:
			self.backend.configState_createObjects([depotAssignment])
			logger.notice(u"Assigned %s to depot %s", clientId, depot)
		except Exception as assignmentError:
			logger.warning(u"Assgining %s to depot %s failed: %s", clientId, depot, assignmentError)

	@staticmethod
	def _getMacAddress(ipAddress):
		mac = u''
		with open("/proc/net/arp") as arptable:
			for line in arptable:
				line = line.strip()
				if not line:
					continue

				if line.split()[0] == ipAddress:
					mac = line.split()[3].lower().strip()
					break

		if not mac or (mac == u'00:00:00:00:00:00'):
			mac = u''
		else:
			logger.notice(u"Found hardware ethernet address %s", mac)

		return mac

	@property
	def networkAddress(self):
		if self._networkAddress is None:
			raise ValueError("No network address set!")

		return self._networkAddress

	def _setNetworkAddress(self, hostId, hostName, ipAddress):
		if self.deploymentMethod == 'hostname':
			self._networkAddress = hostName
		elif self.deploymentMethod == 'fqdn':
			self._networkAddress = hostId
		else:
			self._networkAddress = ipAddress

	def _setOpsiClientAgentToInstalled(self, hostId):
		poc = ProductOnClient(
			productType=u'LocalbootProduct',
			clientId=hostId,
			productId=u'opsi-client-agent',
			installationStatus=u'installed',
			actionResult=u'successful'
		)
		self.backend.productOnClient_updateObjects([poc])

	def _removeHostFromBackend(self, host):
		try:
			logger.notice('Deleting client %s from backend.', host)
			self.backend.host_deleteObjects([host])
		except Exception as error:
			logger.error(error)


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
				localFolder = os.path.dirname(os.path.abspath(__file__))		# for running from python
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
				self._executeViaSSH("test -e /etc/opsi-client-agent/opsiclientd.conf")
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


def main():
	logger.setConsoleColor(True)

	if getattr(sys, 'frozen', False):
		workdir = os.path.dirname(os.path.abspath(sys.executable))		# for running as executable
	else:
		workdir = os.path.dirname(os.path.abspath(__file__))		# for running from python
	try:
		os.chdir(workdir)
	except Exception as error:
		logger.setConsoleLevel(LOG_ERROR)
		logger.logException(error)
		print(u"ERROR: {0}".format(forceUnicode(error)), file=sys.stderr)
		raise error

	logger.setConsoleLevel(LOG_NOTICE)

	# If we are inside a folder with 'opsi-linux-client-agent' in it's
	# name we assume that we want to deploy the opsi-linux-client-agent.
	deployLinux = 'opsi-linux-client-agent' in workdir

	scriptDescription = u"Deploy opsi client agent to the specified clients."
	if deployLinux:
		scriptDescription = '\n'.join((
			scriptDescription,
			u"The clients must be accessible via SSH.",
			u"The user must be allowed to use sudo non-interactive.",
		))
		defaultUser = u"root"
	else:
		scriptDescription = '\n'.join((
			scriptDescription,
			u"The c$ and admin$ must be accessible on every client.",
			u"Simple File Sharing (Folder Options) should be disabled on the Windows machine."
		))
		defaultUser = u"Administrator"

	parser = argparse.ArgumentParser(description=scriptDescription)
	parser.add_argument('--version', '-V', action='version', version=__version__)
	parser.add_argument('--verbose', '-v',
						dest="logLevel", default=LOG_WARNING, action="count",
						help="increase verbosity (can be used multiple times)")
	parser.add_argument('--debug-file', dest='debugFile',
						help='Write debug output to given file.')
	parser.add_argument('--username', '-u', dest="username", default=defaultUser,
						help=(
							u'username for authentication (default: {0}).\n'
							u"Example for a domain account: -u \"<DOMAIN>\\\\<username>\""
							).format(defaultUser)
						)
	parser.add_argument('--password', '-p', dest="password", default=u"",
						help=u"password for authentication")
	networkAccessGroup = parser.add_mutually_exclusive_group()
	networkAccessGroup.add_argument('--use-fqdn', '-c', dest="useFQDN",
									action="store_true",
									help=u"Use FQDN to connect to client.")
	networkAccessGroup.add_argument('--use-hostname', dest="useNetbios",
									action="store_true",
									help=u"Use hostname to connect to client.")
	networkAccessGroup.add_argument('--use-ip-address', dest="useIPAddress",
									action='store_true',
									help="Use IP address to connect to client.")
	parser.add_argument('--ignore-failed-ping', '-x',
						dest="stopOnPingFailure", default=True,
						action="store_false",
						help=u"try installation even if ping fails")
	if deployLinux:
		sshPolicyGroup = parser.add_mutually_exclusive_group()
		sshPolicyGroup.add_argument('--ssh-hostkey-add', dest="sshHostkeyPolicy",
									const=AUTO_ADD_POLICY, action="store_const",
									help=u"Automatically add unknown SSH hostkeys.")
		sshPolicyGroup.add_argument('--ssh-hostkey-reject', dest="sshHostkeyPolicy",
									const=REJECT_POLICY, action="store_const",
									help=u"Reject unknown SSH hostkeys.")
		sshPolicyGroup.add_argument('--ssh-hostkey-warn', dest="sshHostkeyPolicy",
									const=WARNING_POLICY, action="store_const",
									help=u"Warn when encountering unknown SSH hostkeys. (Default)")

	postInstallationAction = parser.add_mutually_exclusive_group()
	postInstallationAction.add_argument('--reboot', '-r',
										dest="reboot", default=False,
										action="store_true",
										help=u"reboot computer after installation")
	postInstallationAction.add_argument('--shutdown', '-s',
										dest="shutdown", default=False,
										action="store_true",
										help=u"shutdown computer after installation")
	postInstallationAction.add_argument('--start-opsiclientd', '-o',
										dest="startService", default=True,
										action="store_true",
										help=u"Start opsiclientd service after installation (default).")
	postInstallationAction.add_argument('--no-start-opsiclientd',
										dest="startService",
										action="store_false",
										help=u"Do not start opsiclientd service after installation.")
	parser.add_argument('--hosts-from-file', '-f',
						dest="hostFile", default=None,
						help=(
							u"File containing addresses of hosts (one per line)."
							u"If there is a space followed by text after the "
							u"address this will be used as client description "
							u"for new clients."))
	parser.add_argument('--skip-existing-clients', '-S',
						dest="skipExistingClient", default=False,
						action="store_true", help=u"skip known opsi clients")
	parser.add_argument('--threads', '-t', dest="maxThreads", default=1,
						type=int,
						help=u"number of concurrent deployment threads")
	parser.add_argument('--depot', help="Assign new clients to the given depot.")
	parser.add_argument('--group', dest="group",
						help="Assign fresh clients to an already existing group.")

	if not deployLinux:
		mountGroup = parser.add_mutually_exclusive_group()
		mountGroup.add_argument('--smbclient', dest="mountWithSmbclient",
								default=True, action="store_true",
								help=u"Mount the client's C$-share via smbclient.")
		mountGroup.add_argument('--mount', dest="mountWithSmbclient",
								action="store_false",
								help=u"Mount the client's C$-share via normal mount on the server for copying the files. This imitates the behaviour of the 'old' script.")

	clientRemovalGroup = parser.add_mutually_exclusive_group()
	clientRemovalGroup.add_argument('--keep-client-on-failure',
									dest="keepClientOnFailure",
									default=True, action="store_true",
									help=(u"If the client was created in opsi "
											u"through this script it will not "
											u"be removed in case of failure."
											u" (DEFAULT)"))
	clientRemovalGroup.add_argument('--remove-client-on-failure',
									dest="keepClientOnFailure",
									action="store_false",
									help=(u"If the client was created in opsi "
											u"through this script it will be "
											u"removed in case of failure."))
	parser.add_argument('host', nargs='*',
						help=u'The hosts to deploy the opsi-client-agent to.')

	args = parser.parse_args()

	logger.setConsoleLevel(args.logLevel)

	if args.debugFile:
		logger.setLogFile(args.debugFile)
		logger.setFileLevel(LOG_DEBUG)

	if deployLinux and paramiko is None:
		message = (
			u"Could not import 'paramiko'. "
			u"Deploying to Linux not possible. "
			u"Please install paramiko through your package manager or pip."
		)
		logger.critical(message)
		raise Exception(message)

	additionalHostInfos = {}
	hosts = args.host
	if args.hostFile:
		with open(args.hostFile) as inputFile:
			for line in inputFile:
				line = line.strip()
				if not line or line.startswith('#') or line.startswith(';'):
					continue

				try:
					host, description = line.split(None, 1)
					additionalHostInfos[host] = {"description": description}
				except ValueError as error:
					logger.debug("Splitting line '%s' failed: %s", line, error)
					host = line

				hosts.append(forceUnicodeLower(host))

	if not hosts:
		raise Exception("No hosts given.")

	logger.debug('Deploying to the following hosts: %s', hosts)

	password = args.password
	if not password:
		print("Password is required for deployment.")
		password = forceUnicode(getpass.getpass())
		if not password:
			raise Exception("No password given.")

	for character in (u'$', u'§'):
		if character in password:
			logger.warning(
				u"Please be aware that special characters in passwords may result"
				u"in incorrect behaviour."
			)
			break
	logger.addConfidentialString(password)

	maxThreads = forceInt(args.maxThreads)
	if maxThreads < 1:
		maxThreads = 1

	if args.useIPAddress:
		deploymentMethod = "ip"
	elif args.useNetbios:
		deploymentMethod = "hostname"
	elif args.useFQDN:
		deploymentMethod = "fqdn"
	else:
		deploymentMethod = "auto"

	if not deployLinux:
		logger.info("Deploying to Windows.")
		deploymentClass = WindowsDeployThread
		mountWithSmbclient = args.mountWithSmbclient

		if mountWithSmbclient:
			logger.debug('Explicit check for smbclient.')
			try:
				which('smbclient')
			except Exception as error:
				raise Exception(
					"Please make sure that 'smbclient' is installed: "
					"{0}".format(error)
				)
		else:
			if os.getuid() != 0:
				raise Exception("You have to be root to use mount.")
	else:
		logger.info("Deploying to Linux.")
		deploymentClass = LinuxDeployThread
		mountWithSmbclient = False

	# Create BackendManager
	backend = BackendManager(
		dispatchConfigFile=u'/etc/opsi/backendManager/dispatch.conf',
		backendConfigDir=u'/etc/opsi/backends',
		extend=True,
		depotbackend=False,
		hostControlBackend=False
	)

	if args.depot:
		assert backend.config_getObjects(id='clientconfig.depot.id')
		if not backend.host_getObjects(type=['OpsiConfigserver', 'OpsiDepotserver'], id=args.depot):
			raise ValueError("No depot with id {0!r} found!".format(args.depot))
	if args.group and not backend.group_getObjects(id=args.group):
		raise ValueError(u"Group {0} does not exist.".format(args.group))

	total = 0
	fails = 0
	skips = 0

	runningThreads = []
	while hosts or runningThreads:
		if hosts and len(runningThreads) < maxThreads:
			# start new thread
			host = hosts.pop()

			clientConfig = {
				"host": host,
				"backend": backend,
				"username": args.username,
				"password": password,
				"shutdown": args.shutdown,
				"reboot": args.reboot,
				"startService": args.startService,
				"deploymentMethod": deploymentMethod,
				"stopOnPingFailure": args.stopOnPingFailure,
				"skipExistingClient": args.skipExistingClient,
				"mountWithSmbclient": mountWithSmbclient,
				"keepClientOnFailure": args.keepClientOnFailure,
				"depot": args.depot,
				"group": args.group,
			}

			try:
				clientConfig['additionalClientSettings'] = additionalHostInfos[host]
			except KeyError:
				pass

			if deployLinux:
				clientConfig["sshPolicy"] = args.sshHostkeyPolicy or WARNING_POLICY

			thread = deploymentClass(**clientConfig)
			total += 1
			thread.daemon = True
			thread.start()
			runningThreads.append(thread)
			time.sleep(0.5)

		newRunningThreads = []
		for thread in runningThreads:
			if thread.isAlive():
				newRunningThreads.append(thread)
			else:
				if thread.success == SKIP_MARKER:
					skips += 1
				elif not thread.success:
					fails += 1
		runningThreads = newRunningThreads
		time.sleep(1)
	
	success = total - fails - skips

	logger.notice("%s/%s deployments successfully", success, total)
	if skips:
		logger.notice("%s/%s deployments skipped", skips, total)
	if fails:
		logger.warning("%s/%s deployments failed", fails, total)

	if fails:
		return 1
	else:
		return 0

if __name__ == "__main__":
	main()
