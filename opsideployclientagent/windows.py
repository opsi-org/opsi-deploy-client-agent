# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
windows deployment module

This module contains the class WindowsDeployThread and related methods.
"""

import time
import socket
import shutil
import re
import os
import logging
import random

from opsicommon.logging import logger, secret_filter
from opsicommon.types import forceIPAddress, forceUnicode, forceUnicodeLower

from opsideployclientagent.common import DeployThread, SkipClientException, SKIP_MARKER, _get_id_from_hostname, getProductId, execute


def winexe(cmd, host, username, password):
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
		return execute(f"{executable} -d 9 -U '{credentials}' //{host} '{cmd}'")
	return execute(f"{executable} -U '{credentials}' //{host} '{cmd}'")

class WindowsDeployThread(DeployThread):
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, host, backend, username, password, shutdown, reboot, startService,
		deploymentMethod="hostname", stopOnPingFailure=True,
		skipExistingClient=False, mountWithSmbclient=True,
		keepClientOnFailure=False, additionalClientSettings=None,
		depot=None, group=None
	):
		DeployThread.__init__(
			self, host, backend, username, password, shutdown,
			reboot, startService, deploymentMethod, stopOnPingFailure,
			skipExistingClient, mountWithSmbclient, keepClientOnFailure,
			additionalClientSettings, depot, group
		)

	def run(self):
		if self.mountWithSmbclient:
			self._installWithSmbclient()
		else:
			self._installWithServersideMount()

	def install_from_path(self, path, hostObj):
		logger.info("deploying from path %s", path)
		product_id = getProductId()
		self._setClientAgentToInstalling(hostObj.id, product_id)
		service_address = self._getServiceAddress(hostObj.id)
		logger.notice("Installing %s", product_id)
		secret_filter.add_secrets(hostObj.opsiHostKey)
		cmd = (
			f"{path}\\files\\opsi-script\\opsi-script.exe"
			f" /servicebatch {path}\\setup.opsiscript"
			" c:\\opsi.org\\log\\opsi-client-agent.log"
			f" /productid {product_id}"
			f" /opsiservice {service_address}"
			f" /clientid {hostObj.id}"
			f" /username {hostObj.id}"
			f" /password {hostObj.opsiHostKey}"
			f" /parameter noreboot"
		)
		try:
			winexe(cmd, self.networkAddress, self.username, self.password)
		except Exception as err:  # pylint: disable=broad-except
			raise Exception(f"Failed to install {product_id}: {err}") from err

	def finalize(self):
		if self.reboot or self.shutdown:
			if self.reboot:
				logger.notice("Rebooting machine %s", self.networkAddress)
				cmd = r'"shutdown.exe" /r /t 20 /c "opsi-client-agent installed - reboot"'
			else:	# self.shutdown must be set
				logger.notice("Shutting down machine %s", self.networkAddress)
				cmd = r'"shutdown.exe" /s /t 20 /c "opsi-client-agent installed - shutdown"'

			try:
				winexe(cmd, self.networkAddress, self.username, self.password)
			except Exception as err:  # pylint: disable=broad-except
				if self.reboot:
					logger.error("Failed to reboot computer: %s", err)
				else:
					logger.error("Failed to shutdown computer: %s", err)
		elif self.startService:
			try:
				logger.notice("Starting opsiclientd on computer %s", self.networkAddress)
				winexe('net start opsiclientd', self.networkAddress, self.username, self.password)
			except Exception as err:  # pylint: disable=broad-except
				logger.error("Failed to start opsiclientd on %s: %s", self.networkAddress, err)


	def _installWithSmbclient(self):  # pylint: disable=too-many-branches,too-many-statements
		logger.debug('Installing using client-side mount.')
		host = forceUnicodeLower(self.host)
		hostId = ''
		hostObj = None
		try:
			hostId = self._getHostId(host)
			self._checkIfClientShouldBeSkipped(hostId)

			logger.notice("Starting deployment to host %s", hostId)
			hostObj = self._prepareDeploymentToHost(hostId)
			self._testWinexeConnection()

			try:
				logger.notice("Copying installation files")
				credentials=self.username + '%' + self.password.replace("'", "'\"'\"'")
				debug_param = " -d 9" if logger.isEnabledFor(logging.DEBUG) else ""
				smbclient_cmd = execute("which smbclient")[0]
				cmd = (
					f"{smbclient_cmd} -m SMB3{debug_param} //{self.networkAddress}/c$ -U '{credentials}'"
					" -c 'prompt; recurse;"
					" md opsi.org; cd opsi.org; md log; md tmp; cd tmp; deltree opsi-client-agent_inst; md opsi-client-agent_inst;"
					" cd opsi-client-agent_inst; mput files; mput setup.opsiscript; exit;'"
				)
				execute(cmd)

				self.install_from_path(r"c:\\opsi.org\\tmp\\opsi-client-agent_inst", hostObj)
			finally:
				try:
					cmd = (
						r'cmd.exe /C "del /s /q c:\\opsi.org\\tmp\\opsi-client-agent_inst'
						r' && rmdir /s /q c:\\opsi.org\\tmp\\opsi-client-agent_inst"'
					)
					winexe(cmd, self.networkAddress, self.username, self.password)
				except Exception as err:  # pylint: disable=broad-except
					logger.error(err)

			self.finalize()
			self.evaluate_success(hostObj.id)	#throws Exception if fail
			logger.notice("%s successfully installed on %s", getProductId(), hostId)
			self.success = True
		except SkipClientException:
			logger.notice("Skipping host %s", hostId)
			self.success = SKIP_MARKER
			return
		except Exception as err:  # pylint: disable=broad-except
			logger.error("Deployment to %s failed: %s", self.host, err)
			self.success = False
			if self._clientCreatedByScript and hostObj and not self.keepClientOnFailure:
				self._removeHostFromBackend(hostObj)

	def _getHostId(self, host):  # pylint: disable=too-many-branches
		host_ip = None
		if self.deploymentMethod == 'ip':
			host_ip = forceIPAddress(host)
			try:
				(hostname, _, _) = socket.gethostbyaddr(host_ip)
				host = hostname
			except socket.herror as error:
				logger.debug("Lookup for %s failed: %s", host_ip, error)

				try:
					output = winexe('cmd.exe /C "echo %COMPUTERNAME%"', host_ip, self.username, self.password)
					for line in output:
						if line.strip():
							if 'unknown parameter' in line.lower():
								continue

							host = line.strip()
							break
				except Exception as err:
					logger.debug("Name lookup via winexe failed: %s", err)
					raise Exception(f"Can't find name for IP {host_ip}: {err}") from err

			logger.debug("Lookup of IP returned hostname %s", host)

		return _get_id_from_hostname(host, host_ip)

	def _testWinexeConnection(self):
		logger.notice("Testing winexe")
		cmd = r'cmd.exe /C "del /s /q c:\\tmp\\opsi-client-agent_inst && rmdir /s /q c:\\tmp\\opsi-client-agent_inst || echo not found"'
		try:
			winexe(cmd, self.networkAddress, self.username, self.password)
		except Exception as err:  # pylint: disable=broad-except
			if 'NT_STATUS_LOGON_FAILURE' in str(err):
				logger.warning("Can't connect to %s: check your credentials", self.networkAddress)
			elif 'NT_STATUS_IO_TIMEOUT' in str(err):
				logger.warning("Can't connect to %s: firewall on client seems active", self.networkAddress)
			raise Exception(f"Failed to execute command {cmd} on host {self.networkAddress}: winexe error: {err}") from err

	def _installWithServersideMount(self):  # pylint: disable=too-many-branches,too-many-statements
		logger.debug('Installing using server-side mount.')
		host = forceUnicodeLower(self.host)
		hostObj = None
		mountDir = ''
		instDir = ''
		hostId = self._getHostId(host)
		try:
			self._checkIfClientShouldBeSkipped(hostId)
		except SkipClientException:
			logger.notice("Skipping host %s", hostId)
			self.success = SKIP_MARKER
			return

		logger.notice("Starting deployment to host %s", hostId)
		try:
			hostObj = self._prepareDeploymentToHost(hostId)
			self._testWinexeConnection()

			mountDir = os.path.join(
				'/tmp',
				'mnt_' + ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(10))
			)
			os.makedirs(mountDir)

			logger.notice("Mounting c$ share")
			mount_cmd = execute("which mount")[0]
			try:
				password = self.password.replace("'", "'\"'\"'")
				try:
					execute(f"{mount_cmd} -t cifs -o'username={self.username},password={password}' //{self.networkAddress}/c$ {mountDir}",
						timeout=15
					)
				except Exception as err:  # pylint: disable=broad-except
					logger.info("Failed to mount clients c$ share: %s, retrying with port 139", err)
					execute(f"{mount_cmd} -t cifs -o'port=139,username={self.username},password={password}' //{self.networkAddress}/c$ {mountDir}",
						timeout=15
					)
			except Exception as err:  # pylint: disable=broad-except
				raise Exception(
					f"Failed to mount c$ share: {err}\n"
					"Perhaps you have to disable the firewall or simple file sharing on the windows machine (folder options)?"
				) from err

			logger.notice("Copying installation files")
			instDirName = f'opsi_{"".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(10))}'
			instDir = os.path.join(mountDir, instDirName)
			os.makedirs(instDir)
			if not os.path.exists(os.path.join(mountDir, 'tmp')):
				os.makedirs(os.path.join(mountDir, 'tmp'))

			shutil.copytree('files', instDir)
			shutil.copy('setup.opsiscript', instDir)

			try:
				self.install_from_path(f"c:\\{instDirName}", hostObj)
			finally:
				if instDir or mountDir:
					logger.notice("Cleaning up")

				if instDir:
					try:
						shutil.rmtree(instDir)
					except OSError as err:
						logger.debug('Removing %s failed: %s', instDir, err)

				if mountDir:
					try:
						execute(f"umount {mountDir}")
					except Exception as err:  # pylint: disable=broad-except
						logger.warning('Unmounting %s failed: %s', mountDir, err)

					try:
						os.rmdir(mountDir)
					except OSError as err:
						logger.debug('Removing %s failed: %s', instDir, err)

			self.finalize()
			self.evaluate_success(hostObj.id)	#throws Exception if fail
			logger.notice("%s successfully installed on %s", getProductId(), hostId)
			self.success = True
		except Exception as err:  # pylint: disable=broad-except
			self.success = False
			logger.error("Deployment to %s failed: %s", self.host, err)
			if self._clientCreatedByScript and hostObj and not self.keepClientOnFailure:
				self._removeHostFromBackend(hostObj)
