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
import random

from opsicommon.logging import logger, secret_filter
from opsicommon.types import forceUnicode

from opsideployclientagent.common import DeployThread, SkipClientException, SKIP_MARKER, execute


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

		self.mountDir = None
		self.mounted_client_dir = None


	def copy_data(self):
		logger.notice("Copying installation files")
		if self.mountWithSmbclient:
			logger.debug('Installing using client-side mount.')
			return self.copy_data_clientside_mount()
		logger.debug('Installing using server-side mount.')
		return self.copy_data_serverside_mount()


	def copy_data_clientside_mount(self):
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
		return "c:\\opsi.org\\tmp\\opsi-client-agent_inst"

	def copy_data_serverside_mount(self):
		#TODO: persistent tempdir
		self.mountDir = os.path.join(
			'/tmp',
			'mnt_' + ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(10))
		)
		os.makedirs(self.mountDir)

		logger.notice("Mounting c$ share")
		mount_cmd = execute("which mount")[0]
		try:
			password = self.password.replace("'", "'\"'\"'")
			try:
				execute(f"{mount_cmd} -t cifs -o'username={self.username},password={password}' //{self.networkAddress}/c$ {self.mountDir}",
					timeout=15
				)
			except Exception as err:  # pylint: disable=broad-except
				logger.info("Failed to mount clients c$ share: %s, retrying with port 139", err)
				execute(f"{mount_cmd} -t cifs -o'port=139,username={self.username},password={password}' //{self.networkAddress}/c$ {self.mountDir}",
					timeout=15
				)
		except Exception as err:  # pylint: disable=broad-except
			raise Exception(
				f"Failed to mount c$ share: {err}\n"
				"Perhaps you have to disable the firewall or simple file sharing on the windows machine (folder options)?"
			) from err

		logger.notice("Copying installation files")
		instDirName = f'opsi_{"".join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(10))}'
		self.mounted_client_dir = os.path.join(self.mountDir, instDirName)
		os.makedirs(self.mounted_client_dir)
		if not os.path.exists(os.path.join(self.mountDir, 'tmp')):
			os.makedirs(os.path.join(self.mountDir, 'tmp'))

		shutil.copytree('files', self.mounted_client_dir)
		shutil.copy('setup.opsiscript', self.mounted_client_dir)
		return f"c:\\{instDirName}"


	def run_installation(self, remote_folder):
		logger.info("deploying from path %s", remote_folder)
		self._testWinexeConnection()
		self._setClientAgentToInstalling(self.hostObj.id, self.product_id)
		service_address = self._getServiceAddress(self.hostObj.id)
		logger.notice("Installing %s", self.product_id)
		secret_filter.add_secrets(self.hostObj.opsiHostKey)
		cmd = (
			f"{remote_folder}\\files\\opsi-script\\opsi-script.exe"
			f" /servicebatch {remote_folder}\\setup.opsiscript"
			" c:\\opsi.org\\log\\opsi-client-agent.log"
			f" /productid {self.product_id}"
			f" /opsiservice {service_address}"
			f" /clientid {self.hostObj.id}"
			f" /username {self.hostObj.id}"
			f" /password {self.hostObj.opsiHostKey}"
			f" /parameter noreboot"
		)
		try:
			winexe(cmd, self.networkAddress, self.username, self.password)
		except Exception as err:  # pylint: disable=broad-except
			raise Exception(f"Failed to install {self.product_id}: {err}") from err


	def finalize(self):
		if self.reboot:
			action = "reboot"
			logger.notice("Rebooting machine %s", self.networkAddress)
			cmd = r'"shutdown.exe" /r /t 30 /c "opsi-client-agent installed - reboot"'
		elif self.shutdown:
			action = "shutdown"
			logger.notice("Shutting down machine %s", self.networkAddress)
			cmd = r'"shutdown.exe" /s /t 30 /c "opsi-client-agent installed - shutdown"'
		elif self.startService:
			action = "start service"
			logger.notice("Starting opsiclientd on computer %s", self.networkAddress)
			cmd = 'net start opsiclientd'

		try:
			winexe(cmd, self.networkAddress, self.username, self.password)
		except Exception as err:  # pylint: disable=broad-except
			logger.error("failed to %s on %s: %s", action, self.networkAddress, err)


	def cleanup(self, remote_folder):
		logger.notice("Cleaning up")

		if self.mounted_client_dir:	# in case of serverside mount
			try:
				shutil.rmtree(self.mounted_client_dir)
			except OSError as err:
				logger.debug('Removing %s failed: %s', self.mounted_client_dir, err, exc_info=True)
		elif remote_folder:			# in case of clientside mount
			try:
				cmd = f'cmd.exe /C "del /s /q {remote_folder} && rmdir /s /q {remote_folder}'
				winexe(cmd, self.networkAddress, self.username, self.password)
			except Exception as err:  # pylint: disable=broad-except
				logger.debug('Removing %s failed: %s', remote_folder, err, exc_info=True)

		if self.mountDir:
			try:
				execute(f"umount {self.mountDir}")
			except Exception as err:  # pylint: disable=broad-except
				logger.warning('Unmounting %s failed: %s', self.mountDir, err, exc_info=True)
			try:
				os.rmdir(self.mountDir)
			except OSError as err:
				logger.debug('Removing %s failed: %s', self.mountDir, err, exc_info=True)


	def ask_host_for_hostname(self, host):
		# preferably host should be an ip
		try:
			output = winexe('cmd.exe /C "echo %COMPUTERNAME%"', host, self.username, self.password)
			for line in output:
				if line.strip():
					if 'unknown parameter' in line.lower():
						continue

					hostId = line.strip()
					break
		except Exception as err:
			logger.debug("Name lookup via winexe failed: %s", err)
			raise ValueError(f"Can't find name for IP {host}: {err}") from err

		logger.debug("Lookup of IP returned hostname %s", hostId)
		return hostId


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
