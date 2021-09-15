# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
opsi-deploy-client-agent

This script can be used to deploy the opsi-client-agent to systems
that are already running an operating system that has not been
installed via opsi.
"""

__version__ = '4.2.0.14'


import getpass
import os
import time

from OPSI.Backend.BackendManager import BackendManager
from OPSI.System import which
from OPSI.Types import forceUnicode, forceUnicodeLower

from opsicommon.logging import logger, LOG_WARNING, LOG_DEBUG, logging_config, secret_filter
from opsideployclientagent.common import SKIP_MARKER
from opsideployclientagent.posix import PosixDeployThread, paramiko, WARNING_POLICY
from opsideployclientagent.windows import WindowsDeployThread


def deploy_client_agent(  # pylint: disable=too-many-arguments,too-many-locals,too-many-statements,too-many-branches
	hosts, target_os, logLevel=LOG_WARNING, debugFile=None, hostFile=None,
	password=None, maxThreads=1, useIPAddress=False, useNetbios=False,
	useFQDN=False, mountWithSmbclient=True, depot=None, group=None,
	username=None, shutdown=False, reboot=False, startService=True,
	stopOnPingFailure=False, skipExistingClient=False,
	keepClientOnFailure=True, sshHostkeyPolicy=None
):

	if target_os in ("linux", "macos") and username is None:
		username = "root"
	if not target_os in ("linux", "macos") and username is None:
		username = "Administrator"
	logging_config(stderr_level=logLevel, log_file=debugFile, file_level=LOG_DEBUG)

	if target_os in ("linux", "macos") and paramiko is None:
		message = (
			"Could not import 'paramiko'. "
			"Deploying to Linux/Macos not possible. "
			"Please install paramiko through your package manager or pip."
		)
		logger.critical(message)
		raise Exception(message)

	additionalHostInfos = {}
	if hostFile:
		with open(hostFile, encoding="utf-8") as inputFile:
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

	if not password:
		print("Password is required for deployment.")
		password = forceUnicode(getpass.getpass())
		if not password:
			raise Exception("No password given.")

	for character in ('$', '§'):
		if character in password:
			logger.warning(
				"Please be aware that special characters in passwords may result "
				"in incorrect behaviour."
			)
			break
	secret_filter.add_secrets(password)

	maxThreads = int(maxThreads)

	if useIPAddress:
		deploymentMethod = "ip"
	elif useNetbios:
		deploymentMethod = "hostname"
	elif useFQDN:
		deploymentMethod = "fqdn"
	else:
		deploymentMethod = "auto"

	if target_os == "windows":
		logger.info("Deploying to Windows.")
		deploymentClass = WindowsDeployThread

		if mountWithSmbclient:
			logger.debug('Explicit check for smbclient.')
			try:
				which('smbclient')
			except Exception as err:
				raise Exception(f"Please make sure that 'smbclient' is installed: {err}") from err
		elif os.getuid() != 0:
			raise Exception("You have to be root to use mount.")
	else:
		deploymentClass = PosixDeployThread
		mountWithSmbclient = False

	if target_os == "linux":
		logger.info("Deploying to Linux.")
	elif target_os == "macos":
		logger.info("Deploying to MacOS.")

	# Create BackendManager
	backend = BackendManager(
		dispatchConfigFile='/etc/opsi/backendManager/dispatch.conf',
		backendConfigDir='/etc/opsi/backends',
		extend=True,
		depotbackend=False,
		hostControlBackend=False
	)

	if depot:
		assert backend.config_getObjects(id='clientconfig.depot.id')  # pylint: disable=no-member
		if not backend.host_getObjects(type=['OpsiConfigserver', 'OpsiDepotserver'], id=depot):  # pylint: disable=no-member
			raise ValueError(f"No depot with id {depot} found")
	if group and not backend.group_getObjects(id=group):  # pylint: disable=no-member
		raise ValueError(f"Group {group} does not exist")

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
				"username": username,
				"password": password,
				"shutdown": shutdown,
				"reboot": reboot,
				"startService": startService,
				"deploymentMethod": deploymentMethod,
				"stopOnPingFailure": stopOnPingFailure,
				"skipExistingClient": skipExistingClient,
				"mountWithSmbclient": mountWithSmbclient,
				"keepClientOnFailure": keepClientOnFailure,
				"depot": depot,
				"group": group,
			}

			try:
				clientConfig['additionalClientSettings'] = additionalHostInfos[host]
			except KeyError:
				pass

			if target_os in ("linux", "macos"):
				clientConfig["sshPolicy"] = sshHostkeyPolicy or WARNING_POLICY
				clientConfig["target_os"] = target_os

			thread = deploymentClass(**clientConfig)
			total += 1
			thread.daemon = True
			thread.start()
			runningThreads.append(thread)
			time.sleep(0.5)

		newRunningThreads = []
		for thread in runningThreads:
			if thread.is_alive():
				newRunningThreads.append(thread)
			else:
				if thread.success == SKIP_MARKER:
					skips += 1
				elif not thread.success:
					fails += 1
		runningThreads = newRunningThreads
		time.sleep(1)

	success = total - fails - skips

	logger.notice("%s/%s deployments successful", success, total)
	if skips:
		logger.notice("%s/%s deployments skipped", skips, total)
	if fails:
		logger.warning("%s/%s deployments failed", fails, total)

	if fails:
		return 1
	return 0
