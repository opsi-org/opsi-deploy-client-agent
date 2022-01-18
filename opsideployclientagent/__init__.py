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
import paramiko

from OPSI.Backend.BackendManager import BackendManager

from opsicommon.logging import logger, secret_filter
from opsicommon.types import forceUnicode, forceUnicodeLower

from opsideployclientagent.common import SKIP_MARKER, execute
from opsideployclientagent.posix import PosixDeployThread
from opsideployclientagent.windows import WindowsDeployThread


def deploy_client_agent(  # pylint: disable=too-many-arguments,too-many-locals,too-many-statements,too-many-branches
	hosts, target_os, host_file=None, password=None, max_threads=1,
	deployment_method="auto", mount_with_smbclient=True, depot=None, group=None,
	finalize_action="start_service", username=None,
	stop_on_ping_failure=False, skip_existing_client=False,
	keep_client_on_failure=True, ssh_hostkey_policy=None
):

	if target_os in ("linux", "macos") and username is None:
		username = "root"
	if not target_os in ("linux", "macos") and username is None:
		username = "Administrator"

	additional_host_infos = {}
	if host_file:
		with open(host_file, encoding="utf-8") as input_file:
			for line in input_file:
				line = line.strip()
				if not line or line.startswith('#') or line.startswith(';'):
					continue

				try:
					host, description = line.split(None, 1)
					additional_host_infos[host] = {"description": description}
				except ValueError as error:
					logger.debug("Splitting line '%s' failed: %s", line, error)
					host = line
				hosts.append(forceUnicodeLower(host))

	if not hosts:
		raise ValueError("No hosts given.")

	logger.debug('Deploying to the following hosts: %s', hosts)

	if not password:
		print("Password is required for deployment.")
		password = forceUnicode(getpass.getpass())
		if not password:
			raise ValueError("No password given.")

	for character in ('$', '§'):
		if character in password:
			logger.warning(
				"Please be aware that special characters in passwords may result "
				"in incorrect behaviour."
			)
			break
	secret_filter.add_secrets(password)

	max_threads = int(max_threads)

	if target_os == "windows":
		logger.info("Deploying to Windows.")
		DeploymentClass = WindowsDeployThread

		if mount_with_smbclient:
			logger.debug('Explicit check for smbclient.')
			try:
				execute("which smbclient")
			except Exception as err:	# pylint: disable=broad-except
				raise RuntimeError(f"Please make sure that 'smbclient' is installed: {err}") from err
		elif os.getuid() != 0:
			raise RuntimeError("You have to be root to use mount.")
	else:
		DeploymentClass = PosixDeployThread
		mount_with_smbclient = False

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

	running_threads = []
	while hosts or running_threads:
		if hosts and len(running_threads) < max_threads:
			# start new thread
			host = hosts.pop()

			client_config = {
				"host": host,
				"backend": backend,
				"username": username,
				"password": password,
				"finalize_action": finalize_action,
				"deployment_method": deployment_method,
				"stop_on_ping_failure": stop_on_ping_failure,
				"skip_existing_client": skip_existing_client,
				"mount_with_smbclient": mount_with_smbclient,
				"keep_client_on_failure": keep_client_on_failure,
				"depot": depot,
				"group": group,
			}

			try:
				client_config['additional_client_settings'] = additional_host_infos[host]
			except KeyError:
				pass

			if target_os in ("linux", "macos"):
				client_config["ssh_policy"] = ssh_hostkey_policy or paramiko.WarningPolicy
				client_config["target_os"] = target_os

			thread = DeploymentClass(**client_config)
			total += 1
			thread.daemon = True
			thread.start()
			running_threads.append(thread)
			time.sleep(0.5)

		new_running_threads = []
		for thread in running_threads:
			if thread.is_alive():
				new_running_threads.append(thread)
			else:
				if thread.success == SKIP_MARKER:
					skips += 1
				elif not thread.success:
					fails += 1
		running_threads = new_running_threads
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
