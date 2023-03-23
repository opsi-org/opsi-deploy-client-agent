# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0
"""
opsi-deploy-client-agent

This script can be used to deploy the opsi-client-agent to systems
that are already running an operating system that has not been
installed via opsi.
"""

__version__ = "4.3.0.0"


import getpass
import time
from pathlib import Path

import paramiko  # type: ignore[import]
from opsicommon.logging import get_logger, secret_filter
from opsicommon.types import forceUnicode, forceUnicodeLower
from opsideployclientagent.common import DeployThread, backend_disconnect, get_backend
from opsideployclientagent.posix import PosixDeployThread
from opsideployclientagent.windows import WindowsDeployThread

logger = get_logger("opsi-deploy-client-agent")


def write_failed_clients(clients: dict[str, str], failed_clients_file: Path) -> None:
	if failed_clients_file.name == "console":
		for client, reason in clients.items():
			print(f"{client}\t{reason}")
		return
	if failed_clients_file.exists():
		logger.info("Deleting file %s", failed_clients_file)
		failed_clients_file.unlink()
	logger.notice("Writing list of failed clients to file %s", failed_clients_file)
	with open(failed_clients_file, "w", encoding="utf-8") as fcfile:
		for client, reason in clients.items():
			fcfile.write(f"{client}\t{reason}\n")


def get_password(password: str | None) -> str:
	if not password:
		print("Password is required for deployment.")
		password = forceUnicode(getpass.getpass())
		if not password:
			raise ValueError("No password given.")

	for character in ("$", "§"):
		if character in password:
			logger.warning("Please be aware that special characters in passwords may result in incorrect behaviour.")
			break
	secret_filter.add_secrets(password)
	return password


def deploy_client_agent(  # pylint: disable=too-many-arguments,too-many-locals,too-many-statements,too-many-branches
	hosts: list[str],
	target_os: str,
	host_file: str | None = None,
	password: str | None = None,
	max_threads: int = 1,
	deployment_method: str = "auto",
	depot: str | None = None,
	group: str | None = None,
	finalize_action: str = "start_service",
	username: str | None = None,
	stop_on_ping_failure: bool = False,
	skip_existing_client: bool = False,
	keep_client_on_failure: bool = True,
	ssh_hostkey_policy: paramiko.MissingHostKeyPolicy | None = None,
	install_timeout: int | None = None,
	failed_clients_file: Path | None = None,
) -> int:

	if username is None:
		if target_os in ("linux", "macos"):
			username = "root"
		else:
			username = "Administrator"

	additional_host_infos = {}
	if host_file:
		with open(host_file, encoding="utf-8") as input_file:
			for line in input_file:
				line = line.strip()
				if not line or line.startswith("#") or line.startswith(";"):
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

	logger.debug("Deploying to the following hosts: %s", hosts)

	password = get_password(password)
	max_threads = int(max_threads)

	DeploymentClass: type = PosixDeployThread
	if target_os == "windows":
		logger.info("Deploying to Windows.")
		DeploymentClass = WindowsDeployThread
	elif target_os == "linux":
		logger.info("Deploying to Linux.")
	elif target_os == "macos":
		logger.info("Deploying to MacOS.")

	if depot:
		assert get_backend().config_getObjects(id="clientconfig.depot.id")  # type: ignore  # pylint: disable=no-member
		if not get_backend().host_getObjects(type=["OpsiConfigserver", "OpsiDepotserver"], id=depot):  # type: ignore  # pylint: disable=no-member
			raise ValueError(f"No depot with id {depot} found")
	if group and not get_backend().group_getObjects(id=group):  # type: ignore  # pylint: disable=no-member
		raise ValueError(f"Group {group} does not exist")

	total = 0
	success = 0
	skips = 0
	failed_clients: dict[str, str] = {}

	running_threads: list[DeployThread] = []

	while hosts or running_threads:
		try:
			if hosts and len(running_threads) < max_threads:
				# start new thread
				host = hosts.pop()

				client_config = {
					"host": host,
					"username": username,
					"password": password,
					"finalize_action": finalize_action,
					"deployment_method": deployment_method,
					"stop_on_ping_failure": stop_on_ping_failure,
					"skip_existing_client": skip_existing_client,
					"keep_client_on_failure": keep_client_on_failure,
					"depot": depot,
					"group": group,
					"install_timeout": install_timeout,
				}

				try:
					client_config["additional_client_settings"] = additional_host_infos[host]
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
					if thread.result == "clientskipped":
						skips += 1
					elif thread.result == "success":
						success += 1
						failed_clients.update({thread.host: thread.result})
			running_threads = new_running_threads
			time.sleep(1)
		except KeyboardInterrupt:
			try:
				logger.notice("Waiting for deployments to end")
				hosts = []
				for thread in running_threads:
					thread.stop()
			except KeyboardInterrupt:
				pass
	backend_disconnect()

	fails = total - success - skips

	logger.notice("%s/%s deployments successful", success, total)
	if skips:
		logger.notice("%s/%s deployments skipped", skips, total)
	if fails:
		logger.warning("%s/%s deployments failed", fails, total)
		if failed_clients_file:
			write_failed_clients(failed_clients, failed_clients_file)
		return 1
	return 0
