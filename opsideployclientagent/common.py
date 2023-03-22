# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
common deployment module

This module contains the class DeployThread and related methods.
"""

import re
import os
import sys
import time
import socket
import threading
import subprocess

from opsicommon.client.opsiservice import ServiceClient
from opsicommon.objects import OpsiClient, ProductOnClient, OpsiConfigserver, OpsiDepotserver
from opsicommon.types import forceIPAddress, forceUnicodeLower, forceHostId
from opsicommon.logging import get_logger, secret_filter, log_context
from opsicommon.utils import monkeypatch_subprocess_for_frozen

logger = get_logger("opsi-deploy-client-agent")
monkeypatch_subprocess_for_frozen()


def get_product_id():
	# return os.path.basename(os.getcwd())
	if getattr(sys, "frozen", False):
		workdir = os.path.dirname(os.path.abspath(sys.executable))  # for running as executable
	else:
		workdir = os.path.dirname(os.path.abspath(__file__))  # for running from python
	try:
		os.chdir(workdir)
	except Exception as error:
		logger.error(error, exc_info=True)
		raise error

	if "opsi-linux-client-agent" in workdir:
		product_id = "opsi-linux-client-agent"
	elif "opsi-mac-client-agent" in workdir:
		product_id = "opsi-mac-client-agent"
	else:
		product_id = "opsi-client-agent"
	if os.path.basename(workdir) not in ["opsi-client-agent", "opsi-linux-client-agent", "opsi-mac-client-agent"]:
		logger.warning(
			"Calling opsi-deploy-client-agent from a modified product-id Package is dangerous "
			"- It will still be treated as opsi-[linux-|mac-]client-agent"
		)
	return product_id


def execute(cmd: str, timeout: int | None = None) -> list[str]:
	logger.info("Executing %s", cmd)
	if timeout:
		logger.info("Timeout is %s seconds", timeout)
	# In case of fail subprocess.CalledProcessError or subprocess.TimeoutExpired
	return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout).decode("utf-8", errors="replace").split("\n")


def _get_id_from_hostname(host, host_ip=None):
	host = host.replace("_", "-")

	if host.count(".") < 2:
		host_before = host
		try:
			host = socket.getfqdn(socket.gethostbyname(host))

			try:
				if host_ip == forceIPAddress(host):  # Lookup did not succeed
					host = host_before  # Falling back to hopefully valid hostname
			except ValueError:
				pass  # no IP - great!
			except NameError:
				pass  # no deployment via IP
		except socket.gaierror:
			logger.debug("Lookup of %s failed.", host)

	logger.debug("Host is now: %s", host)
	if host.count(".") < 2:
		host_id = forceHostId(f'{host}.{".".join(socket.getfqdn().split(".")[1:])}')
	else:
		host_id = forceHostId(host)

	logger.info("Got host_id %s", host_id)
	return host_id


class SkipClientException(Exception):
	pass


class ProductNotFound(Exception):
	pass


class InstallationUnsuccessful(Exception):
	pass


class FiletransferUnsuccessful(Exception):
	pass


class DeployThread(threading.Thread):  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self,
		host: str,
		backend: ServiceClient,
		username: str,
		password: str,
		finalize_action: str = "start_service",
		deployment_method: str = "auto",
		stop_on_ping_failure: bool = True,
		skip_existing_client: bool = False,
		keep_client_on_failure: bool = False,
		additional_client_settings: dict[str, str] | None = None,
		depot: str | None = None,
		group: str | None = None,
		install_timeout: int | None = None,
	) -> None:
		threading.Thread.__init__(self)

		self.result = "noattempt"

		self.backend: ServiceClient = backend
		self.username = username
		self.password = password
		self.finalize_action = finalize_action
		self.stop_on_ping_failure = stop_on_ping_failure
		self.skip_existing_client = skip_existing_client
		self.product_id = get_product_id()

		deployment_method = forceUnicodeLower(deployment_method)
		if deployment_method == "auto":
			self._detect_deployment_method(host)
		else:
			self.deployment_method = deployment_method

		self.keep_client_on_failure = keep_client_on_failure
		self._client_created_by_script = None
		self._network_address = None

		self.additional_client_settings = additional_client_settings
		self.depot = depot
		self.group = group
		self.host = None
		self.set_host_id(host)
		self.host_object = None
		self.install_timeout = install_timeout
		self.remote_folder = None
		self._should_stop = False

	def stop(self):
		self._should_stop = True

	def _detect_deployment_method(self, host):
		if "." not in host:
			logger.debug("No dots in host. Assuming hostname.")
			self.deployment_method = "hostname"
			return

		try:
			forceIPAddress(host)
			logger.debug("Valid IP found.")
			self.deployment_method = "ip"
		except ValueError:
			logger.debug("Not a valid IP. Assuming FQDN.")
			self.deployment_method = "fqdn"

	def ask_host_for_hostname(self, host):
		raise NotImplementedError

	def set_host_id(self, host):
		host_ip = None
		try:
			if self.deployment_method == "ip":
				host_ip = forceIPAddress(host)
				(hostname, _, _) = socket.gethostbyaddr(host_ip)
				host = hostname
				logger.debug("Lookup of IP returned hostname %s", host)

			self.host = _get_id_from_hostname(host, host_ip)
		except socket.herror as error:
			logger.warning("Resolving hostName failed, attempting to resolve fqdn via connection to ip %s", host_ip or host)
			logger.debug("Lookup for %s failed: %s", host_ip or host, error)
			logger.info("Without a working reverse DNS you can use the file '/etc/hosts' for working around this.")
			self.host = _get_id_from_hostname(self.ask_host_for_hostname(host_ip or host), host_ip)
		if not self.host:
			raise ValueError(f"invalid host {host}")

	def _check_if_client_should_be_skipped(self):
		hosts = self.backend.jsonrpc("host_getObjects", [[], {"id": self.host}])
		if hosts and self.skip_existing_client:
			raise SkipClientException(f"Client {self.host} exists.")

		if isinstance(hosts[0], (OpsiConfigserver, OpsiDepotserver)):
			logger.warning("Tried to deploy to existing opsi server %s. Skipping!", self.host)
			raise SkipClientException(f"Not deploying to server {self.host}.")

	def _get_ip_address(self, host_name):
		logger.notice("Querying for ip address of host %s", self.host)
		ip_address = ""
		logger.info("Getting host %s by name", self.host)
		try:
			ip_address = socket.gethostbyname(self.host)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to get ip address for host %s by syscall: %s", self.host, err)

		if ip_address:
			logger.notice("Got ip address %s from syscall", ip_address)
		else:
			logger.info("Executing 'nmblookup %s#20'", host_name)
			for line in execute(f"nmblookup {host_name}#20"):
				match = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+" + f"{host_name}<20>", line, re.IGNORECASE)
				if match:
					ip_address = match.group(1)
					break
			if ip_address:
				logger.notice("Got ip address %s from netbios lookup", ip_address)
			else:
				raise ConnectionError(f"Failed to get ip address for host {host_name}")

		return ip_address

	def _ping_client(self, ip_address):
		logger.notice("Pinging host %s ...", ip_address)
		alive = False
		try:
			execute(f"ping -q -c2 {ip_address}")
			alive = True
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err)

		if alive:
			logger.notice("Host %s is up", ip_address)
		elif self.stop_on_ping_failure:
			raise ConnectionError(f"No ping response received from {ip_address}")
		else:
			logger.warning("No ping response received from %s", ip_address)

	def _create_host_if_not_existing(self, ip_address):
		if not self.backend.jsonrpc("host_getIdents", [[], {"type": "OpsiClient", "id": self.host}]):
			logger.notice("Getting hardware ethernet address of host %s", self.host)
			mac = self._get_mac_address(ip_address)
			if not mac:
				logger.warning("Failed to get hardware ethernet address for IP %s", ip_address)

			client_config = {
				"id": self.host,
				"hardwareAddress": mac,
				"ipAddress": ip_address,
				"description": "",
				"notes": f"Created by opsi-deploy-client-agent at {time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime())}",
			}
			if self.additional_client_settings:
				client_config.update(self.additional_client_settings)
				logger.debug("Updated config now is: %s", client_config)

			logger.notice("Creating client %s", self.host)
			self.backend.jsonrpc("host_createObjects", [OpsiClient(**client_config)])
			self._client_created_by_script = True

	def _put_client_into_group(self):
		if not self.group:
			return

		mapping = {
			"type": "ObjectToGroup",
			"groupType": "HostGroup",
			"groupId": self.group,
			"objectId": self.host,
		}
		try:
			self.backend.jsonrpc("objectToGroup_createObjects", [mapping])
			logger.notice("Added %s to group %s", self.host, self.group)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Adding %s to group %s failed: %s", self.host, self.group, err)

	def _assign_client_to_depot(self):
		if not self.depot:
			return

		depot_assignment = {
			"configId": "clientconfig.depot.id",
			"values": [self.depot],
			"objectId": self.host,
			"type": "ConfigState",
		}
		try:
			self.backend.jsonrpc("configState_createObjects", [depot_assignment])
			logger.notice("Assigned %s to depot %s", self.host, self.depot)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Assgining %s to depot %s failed: %s", self.host, self.depot, err)

	@staticmethod
	def _get_mac_address(ip_address):
		mac = ""
		with open("/proc/net/arp", encoding="utf-8") as arptable:
			for line in arptable:
				line = line.strip()
				if not line:
					continue

				if line.split()[0] == ip_address:
					mac = line.split()[3].lower().strip()
					break

		if not mac or (mac == "00:00:00:00:00:00"):
			mac = ""
		else:
			logger.notice("Found hardware ethernet address %s", mac)
		return mac

	@property
	def network_address(self):
		if self._network_address is None:
			raise ValueError("No network address set!")
		return self._network_address

	def _set_network_address(self, host_name, ip_address):
		if self.deployment_method == "hostname":
			self._network_address = host_name
		elif self.deployment_method == "fqdn":
			self._network_address = self.host
		else:
			self._network_address = ip_address

	def _set_client_agent_to_installing(self, host_id, product_id):
		poc = ProductOnClient(
			productType="LocalbootProduct",
			clientId=host_id,
			productId=product_id,
			installationStatus="unknown",
			actionRequest="none",
			actionProgress="installing",
		)
		self.backend.jsonrpc("productOnClient_updateObjects", [poc])

	def _remove_host_from_backend(self):
		try:
			logger.notice("Deleting client %s from backend", self.host)
			self.backend.jsonrpc("host_deleteObjects", [self.host])
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err)

	def _get_service_address(self, host_id):
		service_configstate = self.backend.jsonrpc(
			"configState_getObjects", [[], {"configId": "clientconfig.configserver.url", "objectId": host_id}]
		)
		if len(service_configstate) == 1 and len(service_configstate[0].values) >= 1:
			return service_configstate[0].values[0]
		service_config = self.backend.jsonrpc("config_getObjects", [[], {"id": "clientconfig.configserver.url"}])
		if len(service_config) == 1 and len(service_config[0].defaultValues) >= 1:
			return service_config[0].defaultValues[0]
		raise ValueError("Could not determine associated configservice url")

	def evaluate_success(self):
		product_on_client = self.backend.jsonrpc("productOnClient_getObjects", [[], {"productId": self.product_id, "clientId": self.host}])
		if not product_on_client or not product_on_client[0]:
			raise ProductNotFound(f"Product {self.product_id} not found on client {self.host}")
		if not product_on_client[0].installationStatus == "installed":
			raise InstallationUnsuccessful(f"Installation of {self.product_id} on client {self.host} unsuccessful")

	def prepare_deploy(self):
		host_name = self.host.split(".")[0]
		ip_address = self._get_ip_address(host_name)
		self._ping_client(ip_address)
		self._set_network_address(host_name, ip_address)

		self._create_host_if_not_existing(ip_address)
		self._put_client_into_group()
		self._assign_client_to_depot()

		self.host_object = self.backend.jsonrpc("host_getObjects", [[], {"type": "OpsiClient", "id": self.host}])[0]
		secret_filter.add_secrets(self.host_object.opsiHostKey)

	def run(self):
		with log_context({"client": self.host}):
			try:
				logger.debug("Checking if client should be skipped")
				self._check_if_client_should_be_skipped()
			except SkipClientException as skip:
				logger.notice("Skipping host %s: %s", self.host, skip)
				self.result = "clientskipped"
				return

			logger.notice("Starting deployment to host %s", self.host)
			self.prepare_deploy()
			try:
				try:
					self.copy_data()
					logger.notice("Installing %s", self.product_id)
					if self._should_stop:
						self.result = "failed:aborted"
						raise InterruptedError("Aborted")
					self.run_installation()
					logger.debug("Evaluating success")
					self.evaluate_success()  # throws Exception if fail
					logger.info("Finalizing deployment")
					self.finalize()
					self.result = "success"
				except FiletransferUnsuccessful:
					self.result = "failed:filetransferunsuccessful"
					raise
				except InstallationUnsuccessful:
					self.result = "failed:installationunsuccessful"
					raise
				except ProductNotFound:
					self.result = "failed:productnotfound"
					raise
				except subprocess.TimeoutExpired:
					self.result = "failed:timeout"
					raise
			except Exception as error:  # pylint: disable=broad-except
				if self.result == "noattempt":
					self.result = "failed:unknownreason"
				logger.error("Deployment to %s failed: %s", self.host, error)
				if self._client_created_by_script and self.host_object and not self.keep_client_on_failure:
					self._remove_host_from_backend()

			finally:
				self.cleanup()

	def copy_data(self):
		raise NotImplementedError

	def run_installation(self):  # pylint: disable=unused-argument
		raise NotImplementedError

	def finalize(self):
		raise NotImplementedError

	def cleanup(self):  # pylint: disable=unused-argument
		raise NotImplementedError
