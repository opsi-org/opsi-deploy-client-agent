# -*- coding: utf-8 -*-

# Copyright (c) uib GmbH <info@uib.de>
# License: AGPL-3.0

"""
common deployment module

This module contains the class DeployThread and related methods.
"""

import time
import threading
import socket
import re
import os
import sys
import subprocess

from opsicommon.objects import OpsiClient, ProductOnClient
from opsicommon.types import forceIPAddress, forceUnicodeLower, forceHostId
from opsicommon.logging import logger

def getProductId():
	#return os.path.basename(os.getcwd())
	if getattr(sys, 'frozen', False):
		workdir = os.path.dirname(os.path.abspath(sys.executable))	# for running as executable
	else:
		workdir = os.path.dirname(os.path.abspath(__file__))		# for running from python
	try:
		os.chdir(workdir)
	except Exception as error:
		logger.error(error, exc_info=True)
		raise error

	if 'opsi-linux-client-agent' in workdir:
		product_id = "opsi-linux-client-agent"
	elif 'opsi-mac-client-agent' in workdir:
		product_id = "opsi-mac-client-agent"
	else:
		product_id = "opsi-client-agent"
	if os.path.basename(workdir) not in ["opsi-client-agent", "opsi-linux-client-agent", "opsi-mac-client-agent"]:
		logger.warning("Calling opsi-deploy-client-agent from a modified product-id Package is dangerous - It will still be treated as opsi-[linux-|mac-]client-agent")
	return product_id


def execute(cmd, timeout=None):
	logger.debug("executing %s", cmd)
	# in case of fail subprocess.CalledProcessError or subprocess.TimeoutExpired
	return subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout).decode("utf-8", errors="replace").split("\n")

SKIP_MARKER = 'clientskipped'

def _get_id_from_hostname(host, host_ip=None):
	host = host.replace('_', '-')

	if host.count('.') < 2:
		hostBefore = host
		try:
			host = socket.getfqdn(socket.gethostbyname(host))

			try:
				if host_ip == forceIPAddress(host):  # Lookup did not succeed
					# Falling back to hopefully valid hostname
					host = hostBefore
			except ValueError:
				pass  # no IP - great!
			except NameError:
				pass  # no deployment via IP
		except socket.gaierror:
			logger.debug("Lookup of %s failed.", host)

	logger.debug("Host is now: %s", host)
	if host.count('.') < 2:
		hostId = forceHostId(f'{host}.{".".join(socket.getfqdn().split(".")[1:])}')
	else:
		hostId = forceHostId(host)

	logger.info("Got hostId %s", hostId)
	return hostId

class SkipClientException(Exception):
	pass

class DeployThread(threading.Thread):  # pylint: disable=too-many-instance-attributes
	def __init__(  # pylint: disable=too-many-arguments,too-many-locals
		self, host, backend, username, password, shutdown, reboot, startService,
		deploymentMethod="auto", stopOnPingFailure=True,
		skipExistingClient=False, mountWithSmbclient=True,
		keepClientOnFailure=False, additionalClientSettings=None,
		depot=None, group=None
	):

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
			raise ValueError(f"Invalid deployment method: {deploymentMethod}")

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
		host_ip = None
		if self.deploymentMethod == 'ip':
			host_ip = forceIPAddress(host)
			try:
				(hostname, _, _) = socket.gethostbyaddr(host_ip)
				host = hostname
			except socket.herror as error:
				logger.debug("Lookup for %s failed: %s", host_ip, error)
				logger.warning("Could not get a hostname for %s. This is needed to create a FQDN for the client in opsi.", host_ip)
				logger.info("Without a working reverse DNS you can use the file '/etc/hosts' for working around this.")
				raise error

			logger.debug("Lookup of IP returned hostname %s", host)

		return _get_id_from_hostname(host, host_ip)

	def _checkIfClientShouldBeSkipped(self, hostId):
		if self.backend.host_getIdents(type='OpsiClient', id=hostId) and self.skipExistingClient:
			raise SkipClientException(f"Client {hostId} exists.")

		if self.backend.host_getObjects(type=['OpsiConfigserver', 'OpsiDepotserver'], id=hostId):
			logger.warning("Tried to deploy to existing opsi server %s. Skipping!", hostId)
			raise SkipClientException(f"Not deploying to server {hostId}.")

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

		logger.notice("Querying for ip address of host %s", hostId)
		ipAddress = ''
		logger.info("Getting host %s by name", hostId)
		try:
			ipAddress = socket.gethostbyname(hostId)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Failed to get ip address for host %s by syscall: %s", hostId, err)

		if ipAddress:
			logger.notice("Got ip address %s from syscall", ipAddress)
		else:
			logger.info("Executing 'nmblookup %s#20'", hostName)
			for line in execute(f"nmblookup {hostName}#20"):
				match = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+" + f"{hostName}<20>", line, re.IGNORECASE)
				if match:
					ipAddress = match.group(1)
					break
			if ipAddress:
				logger.notice("Got ip address %s from netbios lookup", ipAddress)
			else:
				raise Exception(f"Failed to get ip address for host {hostName}")

		return ipAddress

	def _pingClient(self, ipAddress):
		logger.notice("Pinging host %s ...", ipAddress)
		alive = False
		try:
			execute(f"ping -q -c2 {ipAddress}")
			alive = True
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err)

		if alive:
			logger.notice("Host %s is up", ipAddress)
		elif self.stopOnPingFailure:
			raise Exception(f"No ping response received from {ipAddress}")
		else:
			logger.warning("No ping response received from %s", ipAddress)

	def _createHostIfNotExisting(self, hostId, ipAddress):
		if not self.backend.host_getIdents(type='OpsiClient', id=hostId):
			logger.notice("Getting hardware ethernet address of host %s", hostId)
			mac = self._getMacAddress(ipAddress)
			if not mac:
				logger.warning("Failed to get hardware ethernet address for IP %s", ipAddress)

			clientConfig = {
				"id": hostId,
				"hardwareAddress": mac,
				"ipAddress": ipAddress,
				"description": "",
				"notes": f"Created by opsi-deploy-client-agent at {time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime())}"
			}
			if self.additionalClientSettings:
				clientConfig.update(self.additionalClientSettings)
				logger.debug("Updated config now is: %s", clientConfig)

			logger.notice("Creating client %s", hostId)
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
			logger.notice("Added %s to group %s", clientId, groupId)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Adding %s to group %s failed: %s", clientId, groupId, err)

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
			logger.notice("Assigned %s to depot %s", clientId, depot)
		except Exception as err:  # pylint: disable=broad-except
			logger.warning("Assgining %s to depot %s failed: %s", clientId, depot, err)

	@staticmethod
	def _getMacAddress(ipAddress):
		mac = ''
		with open("/proc/net/arp", encoding="utf-8") as arptable:
			for line in arptable:
				line = line.strip()
				if not line:
					continue

				if line.split()[0] == ipAddress:
					mac = line.split()[3].lower().strip()
					break

		if not mac or (mac == '00:00:00:00:00:00'):
			mac = ''
		else:
			logger.notice("Found hardware ethernet address %s", mac)

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

	def _setClientAgentToInstalling(self, hostId, productId):
		poc = ProductOnClient(
			productType='LocalbootProduct',
			clientId=hostId,
			productId=productId,
			installationStatus='unknown',
			actionRequest='none',
			actionProgress='installing'
		)
		self.backend.productOnClient_updateObjects([poc])

	def _removeHostFromBackend(self, host):
		try:
			logger.notice("Deleting client %s from backend", host)
			self.backend.host_deleteObjects([host])
		except Exception as err:  # pylint: disable=broad-except
			logger.error(err)

	def _getServiceAddress(self, host_id):
		service_configstate = self.backend.configState_getObjects(configId='clientconfig.configserver.url', objectId=host_id)
		if len(service_configstate) == 1 and len(service_configstate[0].values) >= 1:
			return service_configstate[0].values[0]
		service_config = self.backend.config_getObjects(id='clientconfig.configserver.url')
		if len(service_config) == 1 and len(service_config[0].defaultValues) >= 1:
			return service_config[0].defaultValues[0]
		raise ValueError("Could not determine associated configservice url")

	def evaluate_success(self, hostId):
		product_id = getProductId()

		product_on_client = self.backend.productOnClient_getObjects(productId=product_id, clientId=hostId)
		if not product_on_client or not product_on_client[0]:
			raise ValueError(f"Product {product_id} not found on client {hostId}")
		if not product_on_client[0].installationStatus == "installed":
			raise ValueError(f"Installation of {product_id} on client {hostId} unsuccessful")
