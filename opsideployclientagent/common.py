import time
import threading
import socket
import re

from OPSI.System import execute, getFQDN
from OPSI.Object import OpsiClient, ProductOnClient
from OPSI.Logger import Logger, LOG_DEBUG, LOG_ERROR, LOG_NOTICE, LOG_WARNING
from OPSI.Types import forceHostId, forceIPAddress, forceUnicode, forceUnicodeLower, forceInt


SKIP_MARKER = 'clientskipped'
logger = Logger()

class SkipClientException(Exception):
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