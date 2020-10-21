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
import sys
import time

from OPSI.Backend.BackendManager import BackendManager
from OPSI.System import which
from OPSI.Types import forceUnicode, forceUnicodeLower

from . import __version__
from .posix import LinuxDeployThread, paramiko, AUTO_ADD_POLICY, WARNING_POLICY, REJECT_POLICY
from .windows import WindowsDeployThread
from .common import logger, SKIP_MARKER, LOG_WARNING, LOG_ERROR, LOG_DEBUG

def initialize():
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

	# If we are inside a folder with 'opsi-linux-client-agent' in it's
	# name we assume that we want to deploy the opsi-linux-client-agent.
	return ('opsi-linux-client-agent' in workdir)


def parse_args(deployLinux):
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

	return args

def main():
	deployLinux = initialize()
	args = parse_args(deployLinux)

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

	maxThreads = int(args.maxThreads)
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
