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
import os
import sys
import argparse

from OPSI import __version__ as python_opsi_version

from opsicommon.deployment.posix import AUTO_ADD_POLICY, WARNING_POLICY, REJECT_POLICY
from opsicommon.deployment import deploy_client_agent
from opsicommon.logging import logging_config, logger
from opsicommon.logging.constants import DEFAULT_COLORED_FORMAT, LOG_WARNING

from opsideployclientagent import __version__

def get_target_os():
	if getattr(sys, 'frozen', False):
		workdir = os.path.dirname(os.path.abspath(sys.executable))	# for running as executable
	else:
		workdir = os.path.dirname(os.path.abspath(__file__))		# for running from python
	try:
		os.chdir(workdir)
	except Exception as error:
		logger.error(error, exc_info=True)
		raise error

	# If we are inside a folder with 'opsi-linux-client-agent' in it's
	# name we assume that we want to deploy the opsi-linux-client-agent.
	if 'opsi-linux-client-agent' in workdir:
		return "linux"
	if 'opsi-mac-client-agent' in workdir:
		return "macos"
	return "windows"

def parse_args(target_os):
	scriptDescription = "Deploy opsi client agent to the specified clients."
	if target_os in ("linux", "macos"):
		scriptDescription = '\n'.join((
			scriptDescription,
			"The clients must be accessible via SSH.",
			"The user must be allowed to use sudo non-interactive.",
		))
		defaultUser = "root"
	else:
		scriptDescription = '\n'.join((
			scriptDescription,
			"The c$ and admin$ must be accessible on every client.",
			"Simple File Sharing (Folder Options) should be disabled on the Windows machine."
		))
		defaultUser = "Administrator"

	parser = argparse.ArgumentParser(description=scriptDescription)
	parser.add_argument('--version', '-V', action='version', version=f"{__version__} [python-opsi={python_opsi_version}]")
	parser.add_argument('--verbose', '-v',
						dest="logLevel", default=LOG_WARNING, action="count",
						help="increase verbosity (can be used multiple times)")
	parser.add_argument('--debug-file', dest='debugFile',
						help='Write debug output to given file.')
	parser.add_argument('--username', '-u', dest="username", default=defaultUser,
						help=f'username for authentication (default: {defaultUser}).' + r'Example for a domain account: -u <DOMAIN>\\<username>'
						)
	parser.add_argument('--password', '-p', dest="password", default="",
						help="password for authentication")
	networkAccessGroup = parser.add_mutually_exclusive_group()
	networkAccessGroup.add_argument('--use-fqdn', '-c', dest="useFQDN",
									action="store_true",
									help="Use FQDN to connect to client.")
	networkAccessGroup.add_argument('--use-hostname', dest="useNetbios",
									action="store_true",
									help="Use hostname to connect to client.")
	networkAccessGroup.add_argument('--use-ip-address', dest="useIPAddress",
									action='store_true',
									help="Use IP address to connect to client.")
	parser.add_argument('--ignore-failed-ping', '-x',
						dest="stopOnPingFailure", default=True,
						action="store_false",
						help="try installation even if ping fails")
	if target_os in ("linux", "macos"):
		sshPolicyGroup = parser.add_mutually_exclusive_group()
		sshPolicyGroup.add_argument('--ssh-hostkey-add', dest="sshHostkeyPolicy",
									const=AUTO_ADD_POLICY, action="store_const",
									help="Automatically add unknown SSH hostkeys.")
		sshPolicyGroup.add_argument('--ssh-hostkey-reject', dest="sshHostkeyPolicy",
									const=REJECT_POLICY, action="store_const",
									help="Reject unknown SSH hostkeys.")
		sshPolicyGroup.add_argument('--ssh-hostkey-warn', dest="sshHostkeyPolicy",
									const=WARNING_POLICY, action="store_const",
									help="Warn when encountering unknown SSH hostkeys. (Default)")

	postInstallationAction = parser.add_mutually_exclusive_group()
	postInstallationAction.add_argument('--reboot', '-r',
										dest="reboot", default=False,
										action="store_true",
										help="reboot computer after installation")
	postInstallationAction.add_argument('--shutdown', '-s',
										dest="shutdown", default=False,
										action="store_true",
										help="shutdown computer after installation")
	postInstallationAction.add_argument('--start-opsiclientd', '-o',
										dest="startService", default=True,
										action="store_true",
										help="Start opsiclientd service after installation (default).")
	postInstallationAction.add_argument('--no-start-opsiclientd',
										dest="startService",
										action="store_false",
										help="Do not start opsiclientd service after installation.")
	parser.add_argument('--hosts-from-file', '-f',
						dest="hostFile", default=None,
						help=(
							"File containing addresses of hosts (one per line)."
							"If there is a space followed by text after the "
							"address this will be used as client description "
							"for new clients."))
	parser.add_argument('--skip-existing-clients', '-S',
						dest="skipExistingClient", default=False,
						action="store_true", help="skip known opsi clients")
	parser.add_argument('--threads', '-t', dest="maxThreads", default=1,
						type=int,
						help="number of concurrent deployment threads")
	parser.add_argument('--depot', help="Assign new clients to the given depot.")
	parser.add_argument('--group', dest="group",
						help="Assign fresh clients to an already existing group.")

	if not target_os in ("linux", "macos"):
		mountGroup = parser.add_mutually_exclusive_group()
		mountGroup.add_argument('--smbclient', dest="mountWithSmbclient",
								default=True, action="store_true",
								help="Mount the client's C$-share via smbclient.")
		mountGroup.add_argument('--mount', dest="mountWithSmbclient",
								action="store_false",
								help="Mount the client's C$-share via normal mount on the server for copying the files. This imitates the behaviour of the 'old' script.")

	clientRemovalGroup = parser.add_mutually_exclusive_group()
	clientRemovalGroup.add_argument('--keep-client-on-failure',
									dest="keepClientOnFailure",
									default=True, action="store_true",
									help=("If the client was created in opsi "
											"through this script it will not "
											"be removed in case of failure."
											" (DEFAULT)"))
	clientRemovalGroup.add_argument('--remove-client-on-failure',
									dest="keepClientOnFailure",
									action="store_false",
									help=("If the client was created in opsi "
											"through this script it will be "
											"removed in case of failure."))
	parser.add_argument('host', nargs='*',
						help='The hosts to deploy the opsi-client-agent to.')

	args = parser.parse_args()
	logging_config(stderr_level=args.logLevel, stderr_format=DEFAULT_COLORED_FORMAT, log_file=args.debugFile)
	return args

def main():
	target_os = get_target_os()
	args = parse_args(target_os)

	sshHostkeyPolicy = None
	if hasattr(args, "sshHostkeyPolicy"):
		sshHostkeyPolicy = args.sshHostkeyPolicy
	mountWithSmbclient = None
	if hasattr(args, "mountWithSmbclient"):
		mountWithSmbclient = args.mountWithSmbclient

	if not args.startService:
		logger.warning("The option --no-start-opsiclientd is deprecated - ignoring.")

	returncode = deploy_client_agent(
			args.host,
			target_os,
			logLevel=args.logLevel,
			debugFile=args.debugFile,
			hostFile=args.hostFile,
			password=args.password,
			maxThreads=args.maxThreads,
			useIPAddress=args.useIPAddress,
			useNetbios=args.useNetbios,
			useFQDN=args.useFQDN,
			mountWithSmbclient=mountWithSmbclient,
			depot=args.depot,
			group=args.group,
			username=args.username,
			shutdown=args.shutdown,
			reboot=args.reboot,
			startService=args.startService,
			stopOnPingFailure=args.stopOnPingFailure,
			skipExistingClient=args.skipExistingClient,
			keepClientOnFailure=args.keepClientOnFailure,
			sshHostkeyPolicy=sshHostkeyPolicy
	)
	sys.exit(returncode)

if __name__ == "__main__":
	main()
