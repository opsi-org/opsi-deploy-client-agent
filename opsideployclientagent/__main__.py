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
import sys
import argparse
import paramiko

from opsicommon import __version__ as python_opsi_common_version
from opsicommon.logging import logging_config, logger
from opsicommon.logging.constants import DEFAULT_COLORED_FORMAT, LOG_WARNING, LOG_DEBUG

from opsideployclientagent import deploy_client_agent, __version__
from opsideployclientagent.common import get_product_id

def get_target_os():
	product_id = get_product_id()
	if product_id == "opsi-client-agent":
		return "windows"
	if product_id == "opsi-linux-client-agent":
		return "linux"
	if product_id == "opsi-mac-client-agent":
		return "macos"
	raise ValueError(f"Unknown product_id {product_id} cannot match os")

def parse_args(target_os):
	script_description = "Deploy opsi client agent to the specified clients."
	if target_os in ("linux", "macos"):
		script_description = '\n'.join((
			script_description,
			"The clients must be accessible via SSH.",
			"The user must be allowed to use sudo non-interactive.",
		))
		default_user = "root"
	else:
		script_description = '\n'.join((
			script_description,
			"The c$ and admin$ must be accessible on every client.",
			"Simple File Sharing (Folder Options) should be disabled on the Windows machine."
		))
		default_user = "Administrator"

	parser = argparse.ArgumentParser(description=script_description)
	parser.add_argument('--version', '-V', action='version', version=f"{__version__} [python-opsi-common={python_opsi_common_version}]")
	parser.add_argument('--verbose', '-v',
						dest="log_level", default=LOG_WARNING, action="count",
						help="increase verbosity (can be used multiple times)")
	parser.add_argument('--debug-file', dest='debug_file',
						help='Write debug output to given file.')
	parser.add_argument('--username', '-u', dest="username", default=default_user,
						help=f'username for authentication (default: {default_user}).' + r'Example for a domain account: -u <DOMAIN>\\<username>'
						)
	parser.add_argument('--password', '-p', dest="password", default="",
						help="password for authentication")
	network_access_group = parser.add_mutually_exclusive_group()
	network_access_group.add_argument('--use-fqdn', '-c', dest="deployment_method",
									action="store_const", const="fqdn",
									help="Use FQDN to connect to client.")
	network_access_group.add_argument('--use-hostname', dest="deployment_method",
									action="store_const", const="hostname",
									help="Use hostname to connect to client.")
	network_access_group.add_argument('--use-ip-address', dest="deployment_method",
									action='store_const', const="ip",
									help="Use IP address to connect to client.")
	parser.add_argument('--ignore-failed-ping', '-x',
						dest="stop_on_ping_failure", default=True,
						action="store_false",
						help="try installation even if ping fails")
	if target_os in ("linux", "macos"):
		ssh_policy_group = parser.add_mutually_exclusive_group()
		ssh_policy_group.add_argument('--ssh-hostkey-add', dest="ssh_hostkey_policy",
									const=paramiko.AutoAddPolicy, action="store_const",
									help="Automatically add unknown SSH hostkeys.")
		ssh_policy_group.add_argument('--ssh-hostkey-reject', dest="ssh_hostkey_policy",
									const=paramiko.RejectPolicy, action="store_const",
									help="Reject unknown SSH hostkeys.")
		ssh_policy_group.add_argument('--ssh-hostkey-warn', dest="ssh_hostkey_policy",
									const=paramiko.WarningPolicy, action="store_const",
									help="Warn when encountering unknown SSH hostkeys. (Default)")

	finalize_action_group = parser.add_mutually_exclusive_group()
	finalize_action_group.add_argument('--reboot', '-r', dest="finalize_action",
										const="reboot", action="store_const",
										help="reboot computer after installation")
	finalize_action_group.add_argument('--shutdown', '-s', dest="finalize_action",
										const="reboot", action="store_const",
										help="shutdown computer after installation")
	finalize_action_group.add_argument('--start-opsiclientd', '-o', dest="finalize_action",
										const="start_service", action="store_const",
										help="Start opsiclientd service after installation without performing Events (default).")
	finalize_action_group.add_argument('--no-start-opsiclientd', dest="finalize_action",
										const="no_start_service", action="store_const",
										help="Do not start opsiclientd service after installation (deprecated).")
	parser.add_argument('--hosts-from-file', '-f',
						dest="host_file", default=None,
						help=(
							"File containing addresses of hosts (one per line)."
							"If there is a space followed by text after the "
							"address this will be used as client description "
							"for new clients."))
	parser.add_argument('--skip-existing-clients', '-S',
						dest="skip_existing_client", default=False,
						action="store_true", help="skip known opsi clients")
	parser.add_argument('--threads', '-t', dest="max_threads", default=1,
						type=int,
						help="number of concurrent deployment threads")
	parser.add_argument('--depot', help="Assign new clients to the given depot.")
	parser.add_argument('--group', dest="group",
						help="Assign fresh clients to an already existing group.")

	if not target_os in ("linux", "macos"):
		mount_group = parser.add_mutually_exclusive_group()
		mount_group.add_argument('--smbclient', dest="mount_with_smbclient",
								default=True, action="store_true",
								help="Mount the client's C$-share via smbclient.")
		mount_group.add_argument('--mount', dest="mount_with_smbclient",
								action="store_false",
								help=("Mount the client's C$-share via normal mount on the server for copying the files."
								"This imitates the behaviour of the 'old' script.")
								)

	client_removal_group = parser.add_mutually_exclusive_group()
	client_removal_group.add_argument('--keep-client-on-failure',
									dest="keep_client_on_failure",
									default=True, action="store_true",
									help=("If the client was created in opsi "
											"through this script it will not "
											"be removed in case of failure."
											" (DEFAULT)"))
	client_removal_group.add_argument('--remove-client-on-failure',
									dest="keep_client_on_failure",
									action="store_false",
									help=("If the client was created in opsi "
											"through this script it will be "
											"removed in case of failure."))
	parser.add_argument('host', nargs='*',
						help='The hosts to deploy the opsi-client-agent to.')

	args = parser.parse_args()
	logging_config(stderr_level=args.log_level, stderr_format=DEFAULT_COLORED_FORMAT, log_file=args.debug_file, file_level=LOG_DEBUG)
	return args

def main():
	target_os = get_target_os()
	args = parse_args(target_os)

	ssh_hostkey_policy = paramiko.WarningPolicy
	if hasattr(args, "ssh_hostkey_policy") and args.ssh_hostkey_policy is not None:
		ssh_hostkey_policy = args.ssh_hostkey_policy
	mount_with_smbclient = True
	if hasattr(args, "mount_with_smbclient") and args.mount_with_smbclient is not None:
		mount_with_smbclient = args.mount_with_smbclient
	finalize_action = "start_service"
	if hasattr(args, "finalize_action") and args.finalize_action is not None:
		finalize_action = args.finalize_action
	if finalize_action == "no_start_service":
		logger.warning("The option --no-start-opsiclientd is deprecated - ignoring.")
		finalize_action = "start_service"	#with start_service execution of events is subpressed on service start

	returncode = deploy_client_agent(
			args.host,
			target_os,
			host_file=args.host_file,
			password=args.password,
			max_threads=args.max_threads,
			deployment_method=args.deployment_method,
			mount_with_smbclient=mount_with_smbclient,
			depot=args.depot,
			group=args.group,
			username=args.username,
			finalize_action=finalize_action,
			stop_on_ping_failure=args.stop_on_ping_failure,
			skip_existing_client=args.skip_existing_client,
			keep_client_on_failure=args.keep_client_on_failure,
			ssh_hostkey_policy=ssh_hostkey_policy
	)
	sys.exit(returncode)

if __name__ == "__main__":
	main()
