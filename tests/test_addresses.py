# opsi-deploy-client-agent is part of the desktop management solution opsi http://www.opsi.org
# Copyright (c) 2020-2025 uib GmbH <info@uib.de>
# This code is owned by the uib GmbH, Mainz, Germany (uib.de). All rights reserved.
# License: AGPL-3.0-only

"""
test addresses

basic tests for address handling of DeployThreads
"""

import socket
import pytest

from opsideployclientagent.common import DeployThread

BACKEND = None
SUFFIX = ".".join(socket.getfqdn().split(".")[1:])


@pytest.mark.parametrize(
	"host, method, result_method",
	(
		("localhost.domain.local", "auto", "fqdn"),
		("127.0.0.1", "auto", "ip"),
		("localhost", "auto", "hostname"),
		("localhost.domain.local", "fqdn", "fqdn"),
		("127.0.0.1", "ip", "ip"),
		("localhost", "hostname", "hostname"),
	),
)
def test_detect_deployment_method(host, method, result_method):
	deploy_thread = DeployThread(
		host,
		BACKEND,
		"testuser",
		"testpassword",
		deployment_method=method,
	)
	assert deploy_thread.deployment_method == result_method


@pytest.mark.parametrize(
	"host, result_host",
	(
		("localhost.domain.local", "localhost.domain.local"),
		("127.0.0.1", f"localhost.{SUFFIX}"),
		("localhost", f"localhost.{SUFFIX}"),
	),
)
def test_set_host_id(host, result_host):
	deploy_thread = DeployThread(
		host,
		BACKEND,
		"testuser",
		"testpassword",
	)
	assert deploy_thread.host == result_host
