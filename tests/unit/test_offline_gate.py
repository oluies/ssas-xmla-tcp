"""Constitution III is NON-NEGOTIABLE, so assert it rather than trusting config.

If someone later drops --disable-socket from pytest configuration, these fail and
say why, instead of the suite quietly acquiring a network dependency.
"""

import socket

import pytest
from pytest_socket import SocketBlockedError


def test_creating_a_socket_is_blocked_in_the_default_run():
    # pytest-socket blocks construction, not merely connect(), so nothing in the
    # suite can reach the network even by accident.
    with pytest.raises(SocketBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_connecting_is_blocked_too():
    with pytest.raises(SocketBlockedError):
        socket.create_connection(("198.51.100.1", 80), timeout=1)
