"""Tests for Requests."""

import threading

import pytest
import requests

from .testserver.server import TLSServer, consume_socket_content

# Requests to this URL should always fail with a connection timeout (nothing
# listening on that port)
TARPIT = "http://10.255.255.1"

# This is to avoid waiting the timeout of using TARPIT
INVALID_PROXY = "http://localhost:1"

try:
    from ssl import SSLContext

    del SSLContext
    HAS_MODERN_SSL = True
except ImportError:
    HAS_MODERN_SSL = False

try:
    requests.pyopenssl
    HAS_PYOPENSSL = True
except AttributeError:
    HAS_PYOPENSSL = False


class TestPreparingURLs:
    def test_different_connection_pool_for_mtls_settings(self, session):
        client_cert = None

        def response_handler(sock):
            print("server got mesg")
            nonlocal client_cert
            client_cert = sock.getpeercert()
            consume_socket_content(sock, timeout=0.5)
            sock.send(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 18\r\n\r\n"
                b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'
            )

        close_server = threading.Event()
        server = TLSServer(
            handler=response_handler,
            wait_to_close_event=close_server,
            requests_to_handle=2,
            cert_chain="tests/certs/valid/server/server.pem",
            keyfile="tests/certs/valid/server/server.key",
            mutual_tls=True,
            cacert="tests/certs/valid/ca/ca.crt",
        )

        cert = (
            "tests/certs/mtls/client/client.pem",
            "tests/certs/mtls/client/client.key",
        )
        with server as (host, port):
            url = f"https://{host}:{port}"
            r1 = session.get(url, verify=False, cert=cert)
            assert r1.status_code == 200
            with pytest.raises(requests.exceptions.SSLError):
                session.get(url, cert=cert)
            close_server.set()

        assert client_cert is not None
