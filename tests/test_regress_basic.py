import os
from time import sleep
from unittest import mock
import uuid

import ssl
import logging
import socket
import inspect

from tlssysloghandler import TLSSysLogHandler

from test_util import SOCKET_PORT, TestCertManager

class TestTLSSysLogHandlerE2E(TestCertManager):
    def _build_logger(self) -> logging.Logger:
        stack = inspect.stack()
        logger_name = "{}.{}".format(__name__, stack[1][3])

        test_logger = logging.getLogger(logger_name)
        test_logger.setLevel(logging.DEBUG)

        for handler in test_logger.handlers:
            test_logger.removeHandler(handler)

        return test_logger

    def test_e2e_unix_DGRAM(self):
        self.socket_path = os.path.join(self.tmpdir.name, "syslog.sock")
        self._start_server(socket.AF_UNIX, socket.SOCK_DGRAM, (self.socket_path,))

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(address=self.socket_path, socktype=socket.SOCK_DGRAM)
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_unix_STREAM(self):
        self.socket_path = os.path.join(self.tmpdir.name, "syslog.sock")
        self._start_server(socket.AF_UNIX, socket.SOCK_STREAM, (self.socket_path,))

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=self.socket_path, socktype=socket.SOCK_STREAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET_DGRAM(self):
        socket_addr = ("127.0.0.1", SOCKET_PORT)
        self._start_server(socket.AF_INET, socket.SOCK_DGRAM, (socket_addr,))

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(address=socket_addr, socktype=socket.SOCK_DGRAM)
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET_STREAM(self):
        socket_addr = ("127.0.0.1", SOCKET_PORT)
        self._start_server(socket.AF_INET, socket.SOCK_STREAM, (socket_addr,))

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(address=socket_addr, socktype=socket.SOCK_STREAM)
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET6_DGRAM(self):
        socket_addr = ("::1", SOCKET_PORT)
        self._start_server(socket.AF_INET6, socket.SOCK_DGRAM, (socket_addr,))

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(address=socket_addr, socktype=socket.SOCK_DGRAM)
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET6_STREAM(self):
        socket_addr = ("::1", SOCKET_PORT)
        self._start_server(socket.AF_INET6, socket.SOCK_STREAM, (socket_addr,))

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(address=socket_addr, socktype=socket.SOCK_STREAM)
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET6_STREAM_SECURE_NOVERIFY(self):
        socket_addr = ("::1", SOCKET_PORT)
        self._start_server(socket.AF_INET6, socket.SOCK_STREAM, (socket_addr,), True)

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=socket_addr, socktype=socket.SOCK_STREAM, secure="noverify"
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET_STREAM_SECURE_VERIFY_CONTEXT(self):
        socket_addr = ("localhost", SOCKET_PORT)
        self._start_server(socket.AF_INET, socket.SOCK_STREAM, (socket_addr,), True)

        test_logger = self._build_logger()

        context = ssl.create_default_context()
        context.load_verify_locations(cafile=self.pub_key)

        handler = TLSSysLogHandler(
            address=socket_addr, socktype=socket.SOCK_STREAM, secure=context
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET_STREAM_SECURE_VERIFY_CAFILE(self):
        socket_addr = ("localhost", SOCKET_PORT)
        self._start_server(socket.AF_INET, socket.SOCK_STREAM, (socket_addr,), True)

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=socket_addr,
            socktype=socket.SOCK_STREAM,
            secure={"cafile": self.pub_key},
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(1)

        data = self.queue.get(timeout=1)
        self.assertTrue(uuid_message in data.decode("utf-8"))

        print("done")
        handler.close()

    def test_e2e_INET6_STREAM_SECURE_VERIFY_FAIL_INCORRECT_CERT(self):
        socket_addr = ("::1", SOCKET_PORT)
        self._start_server(socket.AF_INET6, socket.SOCK_STREAM, (socket_addr,), True)

        # normal secure connect should not work
        with self.assertRaises(ssl.SSLCertVerificationError):
            handler = TLSSysLogHandler(
                address=socket_addr, socktype=socket.SOCK_STREAM, secure=True
            )

        print("done")

    @mock.patch("tlssysloghandler.handler.socket.getaddrinfo")
    def test_e2e_INET6_STREAM_SECURE_VERIFY_FAIL_WRONG_HOSTNAME(self, mock_getaddrinfo):
        # try listening on secure-logging.example.com (mocked to return address "::1")
        mock_getaddrinfo.return_value = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 56712, 0, 0))
        ]

        server_socket_addr = ("::1", SOCKET_PORT)
        self._start_server(
            socket.AF_INET6, socket.SOCK_STREAM, (server_socket_addr,), True
        )

        # normal secure connect should not work
        logger_socket_addr = ("secure-logging.example.com.", SOCKET_PORT)
        with self.assertRaises(ssl.SSLCertVerificationError):
            handler = TLSSysLogHandler(
                address=logger_socket_addr,
                socktype=socket.SOCK_STREAM,
                secure={"cafile": self.pub_key},
            )

        print("done")
