import os
from time import sleep
from unittest import mock
import uuid

import ssl
import socket

from tlssysloghandler import TLSSysLogHandler

from test_util import SOCKET_PORT, SOCKET_TIMEOUT, TestCertManager

class TestTLSSysLogHandlerE2E(TestCertManager):
    def _start_server_worker(self, sock_family, sock_type, sock_addr, secure):
        if sock_type != socket.SOCK_DGRAM and sock_type != socket.SOCK_STREAM:
            raise ValueError(
                "sock_type must be socket.SOCK_DGRAM or socket.SOCK_STREAM"
            )
        print(f"starting {sock_family} server on {sock_addr} with {sock_type}")
        sock = socket.socket(sock_family, sock_type)
        print("socket created")
        sock.bind(*sock_addr)
        print("socket bound at:", sock)
        sock.settimeout(SOCKET_TIMEOUT)
        print("socket settimeout")
        oldsock = None
        if sock_type == socket.SOCK_STREAM:
            sock.listen(5)
            print("socket listening")
            if secure:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                print("socket setsockopt")
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                print("secure socket context created")
                context.load_cert_chain(certfile=self.pub_key, keyfile=self.priv_key)
                print("secure socket cert loaded")
                oldsock = sock
                sock = context.wrap_socket(sock, server_side=True)
                print("secure socket listening")

            conn, addr = sock.accept()
            print("socket accepted")
            conn.settimeout(SOCKET_TIMEOUT)
            print("conn socket settimeout")
        else:
            conn = sock
        while True:
            print("socket waiting for data")
            data = conn.recv(1024)
            if not data:
                break
            print("got data:", data.decode("utf-8"))
            self.queue.put(data)
        if sock_type == socket.SOCK_STREAM:
            conn.close()
        sock.close()
        if oldsock:
            oldsock.close()

    def _start_server(self, sock_family, sock_type, sock_addr, secure=False):
        # start a listener on the socket in separate thread using threadpoolexecutor
        self.executor.submit(
            self._start_server_worker, sock_family, sock_type, sock_addr, secure
        )
        sleep(4)

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
