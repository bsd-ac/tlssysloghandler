import datetime
import ipaddress
import multiprocessing
import concurrent.futures
import os
import tempfile
from time import sleep
from unittest import TestCase, mock
import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

import ssl
import logging
import socket
import inspect

from tlssysloghandler import TLSSysLogHandler

SOCKET_PORT = int(os.environ.get("SOCKET_PORT", 56712))
SOCKET_TIMEOUT = 5
SOCKET_BUFFERSIZE = 1024

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048

# logger = logging.getLogger(__name__)


class TestTLSSysLogHandlerE2E(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.queue = multiprocessing.Queue(maxsize=1)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self._generate_keys()

    def tearDown(self):
        self.executor.shutdown(wait=True)
        self.queue.close()
        self.tmpdir.cleanup()

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

    # https://gist.github.com/bloodearnest/9017111a313777b9cce5
    # Copyright 2018 Simon Davy
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    # SOFTWARE.
    def _generate_selfsigned_cert(self, hostname, ip_addresses=None, key=None):
        """Generates self signed certificate for a hostname, and optional IP addresses."""
        # Generate our key
        if key is None:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend(),
            )

        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])

        # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
        alt_names = [x509.DNSName(hostname)]

        # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
        if ip_addresses:
            for addr in ip_addresses:
                # openssl wants DNSnames for ips...
                alt_names.append(x509.DNSName(addr))
                # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
                # note: older versions of cryptography do not understand ip_address objects
                alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))

        san = x509.SubjectAlternativeName(alt_names)

        # path_len=0 means this cert can only sign itself, not other certs.
        basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
        now = datetime.datetime.now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=10 * 365))
            .add_extension(basic_contraints, False)
            .add_extension(san, False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def _generate_keys(self):
        pub_key_bytes, priv_key_bytes = self._generate_selfsigned_cert(
            "localhost", ["::1", "127.0.0.1"]
        )

        pub_key_path = os.path.join(self.tmpdir.name, "syslog.pub")
        priv_key_path = os.path.join(self.tmpdir.name, "syslog.key")

        with open(pub_key_path, "wb") as f:
            f.write(pub_key_bytes)

        with open(priv_key_path, "wb") as f:
            f.write(priv_key_bytes)

        self.priv_key = priv_key_path
        self.pub_key = pub_key_path

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
