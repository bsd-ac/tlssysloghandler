import datetime
import ipaddress
import multiprocessing
import concurrent.futures
import os
import tempfile
from time import sleep
from unittest import TestCase

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

import logging
import inspect


SOCKET_PORT = int(os.environ.get("SOCKET_PORT", 56712))

RSA_PUBLIC_EXPONENT = 65537
RSA_KEY_SIZE = 2048

# logger = logging.getLogger(__name__)


class TestCertManager(TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.queue = multiprocessing.Queue(maxsize=1)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self._generate_keys()

    def tearDown(self):
        self.executor.shutdown(wait=True)
        self.queue.close()
        # self.tmpdir.cleanup()

    def _build_logger(self) -> logging.Logger:
        stack = inspect.stack()
        logger_name = "{}.{}".format(__name__, stack[1][3])

        test_logger = logging.getLogger(logger_name)
        test_logger.setLevel(logging.DEBUG)

        for handler in test_logger.handlers:
            test_logger.removeHandler(handler)

        return test_logger

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
