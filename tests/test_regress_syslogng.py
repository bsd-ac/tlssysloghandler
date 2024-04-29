import os
import socket
import ssl
import subprocess
from time import sleep
import unittest
import uuid

from tlssysloghandler import TLSSysLogHandler

from test_util import SOCKET_PORT, TestCertManager

SOCKET_PORT4_DGRAM = SOCKET_PORT
SOCKET_PORT4_STREAM = SOCKET_PORT + 1
SOCKET_PORT4_TLS = SOCKET_PORT + 2
SOCKET_PORT6_DGRAM = SOCKET_PORT + 3
SOCKET_PORT6_STREAM = SOCKET_PORT + 4
SOCKET_PORT6_TLS = SOCKET_PORT + 5
SOCKET_PORT4_MUTUAL_TLS = SOCKET_PORT + 6
SOCKET_PORT6_MUTUAL_TLS = SOCKET_PORT + 7
SOCKET_PORT4_TLS10 = SOCKET_PORT + 8
SOCKET_PORT4_TLS11 = SOCKET_PORT + 9
SOCKET_PORT4_TLS12 = SOCKET_PORT + 10
SOCKET_PORT4_TLS13 = SOCKET_PORT + 11


# check if syslog-ng is installed else skip tests
try:
    subprocess.check_output(["syslog-ng", "--version"])
except FileNotFoundError:
    raise unittest.SkipTest("syslog-ng not installed")


class TestSyslogNG(TestCertManager):
    def _start_server(self):
        # create syslog-ng tls config
        config = """
@version: 4.4
@include "scl.conf"

source unix_dgram {{
    unix-dgram("{0}/syslog-dgram.sock");
}};
source unix_stream {{
    unix-stream("{0}/syslog-stream.sock");
}};
source net4_dgram {{
    network(
        ip("127.0.0.1")
        transport("udp")
        port({1})
    );
}};
source net4_stream {{
    network(
        ip("127.0.0.1")
        transport("tcp")
        port({2})
    );
}};
source net4_tls {{
    network(
        ip("127.0.0.1")
        transport("tls")
        port({3})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            peer-verify(optional-untrusted)
            cipher-suite("ALL:@SECLEVEL=0")
        )
    );
}};
source net6_dgram {{
    network(
        ip("::1")
        ip-protocol(6)
        transport("udp")
        port({4})
    );
}};
source net6_stream {{
    network(
        ip("::1")
        ip-protocol(6)
        transport("tcp")
        port({5})
    );
}};
source net6_tls {{
    network(
        ip("::1")
        ip-protocol(6)
        transport("tls")
        port({6})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            peer-verify(optional-untrusted)
            cipher-suite("ALL:@SECLEVEL=0")
        )
    );
}};
source net4_mutual_tls {{
    network(
        ip("127.0.0.1")
        transport("tls")
        port({7})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            ca-file("{0}/syslog.pub")
            peer-verify(required-trusted)
        )
    );
}};
source net6_mutual_tls {{
    network(
        ip("::1")
        ip-protocol(6)
        transport("tls")
        port({8})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            ca-file("{0}/syslog.pub")
            peer-verify(required-trusted)
        )
    );
}};
source net4_tls10 {{
    network(
        ip("127.0.0.1")
        transport("tls")
        port({9})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            peer-verify(optional-untrusted)
            ssl-options(no-tlsv11, no-tlsv12, no-tlsv13)
            cipher-suite("ALL:@SECLEVEL=0")
        )
    );
}};
source net4_tls11 {{
    network(
        ip("127.0.0.1")
        transport("tls")
        port({10})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            peer-verify(optional-untrusted)
            ssl-options(no-tlsv1, no-tlsv12, no-tlsv13)
        )
    );
}};
source net4_tls12 {{
    network(
        ip("127.0.0.1")
        transport("tls")
        port({11})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            peer-verify(optional-untrusted)
            ssl-options(no-tlsv1, no-tlsv11, no-tlsv13)
        )
    );
}};
source net4_tls13 {{
    network(
        ip("127.0.0.1")
        transport("tls")
        port({12})
        tls(
            key-file("{0}/syslog.key")
            cert-file("{0}/syslog.pub")
            peer-verify(optional-untrusted)
            ssl-options(no-tlsv1, no-tlsv11, no-tlsv12)
        )
    );
}};


destination all {{
    file("{0}/syslog.log");
}};

filter f_messages {{ level(debug..crit) }};

log {{
    source(unix_dgram);
    filter(f_messages);
    destination(all);
}};
log {{
    source(unix_stream);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_dgram);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_stream);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_tls);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net6_dgram);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net6_stream);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net6_tls);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_mutual_tls);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net6_mutual_tls);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_tls10);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_tls11);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_tls12);
    filter(f_messages);
    destination(all);
}};
log {{
    source(net4_tls13);
    filter(f_messages);
    destination(all);
}};
        """

        config = config.format(
            self.tmpdir.name,
            SOCKET_PORT4_DGRAM,
            SOCKET_PORT4_STREAM,
            SOCKET_PORT4_TLS,
            SOCKET_PORT6_DGRAM,
            SOCKET_PORT6_STREAM,
            SOCKET_PORT6_TLS,
            SOCKET_PORT4_MUTUAL_TLS,
            SOCKET_PORT6_MUTUAL_TLS,
            SOCKET_PORT4_TLS10,
            SOCKET_PORT4_TLS11,
            SOCKET_PORT4_TLS12,
            SOCKET_PORT4_TLS13,
        )

        config_path = os.path.join(self.tmpdir.name, "syslog-ng.conf")
        with open(config_path, "w") as f:
            f.write(config)

        # create output file
        open(os.path.join(self.tmpdir.name, "syslog.log"), "w").close()

        # generate certificates
        self._generate_keys()

        # start syslog-ng
        command = [
            "syslog-ng",
            "-F",
            "-d",
            "-f",
            config_path,
            "--persist-file",
            f"{self.tmpdir.name}/syslog-ng.persist-",
            "--pidfile",
            f"{self.tmpdir.name}/syslog-ng.pid",
            "--control",
            f"{self.tmpdir.name}/syslog-ng.ctl",
        ]

        self.server_pid = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdir.name,
        )

        # wait for syslog-ng to start
        sleep(1)

    def _stop_server(self):
        self.server_pid.kill()
        self.server_pid.wait()

    def setUp(self):
        super().setUp()
        self._start_server()

    def tearDown(self):
        self._stop_server()
        super().tearDown()

    def test_SYSLOGNG_INET4_DGRAM(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_DGRAM), socktype=socket.SOCK_DGRAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_STREAM(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_STREAM), socktype=socket.SOCK_STREAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_TLS(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_TLS),
            socktype=socket.SOCK_STREAM,
            secure={"cafile": self.tmpdir.name + "/syslog.pub"},
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_TLS10(self):
        test_logger = self._build_logger()

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_TLS10),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_TLS12(self):
        test_logger = self._build_logger()

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_TLS12),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_TLS13(self):
        test_logger = self._build_logger()

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_TLS13),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_TLS13_TO_TLS12_FAIL(self):
        test_logger = self._build_logger()

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        with self.assertRaises(ssl.SSLError):
            handler = TLSSysLogHandler(
                address=("127.0.0.1", SOCKET_PORT4_TLS12),
                socktype=socket.SOCK_STREAM,
                secure=context,
            )

    def test_SYSLOGNG_INET4_TLS10_TO_DEFAULT_LISTENER(self):
        test_logger = self._build_logger()

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.set_ciphers("ALL:@SECLEVEL=0")
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_TLS),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_TLS_ENFORCE_MINIMUM(self):
        test_logger = self._build_logger()

        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_TLS),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        tls_version = handler.socket.version()
        self.assertNotEqual(tls_version, ssl.TLSVersion.TLSv1)
        self.assertNotEqual(tls_version, ssl.TLSVersion.TLSv1_1)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_unix_DGRAM(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=self.tmpdir.name + "/syslog-dgram.sock", socktype=socket.SOCK_DGRAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_unix_STREAM(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=self.tmpdir.name + "/syslog-stream.sock",
            socktype=socket.SOCK_STREAM,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET6_DGRAM(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("::1", SOCKET_PORT6_DGRAM), socktype=socket.SOCK_DGRAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET6_STREAM(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("::1", SOCKET_PORT6_STREAM), socktype=socket.SOCK_STREAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET6_TLS(self):
        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("::1", SOCKET_PORT6_TLS),
            socktype=socket.SOCK_STREAM,
            secure={"cafile": self.tmpdir.name + "/syslog.pub"},
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET4_MUTUAL_TLS(self):
        test_logger = self._build_logger()

        # custom context for mutual TLS
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.load_cert_chain(
            certfile=self.tmpdir.name + "/syslog.pub",
            keyfile=self.tmpdir.name + "/syslog.key",
        )

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_MUTUAL_TLS),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)

    def test_SYSLOGNG_INET6_MUTUAL_TLS(self):
        test_logger = self._build_logger()

        # custom context for mutual TLS
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH, cafile=self.tmpdir.name + "/syslog.pub"
        )
        context.load_cert_chain(
            certfile=self.tmpdir.name + "/syslog.pub",
            keyfile=self.tmpdir.name + "/syslog.key",
        )

        handler = TLSSysLogHandler(
            address=("::1", SOCKET_PORT6_MUTUAL_TLS),
            socktype=socket.SOCK_STREAM,
            secure=context,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
            data = f.read()
            self.assertTrue(uuid_message in data)
