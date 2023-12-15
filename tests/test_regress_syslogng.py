import os
import socket
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


# check if syslog-ng is installed else skip tests
try:
    subprocess.check_output(["syslog-ng", "--version"])
except FileNotFoundError:
    raise unittest.SkipTest("syslog-ng not installed")


class TestSyslogNG(TestCertManager):
    def _start_server(self, ip):
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
            peer-verify(required-trusted)
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

    def test_syslogng_inet_DGRAM(self):
        self._start_server("127.0.0.1")

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_DGRAM), socktype=socket.SOCK_DGRAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_inet_STREAM(self):
        self._start_server("127.0.0.1")

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("127.0.0.1", SOCKET_PORT4_STREAM), socktype=socket.SOCK_STREAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_inet_TLS(self):
        self._start_server("127.0.0.1")

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

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_unix_DGRAM(self):
        self._start_server("127.0.0.1")

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=self.tmpdir.name + "/syslog-dgram.sock", socktype=socket.SOCK_DGRAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_unix_STREAM(self):
        self._start_server("127.0.0.1")

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=self.tmpdir.name + "/syslog-stream.sock",
            socktype=socket.SOCK_STREAM,
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_inet6_DGRAM(self):
        self._start_server("::1")

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("::1", SOCKET_PORT6_DGRAM), socktype=socket.SOCK_DGRAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_inet6_STREAM(self):
        self._start_server("::1")

        test_logger = self._build_logger()

        handler = TLSSysLogHandler(
            address=("::1", SOCKET_PORT6_STREAM), socktype=socket.SOCK_STREAM
        )
        test_logger.addHandler(handler)

        uuid_message = uuid.uuid4().hex
        test_logger.critical(uuid_message)

        sleep(2)

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()

    def test_syslogng_inet6_TLS(self):
        self._start_server("::1")

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

        try:
            with open(os.path.join(self.tmpdir.name, "syslog.log")) as f:
                data = f.read()
                self.assertTrue(uuid_message in data)
        finally:
            self._stop_server()
