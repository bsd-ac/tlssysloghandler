import socket
import syslog

from logging.handlers import SYSLOG_UDP_PORT, SysLogHandler
from typing import Union

try:
    import ssl
except ImportError:
    _have_ssl = False
else:
    _have_ssl = True


class TLSSysLogHandler(SysLogHandler):
    def __init__(
        self,
        address: Union[str, tuple[str, str]] = ("localhost", SYSLOG_UDP_PORT),
        facility: int = syslog.LOG_USER,
        socktype: socket.SocketType = socket.SOCK_DGRAM,
        secure: Union[bool, dict, str, ssl.SSLContext] = False,
    ):
        self.secure = secure
        super(TLSSysLogHandler, self).__init__(address, facility, socktype)

    def createSocket(self):
        """
        Try to create a socket and, if it's not a datagram socket, connect it
        to the other end. This method is called during handler initialization,
        but it's not regarded as an error if the other end isn't listening yet
        --- the method will be called again when emitting an event,
        if there is no socket at that point.
        """
        address = self.address
        socktype = self.socktype

        if isinstance(address, str):
            self.unixsocket = True
            # Syslog server may be unavailable during handler initialisation.
            # C's openlog() function also ignores connection errors.
            # Moreover, we ignore these errors while logging, so it's not worse
            # to ignore it also here.
            try:
                self._connect_unixsocket(address)
            except OSError:
                pass
        else:
            self.unixsocket = False
            if socktype is None:
                socktype = socket.SOCK_DGRAM
            host, port = address
            ress = socket.getaddrinfo(host, port, 0, socktype)
            if not ress:
                raise OSError("getaddrinfo returns an empty list")
            for res in ress:
                af, socktype, proto, _, sa = res
                err = sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    if self.secure:
                        if not _have_ssl:
                            raise RuntimeError(
                                "TLS not available in this Python installation"
                            )
                        if socktype != socket.SOCK_STREAM:
                            raise RuntimeError(
                                "TLS support only implemented for TCP connections"
                            )
                        context = ssl._create_stdlib_context()
                        if isinstance(self.secure, ssl.SSLContext):
                            context = self.secure
                        elif isinstance(self.secure, bool) and self.secure:
                            context = ssl.create_default_context()
                        elif isinstance(self.secure, dict):
                            context = ssl.create_default_context(**self.secure)
                        sock = context.wrap_socket(sock, server_hostname=host)
                    if socktype == socket.SOCK_STREAM:
                        sock.connect(sa)
                    break
                except (OSError, ssl.SSLError) as exc:
                    err = exc
                    if sock is not None:
                        sock.close()
            if err is not None:
                raise err
            self.socket = sock
            self.socktype = socktype
