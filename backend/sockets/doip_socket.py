import socket
import ssl
from typing import Optional, Union, Tuple, Dict, Any

class DoIPSSLStreamSocket:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.tls_port: int = 3496
        self.context: Optional[ssl.SSLContext] = None
    
    def connect(self, ip: str, port: int) -> None:
        self.sock.connect((ip, port))

    def send(self, data: bytes) -> int:
        return self.sock.send(data)

    def recv(self, size: int) -> bytes:
        return self.sock.recv(size)

    def close(self) -> None:
        self.sock.close()

class DoIPSocket(DoIPSSLStreamSocket):
    def __init__(self, ip: str = '127.0.0.1', port: int = 13400,
                 activate_routing: bool = True,
                 source_address: int = 0xe80,
                 target_address: int = 0,
                 activation_type: int = 0) -> None:
        self.ip = ip
        self.port = port
        self.source_address = source_address
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().__init__(s)

    def _init_socket(self) -> None:
        activation_return = 0x10
        connected = False
        sock_family = socket.AF_INET

        if activation_return == 0x10:
            return
        elif activation_return == 0x07:
            if self.context is None:
                raise ValueError("SSLContext 'context' can not be None")
            if connected:
                self.sock.close()
                self.sock = socket.socket(sock_family, socket.SOCK_STREAM)
                self.sock.settimeout(5)
                self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            ss = self.context.wrap_socket(self.sock)
            addrinfo = socket.getaddrinfo(
                self.ip, self.tls_port, proto=socket.IPPROTO_TCP)
            ss.connect(addrinfo[0][-1])
            self.sock = ss
