import socket
import ssl
from truststore import verify_peercerts

sock = socket.create_connection(("example.com", 443))
ctx = ssl.create_default_context()
sock = ctx.wrap_socket(sock)

verify_peercerts(sock, server_hostname="example.com")
