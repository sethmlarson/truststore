# truststore

Verify peer certificates using OS trust stores. Supports macOS, Windows, and Linux+OpenSSL.

```python
import socket
from truststore import Truststore

sock = socket.create_connection(("example.com", 443))
ts = Truststore()
sock = ts.wrap_socket(sock, server_hostname="example.com")
```

## License

MIT
