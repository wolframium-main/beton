"""lab-tls.py — pocket HTTPS for L2 measurements. One server, accepts any SNI,
answers 200 OK with the SNI name (found by crude hostname search in ClientHello).
Listens on 0.0.0.0:18443 (no root). lab-cert.pem next to it is NOT committed
(private key!); regenerate:
  openssl req -x509 -newkey rsa:2048 -nodes -keyout lab-cert.pem -out lab-cert.pem -days 2 -subj "/CN=fine.test"

Guest: curl -k https://megablock.test:18443/ --resolve megablock.test:18443:10.0.2.2
"""
import os
import socket
import ssl
import threading

CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lab-cert.pem")
PORT = 18443
HTTP_PORT = 18080


def serve_http() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", HTTP_PORT))
    srv.listen(32)
    print(f"lab-http on :{HTTP_PORT}", flush=True)
    while True:
        conn, _ = srv.accept()
        try:
            conn.settimeout(10)
            try:
                data = conn.recv(4096)
            except socket.timeout:
                data = b""
            host = "?"
            low = data.lower()
            for marker in (b"megablock.test", b"fine.test"):
                if marker in low:
                    host = marker.decode()
                    break
            body = f"lab-http host={host}\n".encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        except OSError:
            pass
        finally:
            conn.close()


def handle(conn: socket.socket) -> None:
    try:
        conn.settimeout(10)
        try:
            data = conn.recv(4096)
        except socket.timeout:
            data = b""
        host = "?"
        for marker in (b"megablock.test", b"fine.test"):
            if marker in data.lower():
                host = marker.decode()
                break
        body = f"lab-tls sni={host}\n".encode()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
    except OSError:
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def main() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(32)
    print(f"lab-tls on :{PORT}", flush=True)
    threading.Thread(target=serve_http, daemon=True).start()
    while True:
        try:
            raw, _ = srv.accept()
        except OSError:
            continue
        raw.settimeout(10)
        try:
            conn = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError, socket.timeout):
            raw.close()
            continue
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
