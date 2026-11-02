import socket


COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    8080: "http-alt",
}


def check_port(hostname, port, timeout=1):
    try:
        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ):
            return True

    except (socket.timeout, socket.error):
        return False


def discover_ports(hostname):
    results = []

    for port, service in COMMON_PORTS.items():
        if check_port(hostname, port):
            results.append({
                "port": port,
                "service": service
            })

    return results
