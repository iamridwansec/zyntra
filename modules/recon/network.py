import socket


def parse_ports(selection, confirm_full_scan=False):
    if not selection or not selection.strip():
        raise ValueError("Port selection cannot be empty.")

    ports = set()

    for item in selection.split(","):
        item = item.strip()

        if not item:
            raise ValueError("Empty port entry detected.")

        if "-" in item:
            parts = item.split("-")

            if len(parts) != 2:
                raise ValueError(f"Invalid port range: {item}")

            try:
                start, end = map(int, parts)
            except ValueError:
                raise ValueError(f"Invalid port range: {item}")

            if start > end:
                raise ValueError(f"Reversed port range: {item}")

            if start < 1 or end > 65535:
                raise ValueError(f"Port range outside 1-65535: {item}")

            ports.update(range(start, end + 1))

        else:
            try:
                port = int(item)
            except ValueError:
                raise ValueError(f"Invalid port: {item}")

            if not 1 <= port <= 65535:
                raise ValueError(f"Port outside 1-65535: {port}")

            ports.add(port)

    if len(ports) == 65535 and not confirm_full_scan:
        raise ValueError(
            "Full port scan requires --confirm-full-scan."
        )

    return sorted(ports)

def check_port(hostname, port, timeout=1):
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return "open"

    except ConnectionRefusedError:
        return "closed"

    except socket.timeout:
        return "no_response"

    except OSError:
        return "error"


def discover_ports(hostname, ports=None, timeout=1):
    if not ports:
        return {
            "status": "skipped",
            "requested_ports": [],
            "results": [],
            "reason": "No ports were explicitly selected."
        }

    results = []

    for port in ports:
        status = check_port(hostname, port, timeout)

        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"

        results.append({
            "port": port,
            "service": service,
            "status": status
        })

    return {
        "status": "completed",
        "requested_ports": ports,
        "results": results,
        "reason": None
    }
