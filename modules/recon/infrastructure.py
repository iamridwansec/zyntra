import socket


def resolve_hostname(hostname):
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM
        )

        return sorted({
            result[4][0]
            for result in results
        })

    except socket.gaierror:
        return []


def map_infrastructure(hostnames):
    infrastructure = {}

    for hostname in hostnames:
        infrastructure[hostname] = resolve_hostname(hostname)

    return infrastructure
