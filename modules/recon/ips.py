import socket


def resolve_ips(hostname):
    results = socket.getaddrinfo(
        hostname,
        None,
        socket.AF_UNSPEC,
        socket.SOCK_STREAM
    )

    ipv4 = set()
    ipv6 = set()

    for result in results:
        address = result[4][0]

        if ":" in address:
            ipv6.add(address)
        else:
            ipv4.add(address)

    return {
        "ipv4": sorted(ipv4),
        "ipv6": sorted(ipv6)
    }
