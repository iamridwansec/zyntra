import socket
import dns.resolver

def resolve_ipv4(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return ""


def resolve_ipv6(hostname):
    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            socket.AF_INET6
        )

        return list({result[4][0] for result in results})

    except socket.gaierror:
        return []

def resolve_reverse(hostname):
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(hostname)

        return {
            "hostname": hostname,
            "aliases": aliases,
            "addresses": addresses
        }

    except socket.herror:
        return {
            "hostname": "",
            "aliases": [],
            "addresses": []
        }



def resolve_mx(hostname):
    try:
        answers = dns.resolver.resolve(hostname, "MX")

        return [
            {
                "preference": record.preference,
                "exchange": str(record.exchange).rstrip(".")
            }
            for record in answers
            if str(record.exchange).rstrip(".")
        ]

    except (
        dns.resolver.NoAnswer, 
        dns.resolver.NXDOMAIN, 
        dns.resolver.NoNameservers, 
        dns.resolver.Timeout
    ):
        return []

def resolve_ns(hostname):
    try:
        answers = dns.resolver.resolve(hostname, "NS")

        return [
            str(record.target).rstrip(".")
            for record in answers
        ]

    except (
        dns.resolver.NoAnswer, 
        dns.resolver.NXDOMAIN, 
        dns.resolver.NoNameservers, 
        dns.resolver.Timeout
    ):
        return []

def collect_dns(hostname):
    return {
        "A": [resolve_ipv4(hostname)],
        "AAAA": resolve_ipv6(hostname),
        "MX": resolve_mx(hostname),
        "NS": resolve_ns(hostname)
    }


