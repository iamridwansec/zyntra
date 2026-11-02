import socket
from pathlib import Path
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path



resolver = dns.resolver.Resolver()
resolver.timeout = 1.0
resolver.lifetime = 2.0


def load_wordlist(wordlist_path):
    with open(wordlist_path, "r") as file:
       return [
           line.strip().rstrip(".")
           for line in file
           if line.strip() and not line.strip().endswith(".")
       ]

def get_candidates():
    return [
        "www",
        "mail",
        "api",
        "dev",
        "test"
    ]


import re


def is_valid_candidate(candidate):
    return bool(re.fullmatch(r"[A-Za-z0-9-]+", candidate))


def check_subdomain(hostname):
    try:
        resolver.resolve(
            hostname,
            "A"
        )

        return hostname.lower()

    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout
    ):
        return None



def discover_subdomains(target, max_workers=10):
    domain = target.hostname

    wordlist_path = (
        Path(__file__).resolve().parents[2]
        / "config"
        / "wordlists"
        / "subdomains.txt"
    )

    candidates = [
        candidate
        for candidate in load_wordlist(wordlist_path)
        if is_valid_candidate(candidate)
    ]

    subdomains = set()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(
            check_subdomain,
            [f"{candidate}.{domain}" for candidate in candidates]
        )

        for result in results:
            if result:
                subdomains.add(result)

    return sorted(subdomains)
