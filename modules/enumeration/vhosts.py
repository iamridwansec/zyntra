import secrets
import re
import hashlib
import ssl
import socket
import http.client
from ipaddress import ip_address
from urllib.parse import urlparse
from config.paths import VHOST_WORDLIST

from modules.recon.ips import resolve_ips


def load_vhost_prefixes():
    wordlist_path = VHOST_WORDLIST

    content = wordlist_path.read_text(encoding="utf-8")

    prefixes = []

    for line in content.splitlines():
        prefix = line.strip()

        if not prefix or prefix.startswith("#"):
            continue

        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
            prefix
        ):
            continue

        if prefix not in prefixes:
            prefixes.append(prefix)

    if not prefixes:
        raise ValueError("VHost wordlist contains no valid entries.")

    return prefixes

class SNIHTTPSConnection(http.client.HTTPConnection):

    def __init__(
        self,
        host,
        port,
        server_hostname,
        timeout=5
    ):
        super().__init__(host, port, timeout=timeout)

        self.server_hostname = server_hostname

        # VHost discovery must tolerate certificates
        # that do not match the candidate hostname.
        self.context = ssl.create_default_context()
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def connect(self):
        self.sock = socket.create_connection(
            (self.host, self.port),
            self.timeout
        )

        self.sock = self.context.wrap_socket(
            self.sock,
            server_hostname=self.server_hostname
        )


def fetch_response(
    target_ip,
    port,
    path,
    host_header,
    scheme="http",
    server_hostname=None,
    timeout=5
):
    if scheme == "https":
        connection = SNIHTTPSConnection(
            target_ip,
            port,
            server_hostname,
            timeout
        )
    else:
        connection = http.client.HTTPConnection(
            target_ip,
            port,
            timeout=timeout
        )

    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": host_header,
                "User-Agent": "Zyntra/0.1.0"
            }
        )

        response = connection.getresponse()
        body = response.read()

        return {
            "status_code": response.status,
            "content_length": len(body),
            "body_hash": hashlib.sha256(body).hexdigest(),
            "location": response.getheader("Location")
        }

    finally:
        connection.close()



def discover_vhosts(base_url):
    try:
        prefixes = load_vhost_prefixes()
    except (OSError, ValueError) as error:
        return {
            "status": "error",
            "message": f"VHost wordlist error: {error}"
        }

    parsed = urlparse(base_url)

    hostname = parsed.hostname
    scheme = parsed.scheme
    port = parsed.port

    if not hostname:
        return {
            "status": "error",
            "message": "Invalid target hostname."
        }

    try:
        ip_address(hostname)
        return {
            "status": "unsupported",
            "message": "VHost discovery requires a domain hostname, not an IP address."
        }
    except ValueError:
        pass

    if scheme not in ("http", "https"):
        return {
            "status": "unsupported",
            "message": "VHost discovery supports HTTP and HTTPS only."
        }

    if port is None:
        port = 443 if scheme == "https" else 80

    default_port = 443 if scheme == "https" else 80

    path = parsed.path or "/"

    if parsed.query:
        path += f"?{parsed.query}"

    try:
        resolved = resolve_ips(hostname)
        addresses = resolved["ipv4"]

        if not addresses:
            return {
                "status": "error",
                "message": "No IPv4 address found for target."
            }

        target_ip = addresses[0]

    except OSError as error:
        return {
            "status": "error",
            "message": f"DNS resolution failed: {error}"
        }

    host_header = (
        hostname if port == default_port
        else f"{hostname}:{port}"
    )

    try:
        baseline = fetch_response(
            target_ip,
            port,
            path,
            host_header,
            scheme=scheme,
            server_hostname=hostname
        )

    except (OSError, http.client.HTTPException, TimeoutError) as error:
        return {
            "status": "error",
            "message": f"Baseline request failed: {error}"
        }
    control_label = secrets.token_hex(3)
    control_hostname = f"control-{control_label}.{hostname}"

    control_host_header = (
        control_hostname if port == default_port
        else f"{control_hostname}:{port}"
    )

    try:
        control_baseline = fetch_response(
            target_ip,
            port,
            path,
            control_host_header,
            scheme=scheme,
            server_hostname=control_hostname
        )

    except (OSError, http.client.HTTPException, TimeoutError) as error:
        return {
            "status": "error",
            "message": f"Control request failed: {error}"
        }

    potential_vhosts = []

    classification_counts = {
        "redirect": 0,
        "distinct_response": 0,
        "generic_response": 0,
        "baseline_match": 0
    }

    for prefix in prefixes:
        candidate = f"{prefix}.{hostname}"

        candidate_host_header = (
            candidate if port == default_port
            else f"{candidate}:{port}"
        )

        try:
            candidate_result = fetch_response(
                target_ip,
                port,
                path,
                candidate_host_header,
                scheme=scheme,
                server_hostname=candidate
            )
            candidate_result["hostname"] = candidate

            redirect_codes = {301, 302, 303, 307, 308}

            matches_control = (
                candidate_result["status_code"] == control_baseline["status_code"]
                and candidate_result["content_length"] == control_baseline["content_length"]
                and candidate_result["body_hash"] == control_baseline["body_hash"]
                and candidate_result["location"] == control_baseline["location"]
            )

            if matches_control:
                candidate_result["classification"] = "generic_response"

            elif candidate_result["status_code"] in redirect_codes:
                candidate_result["classification"] = "redirect"

            elif (
                candidate_result["status_code"] != baseline["status_code"]
                or candidate_result["content_length"] != baseline["content_length"]
                or candidate_result["body_hash"] != baseline["body_hash"]
            ):
                candidate_result["classification"] = "distinct_response"

            else:
                candidate_result["classification"] = "baseline_match"

            classification = candidate_result["classification"]
            classification_counts[classification] += 1

            if classification in ("redirect", "distinct_response"):
                potential_vhosts.append(candidate_result)


        except (OSError, http.client.HTTPException, TimeoutError):
            continue


    return {
        "status": "completed",
        "target": hostname,
        "ip": target_ip,
        "baseline": baseline,
        "control_hostname": control_hostname,
        "control_baseline": control_baseline,
        "tested": len(prefixes),
        "classification_counts": classification_counts,
        "potential_vhosts": potential_vhosts
    }
