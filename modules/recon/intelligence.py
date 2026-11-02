import subprocess
import json
import urllib.request

def collect_whois(target):
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=10
        )

        return {
            "target": target,
            "status": result.returncode,
            "data": result.stdout
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "status": None,
            "data": ""
        }

def collect_rdap(domain):
    url = f"https://rdap.org/domain/{domain}"

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Zyntra/0.1.0"}
        )

        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            return {
                "domain": domain,
                "status": response.status,
                "data": json.loads(response.read().decode())
            }

    except Exception:
        return {
            "domain": domain,
            "status": None,
            "data": {}
        }

def collect_ip_intelligence(ip):
    url = f"https://rdap.org/ip/{ip}"

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Zyntra/0.1.0"}
        )

        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            return {
                "ip": ip,
                "status": response.status,
                "data": json.loads(response.read().decode())
            }

    except Exception:
        return {
            "ip": ip,
            "status": None,
            "data": {}
        }

def extract_ip_intelligence(data):
    intelligence = {
        "network_name": data.get("name", ""),
        "start_address": data.get("startAddress", ""),
        "end_address": data.get("endAddress", ""),
        "cidrs": data.get("cidr0_cidrs", []),
        "organizations": [],
        "registrant": [],
        "technical": [],
        "abuse": []
    }

    for entity_group in data.get("entities", []):
        for entity in entity_group.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [])

            if len(vcard) < 2:
                continue

            for field in vcard[1]:
                if not isinstance(field, list) or len(field) < 4:
                    continue

                if field[0] != "org":
                    continue

                organization = field[3]

                if not organization:
                    continue

                if organization not in intelligence["organizations"]:
                    intelligence["organizations"].append(organization)

                if "registrant" in roles and organization not in intelligence["registrant"]:
                    intelligence["registrant"].append(organization)

                if "technical" in roles and organization not in intelligence["technical"]:
                    intelligence["technical"].append(organization)

                if "abuse" in roles and organization not in intelligence["abuse"]:
                    intelligence["abuse"].append(organization)

    return intelligence
