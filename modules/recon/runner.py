from datetime import datetime

from core.assessment import Assessment
from core.observation import Observation
from .target import Target
from .dns import collect_dns, resolve_reverse
from .subdomains import discover_subdomains
from .ips import resolve_ips
from .intelligence import (
    collect_ip_intelligence,
    extract_ip_intelligence,
    collect_whois,
    collect_rdap
)
from .technologies import identify_technologies
from .network import discover_ports
from .web import discover_web_surface
from .infrastructure import map_infrastructure
from core.ids import generate_assessment_id
from core.serializer import save_assessment



def run(target):
    target = Target(target)

    assessment = Assessment(
        assessment_id=generate_assessment_id(),
        target=target,
        started_at=datetime.now()
    )

    if target.target_type in ("domain", "url"):
        dns_data = collect_dns(target.hostname)

        observation = Observation(
            category="dns",
            source="recon",
            data=dns_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)


        whois_result = collect_whois(target.hostname)

        if whois_result["status"] == 0:
            observation = Observation(
                category="whois",
                source="recon",
                data=whois_result,
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

        rdap_result = collect_rdap(target.hostname)

        if rdap_result["status"] == 200:
            observation = Observation(
                category="rdap",
                source="recon",
                data=rdap_result,
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

        technology_data = identify_technologies(
            target.value if target.target_type == "url"
            else f"https://{target.hostname}"
        )

        observation = Observation(
            category="technologies",
            source="recon",
            data=technology_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)


        subdomains = discover_subdomains(target)

        observation = Observation(
            category="subdomains",
            source="recon",
            data=subdomains,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)

        infrastructure_hosts = [target.hostname] + subdomains

        infrastructure_data = map_infrastructure(
            infrastructure_hosts
        )

        observation = Observation(
            category="infrastructure",
            source="recon",
            data=infrastructure_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)

        ip_data = resolve_ips(target.hostname)

        observation = Observation(
            category="ip_addresses",
            source="recon",
            data=ip_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)
        
        network_data = discover_ports(target.hostname)

        observation = Observation(
            category="network",
            source="recon",
            data=network_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)


        web_data = discover_web_surface(
            target.value if target.target_type == "url"
            else f"https://{target.hostname}"
        )

        observation = Observation(
            category="web_surface",
            source="recon",
            data=web_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)


        seen_intelligence = set()

        for ip in sorted(set(ip_data["ipv4"])):
            ip_result = collect_ip_intelligence(ip)

            if ip_result["status"] == 200:
                intelligence_data = extract_ip_intelligence(ip_result["data"])

                intelligence_key = (
                    intelligence_data["network_name"],
                    intelligence_data["start_address"],
                    intelligence_data["end_address"],
                    tuple(
                        tuple(sorted(cidr.items()))
                        for cidr in intelligence_data["cidrs"]
                    ),
                    tuple(sorted(intelligence_data["organizations"])),
                    tuple(sorted(intelligence_data["technical"])),
                    tuple(sorted(intelligence_data["abuse"]))
                )

                if intelligence_key in seen_intelligence:
                    continue

                seen_intelligence.add(intelligence_key)

                assessment.add_observation(Observation(
                    category="ip_intelligence",
                    source="recon",
                    data=intelligence_data,
                    timestamp=datetime.now()
                ))


    elif target.target_type == "ip":
        reverse_data = resolve_reverse(target.value)

        observation = Observation(
            category="reverse_dns",
            source="recon",
            data=reverse_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)


        network_data = discover_ports(target.value)

        observation = Observation(
            category="network",
            source="recon",
            data=network_data,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)

        ip_result = collect_ip_intelligence(target.value)

        if ip_result["status"] == 200:
            intelligence_data = extract_ip_intelligence(
                ip_result["data"]
            )

            observation = Observation(
                category="ip_intelligence",
                source="recon",
                data=intelligence_data,
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

            
    print(f"[+] Recon target: {assessment.target.value}")
    print(f"[+] Target type: {assessment.target.target_type}")
    print(f"[+] Assessment ID: {assessment.assessment_id}")
    print(f"[+] Assessment status: {assessment.status}")
    print(f"[+] Observations: {len(assessment.observations)}")

    if assessment.observations:
        for observation in assessment.observations:
            print(f"[+] Category: {observation.category}")

            if observation.category == "reverse_dns":
                print(f"[+] Hostname: {observation.data['hostname']}")
                print(f"[+] Aliases: {observation.data['aliases']}")
                print(f"[+] Addresses: {observation.data['addresses']}")

            elif observation.category == "dns":
                print(f"[+] A: {observation.data['A']}")
                print(f"[+] AAAA: {observation.data['AAAA']}")
                print(f"[+] MX: {observation.data['MX']}") 
                print(f"[+] NS: {observation.data['NS']}")


            elif observation.category == "whois":
                print(f"[+] WHOIS target: {observation.data['target']}")
                print(f"[+] WHOIS data:\n{observation.data['data']}")

            elif observation.category == "rdap":
                print(f"[+] RDAP domain: {observation.data['domain']}")
                print(f"[+] RDAP status: {observation.data['status']}")
                print(f"[+] RDAP data keys: {list(observation.data['data'].keys())}")

            elif observation.category == "technologies":
                data = observation.data

                print(f"[+] URL: {data['url']}")
                print(f"[+] Status: {data['status']}")
                print(f"[+] Server: {data['server']}")
                print(f"[+] Powered By: {data['powered_by']}")
                print(f"[+] Error: {data.get('error', '')}")

            elif observation.category == "ip_intelligence":
                data = observation.data

                print(f"[+] Network: {data['network_name']}")
                print(f"[+] Range: {data['start_address']} - {data['end_address']}")
                print(f"[+] CIDRs: {data['cidrs']}")
                print(f"[+] Organizations: {data['organizations']}")
                print(f"[+] Technical: {data['technical']}")
                print(f"[+] Abuse: {data['abuse']}")

            elif observation.category == "subdomains":
                print(f"[+] Subdomains: {observation.data}")


            elif observation.category == "infrastructure":
                print("[+] Infrastructure:")

                for hostname, addresses in observation.data.items():
                    print(f"    {hostname}: {addresses}")


            elif observation.category == "ip_addresses":
                print(f"[+] IPv4: {observation.data['ipv4']}")
                print(f"[+] IPv6: {observation.data['ipv6']}")

            elif observation.category == "network":
                print(f"[+] Services: {observation.data}")
            
            elif observation.category == "web_surface":
                data = observation.data
                print(f"[+] URL: {data['url']}")
                print(f"[+] Status: {data['status']}")
                print(f"[+] Content Type: {data['content_type']}")
                print(f"[+] Content Length: {data['content_length']}")
                print(f"[+] Location: {data['location']}")
                print(f"[+] Allow: {data['allow']}")
                print(f"[+] Error: {data.get('error', '')}")
                

    save_path = (
        f"data/assessments/"
        f"{assessment.assessment_id}/results.json"
    )

    save_assessment(assessment, save_path)

    print(f"[+] Results saved to: {save_path}")
