from datetime import datetime

from modules.recon.target import Target
from core.assessment import Assessment
from core.observation import Observation
from .api import discover_api
from .javascript import (
    fetch_javascript,
    extract_endpoints,
    detect_api_keys
)
from .web import (
    crawl_web_surface,
    discover_page_javascript
)
from core.ids import generate_assessment_id
from core.serializer import save_assessment
from .vhosts import discover_vhosts



def run(target):
    target = Target(target)
 
    assessment = Assessment(
        assessment_id=generate_assessment_id(),
        target=target,
        started_at=datetime.now()

    )

    print(f"[+] Assessment ID: {assessment.assessment_id}")
    print(f"[+] Enumeration target: {target.value}")
    print(f"[+] Target type: {target.target_type}")

    if target.target_type == "domain":
        base_url = f"https://{target.hostname}"
    elif target.target_type == "url":
        base_url = target.value
    elif target.target_type == "ip":
        base_url = f"http://{target.hostname}"
    else:
        print("[!] Unsupported target type.")
        return
    results = discover_api(base_url)

    counts = {}

    for result in results:
        result_type = result["result_type"]
        counts[result_type] = counts.get(result_type, 0) + 1

    print(f"[+] API paths tested: {len(results)}")
    print(f"[+] Candidates: {counts.get('candidate', 0)}")
    print(f"[+] Protected: {counts.get('protected', 0)}")
    print(f"[+] Not confirmed: {counts.get('not_confirmed', 0)}")
    print(f"[+] Not found: {counts.get('not_found', 0)}")
    print(f"[+] Unknown: {counts.get('unknown', 0)}")


    for result in results:
        observation = Observation(
            category="api",
            source="api_discovery",
            data=result,
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)
        print(f"[+] URL: {result['url']}")
        print(f"[+] Status: {result['status']}")
        print(f"[+] Content Type: {result['content_type']}")
        print(f"[+] Result Type: {result['result_type']}")

    pages = crawl_web_surface(base_url)
    print(f"[+] Web pages discovered: {len(pages)}")

    print("[+] Starting virtual host discovery...")

    vhost_results = discover_vhosts(base_url)

    print(f"[+] VHost status: {vhost_results['status']}")

    if vhost_results["status"] == "completed":

        control_observation = Observation(
            category="vhost_control",
            source="vhost_discovery",
            data={
                "hostname": vhost_results["control_hostname"],
                "status_code": vhost_results["control_baseline"]["status_code"],
                "content_length": vhost_results["control_baseline"]["content_length"],
                "body_hash": vhost_results["control_baseline"]["body_hash"],
                "location": vhost_results["control_baseline"]["location"]
            },
            timestamp=datetime.now()
        )

        assessment.add_observation(control_observation)

        summary_observation = Observation(
            category="vhost_summary",
            source="vhost_discovery",
            data={
                "target": vhost_results["target"],
                "ip": vhost_results["ip"],
                "tested": vhost_results["tested"],
                "classification_counts": vhost_results["classification_counts"],
                "baseline": vhost_results["baseline"]
            },
            timestamp=datetime.now()
        )

        assessment.add_observation(summary_observation)

        print(f"[+] VHosts tested: {vhost_results['tested']}")
        print(
            f"[+] VHost classifications: "
            f"{vhost_results['classification_counts']}"
        )
        print(
            f"[+] Potential VHosts: "
            f"{len(vhost_results['potential_vhosts'])}"
        )

        for vhost in vhost_results["potential_vhosts"]:
            observation = Observation(
                category="virtual_host",
                source="vhost_discovery",
                data=vhost,
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

            print("[+] Virtual Host Discovery")
            print(f"    Host: {vhost['hostname']}")
            print(f"    Classification: {vhost['classification']}")
            print(f"    HTTP Status: {vhost['status_code']}")
            print(f"    Response Size: {vhost['content_length']} bytes")

            if vhost["location"]:
                print(f"    Redirect: {vhost['location']}")
            else:
                print("    Redirect: None")

    else:
        print(f"[!] {vhost_results['message']}")

    for page in pages:
        observation = Observation(
            category="web_page",
            source="web_surface_discovery",
            data={
                "url": page["url"],
                "status": page["status"],
                "content_type": page["content_type"]
            },
            timestamp=datetime.now()
        )

        assessment.add_observation(observation)
        print(f"[+] Web page: {page['url']} [{page['status']}]")

    javascript_urls = discover_page_javascript(pages)
    print(f"[+] JavaScript files discovered: {len(javascript_urls)}")

    for javascript_url in javascript_urls:
        print(f"[+] JavaScript: {javascript_url}")

        try:
            javascript = fetch_javascript(javascript_url)
        except (OSError, TimeoutError) as error:
            print(f"[!] Could not fetch JavaScript: {error}")
            continue

        endpoints = extract_endpoints(javascript)

        for endpoint in endpoints:
            observation = Observation(
                category="js_endpoint",
                source="javascript_analysis",
                data={
                    "javascript_url": javascript_url,
                    "endpoint": endpoint
                },
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

        findings = detect_api_keys(javascript)

        for finding in findings:
            observation = Observation(
                category="potential_secret",
                source="javascript_analysis",
                data={
                    "javascript_url": javascript_url,
                    "finding": finding
                },
                timestamp=datetime.now()
            )

            assessment.add_observation(observation)

        print(f"[+] Endpoints extracted: {len(endpoints)}")
        print(f"[+] Potential secrets: {len(findings)}")


    print(f"[+] Assessment observations: {len(assessment.observations)}")

    assessment.status = "completed"

    save_path = (
        f"data/assessments/"
        f"{assessment.assessment_id}/results.json"
    )

    save_assessment(assessment, save_path)

    print(f"[+] Results saved to: {save_path}")
