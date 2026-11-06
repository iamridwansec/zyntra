import urllib.request
from urllib.error import HTTPError, URLError


COMMON_API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger.json",
    "/openapi.json",
    "/api-docs",
    "/v3/api-docs",
    "/graphql",
    "/page"
]


def discover_api(base_url):
    base_url = base_url.rstrip("/")
    results = []

    for path in COMMON_API_PATHS:
        url = f"{base_url}{path}"

        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "Zyntra/0.1.0"}
            )

            with urllib.request.urlopen(request, timeout=5) as response:
                content_type = response.headers.get("Content-Type", "")

                if "json" in content_type.lower():
                    result_type = "candidate"
                elif "html" in content_type.lower():
                    result_type = "not_confirmed"
                else:
                    result_type = "unknown"

                results.append({
                    "url": url,
                    "status": response.status,
                    "content_type": content_type,
                    "result_type": result_type
                })

        except HTTPError as error:
            if error.code in [401, 403]:
                result_type = "protected"
            elif error.code == 404:
                result_type = "not_found"
            else:
                result_type = "unknown"

            results.append({
                "url": url,
                "status": error.code,
                "content_type": error.headers.get("Content-Type", ""),
                "result_type": result_type
            })

        except TimeoutError:
            results.append({
                "url": url,
                "status": None,
                "content_type": "",
                "result_type": "timeout"
            })

        except URLError as error:
            if isinstance(error.reason, TimeoutError):
                result_type = "timeout"
            else:
                result_type = "error"

            results.append({
                "url": url,
                "status": None,
                "content_type": "",
                "result_type": result_type,
                "error": str(error.reason)
            })
    return results
