import urllib.request
from urllib.error import HTTPError, URLError


def classify_response(status_code):
    if 200 <= status_code < 300:
        return "successful_response"

    if 300 <= status_code < 400:
        return "redirect_response"

    if status_code == 401:
        return "authentication_challenge"

    if status_code == 403:
        return "access_forbidden"

    return "http_error"


def check_resource_access(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Zyntra/0.1.0"},
        method="GET"
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status_code = response.status
            final_url = response.url

    except HTTPError as error:
        status_code = error.code
        final_url = error.url
        error.close()


    except URLError as error:
        return {
            "requested_url": url,
            "status_code": None,
            "final_url": None,
            "redirected": False,
            "access_signal": "connection_error",
            "error": str(error.reason)
        }

    return {
        "requested_url": url,
        "status_code": status_code,
        "final_url": final_url,
        "redirected": final_url != url,
        "access_signal": classify_response(status_code)
    }
