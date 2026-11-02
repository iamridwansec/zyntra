import urllib.request


def identify_technologies(url):
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Zyntra/0.1.0"}
        )

        with urllib.request.urlopen(
            request,
            timeout=5
        ) as response:

            headers = dict(response.headers)

            return {
                "url": url,
                "status": response.status,
                "server": headers.get("Server", ""),
                "powered_by": headers.get("X-Powered-By", "")
            }

    except Exception as error:
        return {
            "url": url,
            "status": None,
            "server": "",
            "powered_by": "",
            "error": str(error)
        }
