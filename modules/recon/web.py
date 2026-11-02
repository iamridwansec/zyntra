import urllib.request


def discover_web_surface(url):
    try:
        request = urllib.request.Request(
            url,
            method="GET",
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
                "content_type": headers.get("Content-Type", ""),
                "content_length": headers.get("Content-Length", ""),
                "location": headers.get("Location", ""),
                "allow": headers.get("Allow", "")
            }

    except Exception as error:
        return {
            "url": url,
            "status": None,
            "content_type": "",
            "content_length": "",
            "location": "",
            "allow": "",
            "error": str(error)
        }
