import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from html.parser import HTMLParser


class ReflectionContextParser(HTMLParser):
    def __init__(self, marker):
        super().__init__()
        self.marker = marker
        self.contexts = []
        self.inside_script = False

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value and self.marker in value:
                self.contexts.append("html_attribute")

        if tag.lower() == "script":
            self.inside_script = True

    def handle_endtag(self, tag):
        if tag.lower() == "script":
            self.inside_script = False

    def handle_data(self, data):
        if self.marker in data:
            if self.inside_script:
                self.contexts.append("script")
            else:
                self.contexts.append("html_text")

    def handle_comment(self, data):
        if self.marker in data:
            self.contexts.append("html_comment")

def inspect_input_reflection(url, parameter):
    marker = "ZYNTRA_REFLECTION_TEST"

    parsed_url = urlsplit(url)

    if parsed_url.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed_url.netloc or not parameter:
        raise ValueError("A valid URL and parameter are required.")

    query_parameters = parse_qsl(
        parsed_url.query,
        keep_blank_values=True
    )

    query_parameters = [
        (key, value)
        for key, value in query_parameters
        if key != parameter
    ]

    query_parameters.append((parameter, marker))

    test_url = urlunsplit((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        urlencode(query_parameters),
        ""
    ))

    request = urllib.request.Request(
        test_url,
        headers={"User-Agent": "Zyntra/0.1.0"},
        method="GET"
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status_code = response.status
            final_url = response.url
            content_type = response.headers.get("Content-Type", "")
            body = response.read(65536)

    except HTTPError as error:
        status_code = error.code
        final_url = error.url
        content_type = error.headers.get("Content-Type", "")
        body = error.read(65536)

    except URLError as error:
        return {
            "status": "connection_error",
            "parameter": parameter,
            "error": str(error.reason)
        }

    response_text = body.decode("utf-8", errors="replace")

    reflection_count = response_text.count(marker)

    parser = ReflectionContextParser(marker)
    parser.feed(response_text)

    reflection_contexts = sorted(set(parser.contexts))

    return {
        "status": "completed",
        "parameter": parameter,
        "http_status": status_code,
        "content_type": content_type,
        "marker_reflected": reflection_count > 0,
        "reflection_count": reflection_count,
        "reflection_contexts": reflection_contexts,
        "final_url": urlunsplit((
            urlsplit(final_url).scheme,
            urlsplit(final_url).netloc,
            urlsplit(final_url).path,
            "",
            ""
        )),
        "response_bytes_sampled": len(body)
    }
