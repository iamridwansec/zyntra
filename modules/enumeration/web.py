import urllib.request
from urllib.error import HTTPError, URLError
import re
from urllib.parse import urljoin
from urllib.parse import urlparse

def crawl_web_surface(start_url, max_pages=10):
    visited = set()
    pages = []
    queue = [start_url]

    while queue and len(visited) < max_pages:
        current_url = queue.pop(0)

        if current_url in visited:
            continue

        if not is_same_host(start_url, current_url):
            continue

        visited.add(current_url)

        result = discover_web_surface(current_url)
        if result["status"] is None:
            continue

        pages.append(result)

        links = extract_links(result["html"])
        urls = normalize_urls(result["url"], links)

        for url in urls:
            if url not in visited and is_same_host(start_url, url):
                queue.append(url)

    return pages

def is_same_host(base_url, discovered_url):
    base = urlparse(base_url)
    discovered = urlparse(discovered_url)

    return (
        base.scheme == discovered.scheme
        and base.netloc == discovered.netloc
    )


def discover_web_surface(base_url):
    request = urllib.request.Request(
        base_url,
        headers={"User-Agent": "Zyntra/0.1.0"}
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            content_type = response.headers.get("Content-Type", "")

            if "html" in content_type.lower():
                html = response.read().decode("utf-8", errors="ignore")
            else:
                html = ""
            return {
                "url": response.url,
                "status": response.status,
                "content_type": content_type,
                "html": html
            }

    except HTTPError as error:
        return {
            "url": base_url,
            "status": error.code,
            "content_type": error.headers.get("Content-Type", ""),
            "html": ""
        }

    except URLError as error:
        return {
            "url": base_url,
            "status": None,
            "content_type": "",
            "html": "",
            "error": str(error.reason),
            "result_type": (
                "timeout"
                if isinstance(error.reason, TimeoutError)
                else "error"
            )
        }

    except TimeoutError as error:
        return {
            "url": base_url,
            "status": None,
            "content_type": "",
            "html": "",
            "error": str(error)
        }

def extract_javascript(html):
    pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    return re.findall(pattern, html, re.IGNORECASE)

def discover_page_javascript(pages):
    javascript_urls = []

    for page in pages:
        scripts = extract_javascript(page["html"])
        urls = normalize_urls(page["url"], scripts)
        javascript_urls.extend(urls)

    return list(dict.fromkeys(javascript_urls))

def extract_links(html):
    pattern = r'<a[^>]+href=["\']([^"\']+)["\']'
    return re.findall(pattern, html, re.IGNORECASE)

def remove_url_fragment(url):
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()

def is_valid_web_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)

def normalize_urls(base_url, urls):
    normalized = [remove_url_fragment(urljoin(base_url, url)) for url in urls]
    return list(dict.fromkeys(url for url in normalized if is_valid_web_url(url)))
