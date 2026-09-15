"""Public web-page information extraction.

WebSift fetches one explicitly supplied HTTP(S) page and extracts visible
contact data and links. It does not crawl, authenticate, bypass controls, or
submit data to third-party services.
"""

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from reconx.core.engine import Module
from reconx.utils.http import safe_request
from reconx.utils.output import print_error, print_info, print_success


EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d().\s-]{6,}\d)(?!\w)")
SOCIAL_DOMAINS = (
    "facebook.com",
    "github.com",
    "instagram.com",
    "linkedin.com",
    "mastodon.social",
    "reddit.com",
    "t.me",
    "tiktok.com",
    "x.com",
    "twitter.com",
    "youtube.com",
)


def _unique(values):
    return list(dict.fromkeys(value for value in values if value))


def _normalise_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("A URL is required.")
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("WebSift accepts only absolute http:// or https:// URLs.")
    return target


def _is_social_url(url: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower()
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in SOCIAL_DOMAINS)


class WebSiftModule(Module):
    """Extract publicly visible contact data and links from one web page."""

    name = "websift"
    description = "Extract emails, phone numbers, social links, URLs, and metadata from a public web page"

    def run(self, target):
        self.target = _normalise_target(target)
        self.results = []
        print_info(f"Fetching public page: {self.target}")
        response = safe_request(self.target, timeout=self.timeout, verify_ssl=True)
        if response is None:
            print_error("Could not fetch the page.")
            return {"url": self.target, "error": "Request failed", "emails": [], "phones": [], "social_links": [], "urls": []}
        if not response.ok:
            print_error(f"Page returned HTTP {response.status_code}.")
            return {"url": self.target, "error": f"HTTP {response.status_code}", "emails": [], "phones": [], "social_links": [], "urls": []}

        soup = BeautifulSoup(response.text, "html.parser")
        for element in soup(["script", "style", "noscript"]):
            element.decompose()
        text = soup.get_text(" ", strip=True)
        links = [urljoin(response.url or self.target, anchor.get("href", "").strip()) for anchor in soup.find_all("a")]
        urls = _unique(
            url for url in links
            if urlparse(url).scheme in {"http", "https"} and urlparse(url).netloc
        )
        emails = _unique(EMAIL_RE.findall(text) + [
            link[7:] for link in links if link.lower().startswith("mailto:")
        ])
        phones = _unique(PHONE_RE.findall(text) + [
            link[4:] for link in links if link.lower().startswith("tel:")
        ])
        social_links = _unique([url for url in urls if _is_social_url(url)])
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        description_tag = soup.find("meta", attrs={"name": re.compile("^description$", re.IGNORECASE)})
        description = description_tag.get("content", "").strip() if description_tag else ""

        result = {
            "url": response.url or self.target,
            "status_code": response.status_code,
            "title": title,
            "description": description,
            "emails": emails,
            "phones": phones,
            "social_links": social_links,
            "urls": urls,
        }
        self.add_result("WebSift", result["url"], "found", result)
        print_success(
            f"Extracted {len(emails)} email(s), {len(phones)} phone number(s), "
            f"{len(social_links)} social link(s), and {len(urls)} URL(s)."
        )
        return result
