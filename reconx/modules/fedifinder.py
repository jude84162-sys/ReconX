"""Find Fediverse accounts exposed by domain rel="me" links or Mastodon search."""

from urllib.parse import urlparse

from bs4 import BeautifulSoup

from reconx.utils.http import safe_request


class FedifinderModule:
    def run(self, target: str, timeout: int = 10) -> dict:
        accounts = []
        if target.startswith("@") and target.count("@") >= 2:
            username, instance = target[1:].split("@", 1)
            response = safe_request(
                f"https://{instance}/api/v2/search",
                timeout=timeout,
                params={"q": username, "type": "accounts", "resolve": "true"},
            )
            if response is not None and response.ok:
                for account in response.json().get("accounts", []):
                    accounts.append(self._account(account, instance, "mastodon-search"))
        else:
            domain = target if "://" in target else f"https://{target}"
            response = safe_request(domain, timeout=timeout)
            if response is not None and response.ok:
                soup = BeautifulSoup(response.text, "html.parser")
                for link in soup.find_all("a", rel=lambda value: value and "me" in value):
                    url = link.get("href")
                    if url and url.startswith(("http://", "https://")):
                        parsed = urlparse(url)
                        accounts.append(
                            {
                                "instance": parsed.netloc,
                                "username": parsed.path.strip("/").split("/")[-1],
                                "url": url,
                                "source": "rel-me",
                            }
                        )
        return {"target": target, "accounts": accounts}

    @staticmethod
    def _account(account, fallback_instance, source):
        url = account.get("url", "")
        instance = urlparse(url).netloc or fallback_instance
        username = account.get("acct") or account.get("username", "")
        return {"instance": instance, "username": username, "url": url, "source": source}
