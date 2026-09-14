"""Search multiple Mastodon instances for a username."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from reconx.utils.http import safe_request


DEFAULT_INSTANCES = ("mastodon.social", "mastodon.online", "fosstodon.org", "hachyderm.io")


class FediverseOsintModule:
    def run(self, username: str, timeout: int = 10) -> dict:
        query = username.lstrip("@").split("@", 1)[0]
        accounts = {}

        def search(instance):
            response = safe_request(
                f"https://{instance}/api/v2/search",
                timeout=timeout,
                params={"q": query, "type": "accounts", "resolve": "true"},
            )
            if response is None or not response.ok:
                return instance, []
            return instance, response.json().get("accounts", [])

        with ThreadPoolExecutor(max_workers=len(DEFAULT_INSTANCES)) as executor:
            futures = [executor.submit(search, instance) for instance in DEFAULT_INSTANCES]
            for future in as_completed(futures):
                instance, found = future.result()
                for account in found:
                    url = account.get("url", "")
                    handle = account.get("acct") or account.get("username", "")
                    key = handle.lower() or url.lower()
                    accounts[key] = {
                        "instance": urlparse(url).netloc or instance,
                        "username": handle,
                        "url": url,
                        "source": "mastodon-search",
                    }
        return {
            "username": username,
            "instances_checked": list(DEFAULT_INSTANCES),
            "accounts": list(accounts.values()),
        }
