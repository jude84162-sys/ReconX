"""Query Fediverse instance metadata from Fediverse Observer."""

from urllib.parse import quote

from reconx.utils.http import safe_request


class FediverseObserverModule:
    def run(self, instance: str, timeout: int = 10) -> dict:
        response = safe_request(
            f"https://api.fediverse.observer/api/instance/{quote(instance, safe='')}",
            timeout=timeout,
        )
        result = {"instance": instance, "software": None, "version": None, "users": None, "posts": None, "uptime": None}
        if response is not None and response.ok:
            data = response.json()
            result.update(
                {
                    "software": data.get("software"),
                    "version": data.get("version"),
                    "users": data.get("users", data.get("users_total")),
                    "posts": data.get("posts", data.get("posts_total")),
                    "uptime": data.get("uptime"),
                }
            )
        return result
