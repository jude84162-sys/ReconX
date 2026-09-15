"""Fetch public Inflact profile data.

⚠️ LEGAL: Only use against targets you own or have written authorization.
Instagram scraping may violate Instagram ToS. Users are responsible for
compliance with CFAA and GDPR.
"""

import json
import time
from urllib.parse import quote
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup


class InflactModule:
    def run(self, username: str, timeout: int = 15) -> dict:
        robots = RobotFileParser()
        robots.set_url("https://inflact.com/robots.txt")
        robots.read()
        profile_url = f"https://inflact.com/instagram-viewer/profile/{quote(username)}/"
        if not robots.can_fetch("ReconX", profile_url):
            return {"username": username, "profile_data": {}, "source": "inflact", "error": "Blocked by robots.txt"}
        time.sleep(5)
        response = requests.get(profile_url, timeout=timeout, headers={"User-Agent": "ReconX/1.3"})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        profile = {
            "full_name": self._text(soup, "full_name"),
            "bio": self._text(soup, "bio"),
            "followers": self._number(soup, "followers"),
            "following": self._number(soup, "following"),
            "posts_count": self._number(soup, "posts_count"),
            "is_private": self._boolean(soup, "is_private"),
            "is_verified": self._boolean(soup, "is_verified"),
        }
        for script in soup.find_all("script", type="application/ld+json"):
            try:
                data = json.loads(script.string or "")
                if isinstance(data, dict):
                    profile["full_name"] = profile["full_name"] or data.get("name")
                    profile["bio"] = profile["bio"] or data.get("description")
            except json.JSONDecodeError:
                continue
        return {"username": username, "profile_data": profile, "source": "inflact"}

    @staticmethod
    def _text(soup, key):
        node = soup.select_one(f"[data-{key}], .{key}, #{key}")
        return node.get_text(" ", strip=True) if node else None

    @classmethod
    def _number(cls, soup, key):
        value = cls._text(soup, key)
        try:
            return int(value.replace(",", "")) if value else None
        except ValueError:
            return value

    @classmethod
    def _boolean(cls, soup, key):
        value = cls._text(soup, key)
        return value.lower() in {"true", "yes", "1"} if value else False
