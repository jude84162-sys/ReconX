# modules/github_recon.py
"""ReconX - GitHub Recon (user, repos, secrets, orgs)."""

import re
import ssl
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger("ReconX.github")


def _fetch_json(url, timeout=15):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ReconX/1.0",
                "Accept": "application/vnd.github.v3+json",
            }
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"_error": "not_found"}
        if e.code == 403:
            return {"_error": "rate_limited"}
        return {"_error": f"http_{e.code}"}
    except Exception as e:
        return {"_error": str(e)}


def run_github_recon(username):
    """Gather info about a GitHub user."""
    result = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "profile": {},
        "repos": [],
        "organizations": [],
        "emails_found": set(),
        "suspicious_repos": [],
        "summary": {},
        "error": None,
    }

    # 1. Profile
    profile = _fetch_json(f"https://api.github.com/users/{username}")
    if "_error" in profile:
        result["error"] = profile["_error"]
        return result

    result["profile"] = {
        "login": profile.get("login"),
        "name": profile.get("name"),
        "bio": profile.get("bio"),
        "company": profile.get("company"),
        "location": profile.get("location"),
        "email": profile.get("email"),
        "blog": profile.get("blog"),
        "twitter": profile.get("twitter_username"),
        "public_repos": profile.get("public_repos"),
        "public_gists": profile.get("public_gists"),
        "followers": profile.get("followers"),
        "following": profile.get("following"),
        "created_at": profile.get("created_at"),
        "updated_at": profile.get("updated_at"),
        "hireable": profile.get("hireable"),
        "avatar_url": profile.get("avatar_url"),
        "html_url": profile.get("html_url"),
    }

    if profile.get("email"):
        result["emails_found"].add(profile["email"])

    # 2. Repos
    repos = _fetch_json(f"https://api.github.com/users/{username}/repos?per_page=100&sort=updated")
    if isinstance(repos, list):
        for r in repos:
            repo_info = {
                "name": r.get("name"),
                "description": r.get("description"),
                "language": r.get("language"),
                "stars": r.get("stargazers_count"),
                "forks": r.get("forks_count"),
                "size": r.get("size"),
                "created": r.get("created_at"),
                "updated": r.get("updated_at"),
                "url": r.get("html_url"),
                "fork": r.get("fork"),
            }
            result["repos"].append(repo_info)

            # Suspicious repo keywords
            name = (r.get("name") or "").lower()
            desc = (r.get("description") or "").lower()
            suspicious = ["hack", "exploit", "malware", "crack", "keygen",
                          "botnet", "phish", "steal", "wallet-steal", "backdoor"]
            for kw in suspicious:
                if kw in name or kw in desc:
                    result["suspicious_repos"].append(repo_info)
                    break

    # 3. Organizations
    orgs = _fetch_json(f"https://api.github.com/users/{username}/orgs")
    if isinstance(orgs, list):
        result["organizations"] = [o.get("login") for o in orgs]

    # 4. Gists
    gists = _fetch_json(f"https://api.github.com/users/{username}/gists?per_page=100")
    gist_count = len(gists) if isinstance(gists, list) else 0

    # Summary
    result["emails_found"] = sorted(result["emails_found"])

    result["summary"] = {
        "name": profile.get("name"),
        "public_repos": profile.get("public_repos"),
        "followers": profile.get("followers"),
        "following": profile.get("following"),
        "gists": gist_count,
        "orgs_count": len(result["organizations"]),
        "suspicious_repos": len(result["suspicious_repos"]),
        "emails": len(result["emails_found"]),
        "account_age_days": _account_age(profile.get("created_at")),
    }

    return result


def _account_age(created_at):
    if not created_at:
        return None
    try:
        created = datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
        return (datetime.now() - created).days
    except Exception:
        return None


def print_github_report(result):
    print("\n" + "=" * 70)
    print("  GitHub Recon - ReconX")
    print("=" * 70)

    if result.get("error"):
        print(f"\n[!] {result['error']}")
        return

    p = result["profile"]
    print(f"\n[*] Username:    {result['username']}")
    print(f"[*] Name:        {p.get('name') or '?'}")
    print(f"[*] Bio:         {p.get('bio') or '?'}")
    print(f"[*] Company:     {p.get('company') or '?'}")
    print(f"[*] Location:    {p.get('location') or '?'}")
    print(f"[*] Email:       {p.get('email') or '?'}")
    print(f"[*] Blog:        {p.get('blog') or '?'}")
    print(f"[*] Twitter:     {p.get('twitter') or '?'}")
    print(f"[*] Created:     {p.get('created_at')} ({result['summary'].get('account_age_days')} days ago)")

    s = result["summary"]
    print(f"\n[+] Activity:")
    print(f"    Public repos: {s.get('public_repos', 0)}")
    print(f"    Followers:    {s.get('followers', 0)}")
    print(f"    Following:    {s.get('following', 0)}")
    print(f"    Gists:        {s.get('gists', 0)}")

    if result.get("organizations"):
        print(f"\n[+] Organizations ({len(result['organizations'])}):")
        for o in result["organizations"][:10]:
            print(f"    - {o}")

    if result.get("suspicious_repos"):
        print(f"\n[!] Suspicious repos ({len(result['suspicious_repos'])}):")
        for r in result["suspicious_repos"][:10]:
            print(f"    [!] {r['name']}")
            print(f"        {r['url']}")

    if result.get("emails_found"):
        print(f"\n[+] Emails found:")
        for e in result["emails_found"][:10]:
            print(f"    - {e}")

    # Top repos
    repos = result.get("repos", [])
    if repos:
        top = sorted(repos, key=lambda x: x.get("stars", 0), reverse=True)[:10]
        print(f"\n[+] Top repos by stars:")
        for r in top:
            print(f"    ⭐ {r['stars']:<5} {r['name']:<30} {r['language'] or '?'}")

    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    username = sys.argv[1] if len(sys.argv) > 1 else "torvalds"
    print(f"[*] GitHub Recon: {username}")
    result = run_github_recon(username)
    print_github_report(result)
