"""
ReconX Framework - Email Breach & Security Module
Author: Principal Cybersecurity Software Engineer & OSINT Developer
Description: Async OSINT breach analysis, k-Anonymity password checking, automated risk score computation, 
             local session mitigation, and Telegram incident alert dispatching.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote

import aiohttp
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

# Initialize Logger & Rich Console
logger = logging.getLogger("reconx.email")
console = Console()

# Incident Response Password Reset URLs database
INCIDENT_RESPONSE_URLS: Dict[str, str] = {
    "google": "https://myaccount.google.com/signinoptions/password",
    "microsoft": "https://account.live.com/password/reset",
    "github": "https://github.com/password_reset",
    "twitter": "https://twitter.com/account/begin_password_reset",
    "x": "https://x.com/account/begin_password_reset",
    "facebook": "https://www.facebook.com/recover/initiate",
    "linkedin": "https://www.linkedin.com/uas/request-password-reset",
    "discord": "https://discord.com/login",
    "dropbox": "https://www.dropbox.com/forgot",
    "adobe": "https://account.adobe.com/security",
    "canva": "https://www.canva.com/forgot-password/",
    "spotify": "https://www.spotify.com/password-reset/",
}


@dataclass
class BreachDetail:
    title: str
    domain: str
    breach_date: str
    data_classes: List[str]
    is_verified: bool
    is_fabricated: bool
    is_sensitive: bool
    description: str


@dataclass
class PasswordBreachResult:
    is_pwned: bool
    pwned_count: int
    sha1_prefix: str


@dataclass
class EmailReputation:
    reputation: str  # high, medium, low, suspicious
    suspicious: bool
    references: int
    blacklisted: bool
    malicious_activity: bool
    last_seen: Optional[str] = None


@dataclass
class RiskAssessment:
    score: int  # 0 to 100
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_factors: List[str]


@dataclass
class SecurityReport:
    target_email: str
    timestamp: str
    breaches: List[BreachDetail] = field(default_factory=list)
    password_check: Optional[PasswordBreachResult] = None
    email_rep: Optional[EmailReputation] = None
    risk_assessment: RiskAssessment = field(
        default_factory=lambda: RiskAssessment(0, "LOW", [])
    )
    incident_response_urls: List[str] = field(default_factory=list)
    mitigation_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EmailBreachModule:
    """Async Email Breach Intelligence and Local Security Mitigation Module."""

    HIBP_API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount"
    PWNED_PASS_URL = "https://api.pwnedpasswords.com/range"
    EMAILREP_API_URL = "https://emailrep.io"
    BREACHDIRECTORY_API_URL = "https://breachdirectory.p.rapidapi.com"

    def __init__(
        self,
        session: Optional[aiohttp.ClientSession] = None,
        max_retries: int = 3,
        backoff_factor: float = 2.0,
    ):
        self._external_session = session is not None
        self.session = session
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(
                headers={"User-Agent": "ReconX-OSINT-Framework/2.0"}
            )
        return self.session

    async def close(self) -> None:
        """Close HTTP Session if created internally."""
        if not self._external_session and self.session and not self.session.closed:
            await self.session.close()

    @staticmethod
    def _redact_url(url: str) -> str:
        """Mask credentials carried inside a URL (e.g. Telegram bot tokens) before logging."""
        # Telegram embeds the bot token in the path: /bot<token>/sendMessage
        redacted = re.sub(r"/bot[^/]+", "/bot<redacted>", str(url))
        # Drop any credential-bearing query parameters.
        return re.sub(
            r"([?&](?:key|api_key|token|password|hibp-api-key)=)[^&\s]+",
            r"\1<redacted>",
            redacted,
        )

    @staticmethod
    def _retry_delay(
        retry_after: Optional[str], attempt: int, backoff_factor: float
    ) -> float:
        """Parse Retry-After (delta-seconds or HTTP-date), else use exponential backoff."""
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                # RFC 7231 also permits an HTTP-date here, which float() rejects.
                pass
        return float(backoff_factor**attempt)

    async def _request_with_backoff(
        self, method: str, url: str, **kwargs
    ) -> Optional[aiohttp.ClientResponse]:
        """Execute HTTP request with 429 exponential backoff rate-limit handling."""
        session = await self._get_session()
        for attempt in range(1, self.max_retries + 1):
            try:
                response = await session.request(method, url, **kwargs)
                if response.status == 429:
                    delay = self._retry_delay(
                        response.headers.get("Retry-After"),
                        attempt,
                        self.backoff_factor,
                    )
                    # Release the body so the pooled connection is returned.
                    response.release()
                    logger.warning(
                        f"[429 Rate Limit] Backing off for {delay:.2f}s on "
                        f"{self._redact_url(url)}"
                    )
                    await asyncio.sleep(delay)
                    continue
                return response
            except aiohttp.ClientError as exc:
                logger.error(
                    f"HTTP request error on {self._redact_url(url)} "
                    f"(Attempt {attempt}): {exc}"
                )
                if attempt == self.max_retries:
                    raise
                await asyncio.sleep(self.backoff_factor**attempt)
        return None

    # -------------------------------------------------------------------------
    # 1. Breach Intelligence API Clients
    # -------------------------------------------------------------------------

    async def check_hibp_breaches(
        self, email: str, api_key: Optional[str] = None
    ) -> List[BreachDetail]:
        """Query HaveIBeenPwned API v3 for breached account status."""
        headers = {"User-Agent": "ReconX-OSINT-Framework"}
        if api_key:
            headers["hibp-api-key"] = api_key
        else:
            logger.warning("HIBP API Key not provided. Skipping HIBP query.")
            return []

        # Percent-encode the target: a raw address may contain '?', '#' or '/' and
        # would otherwise be able to rewrite the request target.
        url = f"{self.HIBP_API_URL}/{quote(email, safe='')}?truncateResponse=false"
        resp = await self._request_with_backoff("GET", url, headers=headers)

        if not resp:
            return []

        if resp.status == 200:
            data = await resp.json()
            results = []
            for item in data:
                results.append(
                    BreachDetail(
                        title=item.get("Title", "Unknown"),
                        domain=item.get("Domain", ""),
                        breach_date=item.get("BreachDate", "Unknown"),
                        data_classes=item.get("DataClasses", []),
                        is_verified=item.get("IsVerified", False),
                        is_fabricated=item.get("IsFabricated", False),
                        is_sensitive=item.get("IsSensitive", False),
                        description=re.sub("<[^<]+?>", "", item.get("Description", "")),
                    )
                )
            return results
        elif resp.status == 404:
            logger.info(f"No HIBP breaches found for {email}.")
            return []
        else:
            logger.error(f"HIBP API failed with status HTTP {resp.status}")
            return []

    async def check_pwned_password(self, password: str) -> PasswordBreachResult:
        """Check password strength using k-Anonymity SHA-1 model."""
        # SHA-1 is mandated by the Pwned Passwords k-Anonymity protocol and is
        # NOT used as a security primitive here, hence usedforsecurity=False.
        sha1_hash = hashlib.sha1(
            password.encode("utf-8"), usedforsecurity=False
        ).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        url = f"{self.PWNED_PASS_URL}/{prefix}"
        resp = await self._request_with_backoff("GET", url)

        if resp and resp.status == 200:
            text_data = await resp.text()
            for line in text_data.splitlines():
                if ":" in line:
                    line_suffix, count_str = line.split(":")
                    if line_suffix.upper() == suffix:
                        return PasswordBreachResult(
                            is_pwned=True,
                            pwned_count=int(count_str.strip()),
                            sha1_prefix=prefix,
                        )
        return PasswordBreachResult(
            is_pwned=False, pwned_count=0, sha1_prefix=prefix
        )

    async def check_emailrep(
        self, email: str, api_key: Optional[str] = None
    ) -> Optional[EmailReputation]:
        """Fetch Email Reputation & Threat Risk telemetry from EmailRep.io."""
        headers = {"User-Agent": "ReconX-OSINT-Framework"}
        if api_key:
            headers["Key"] = api_key

        url = f"{self.EMAILREP_API_URL}/{quote(email, safe='')}"
        resp = await self._request_with_backoff("GET", url, headers=headers)

        if resp and resp.status == 200:
            data = await resp.json()
            details = data.get("details", {})
            return EmailReputation(
                reputation=data.get("reputation", "unknown"),
                suspicious=data.get("suspicious", False),
                references=data.get("references", 0),
                blacklisted=details.get("blacklisted", False),
                malicious_activity=details.get("malicious_activity", False),
                last_seen=details.get("last_seen"),
            )
        return None

    # -------------------------------------------------------------------------
    # 2. Automated Risk Assessment Engine
    # -------------------------------------------------------------------------

    def compute_risk_score(
        self,
        breaches: List[BreachDetail],
        pass_result: Optional[PasswordBreachResult] = None,
        email_rep: Optional[EmailReputation] = None,
    ) -> RiskAssessment:
        """Compute an automated Risk Score (0–100) based on leaked vector data."""
        score = 0
        risk_factors: List[str] = []

        plaintext_found = False
        hash_found = False
        pii_found = False

        for breach in breaches:
            data_classes_lower = [dc.lower() for dc in breach.data_classes]

            if any(
                p in data_classes_lower
                for p in ["passwords", "plaintext passwords", "unencrypted passwords"]
            ):
                plaintext_found = True
            elif any(
                h in data_classes_lower
                for h in ["password hashes", "hashes", "encrypted passwords"]
            ):
                hash_found = True

            if any(
                pii in data_classes_lower
                for pii in [
                    "ip addresses",
                    "physical addresses",
                    "phone numbers",
                    "social security numbers",
                    "credit cards",
                ]
            ):
                pii_found = True

        if plaintext_found:
            score += 50
            risk_factors.append("Plaintext password exposure detected (+50)")

        if hash_found:
            score += 30
            risk_factors.append("Hashed password exposure detected (+30)")

        if pii_found:
            score += 20
            risk_factors.append("Sensitive PII / IP address exposure detected (+20)")

        if pass_result and pass_result.is_pwned:
            score += 25
            risk_factors.append(
                f"Target password found in pwned database ({pass_result.pwned_count} times) (+25)"
            )

        if email_rep:
            if email_rep.suspicious or email_rep.blacklisted:
                score += 15
                risk_factors.append("Email flagged as suspicious/blacklisted (+15)")
            if email_rep.malicious_activity:
                score += 15
                risk_factors.append("Associated with known malicious activity (+15)")

        # Cap score at 100
        final_score = min(score, 100)

        # Categorize Severity
        if final_score >= 85:
            severity = "CRITICAL"
        elif final_score >= 60:
            severity = "HIGH"
        elif final_score >= 35:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return RiskAssessment(
            score=final_score, severity=severity, risk_factors=risk_factors
        )

    # -------------------------------------------------------------------------
    # 3. Incident Response Link Generator & Local Session Neutralization
    # -------------------------------------------------------------------------

    def generate_incident_response_links(
        self, breaches: List[BreachDetail]
    ) -> List[str]:
        """Generate targeted password reset URLs for compromised domain platforms."""
        urls: Set[str] = set()
        for breach in breaches:
            domain_key = breach.domain.lower().split(".")[0]
            if domain_key in INCIDENT_RESPONSE_URLS:
                urls.add(INCIDENT_RESPONSE_URLS[domain_key])

        # Default fallback recommendations if generic breach occurred
        if not urls and breaches:
            urls.add(INCIDENT_RESPONSE_URLS["google"])
            urls.add(INCIDENT_RESPONSE_URLS["microsoft"])

        return sorted(list(urls))

    def purge_local_sessions(
        self, target_email: str, target_dirs: List[Path]
    ) -> List[str]:
        """Locally purge cached local session files, auth tokens, and .session files 
        associated with target email to neutralize local unauthorized usage.
        """
        purged_files: List[str] = []
        normalized_email = target_email.strip().lower()
        allowed_suffixes = {".session", ".token", ".json", ".key", ".cache"}

        for directory in target_dirs:
            directory = Path(directory)
            if not directory.exists() or not directory.is_dir():
                continue

            for root, _, files in os.walk(directory, followlinks=False):
                for file in files:
                    file_path = Path(root) / file
                    # Match session formats (.session, .token, token.json, auth.key, etc.)
                    if file_path.suffix not in allowed_suffixes:
                        continue
                    # Never follow or delete symlinks: they can point outside the
                    # directory the caller authorised.
                    if file_path.is_symlink():
                        continue
                    try:
                        content = file_path.read_text(errors="ignore").lower()
                        # Require the full address. Matching the bare local-part
                        # (e.g. "admin", "dev", "a") deletes unrelated config and
                        # credential files.
                        if normalized_email in content:
                            file_path.unlink()
                            purged_files.append(str(file_path))
                            logger.info(
                                f"[Session Mitigation] Purged session artifact: {file_path}"
                            )
                    except Exception as e:
                        logger.error(
                            f"Failed to inspect/purge session file {file_path}: {e}"
                        )

        return purged_files

    # -------------------------------------------------------------------------
    # 4. Webhook Dispatcher System
    # -------------------------------------------------------------------------

    @staticmethod
    def _markdown_safe(value: Any) -> str:
        """Escape Markdown control characters so untrusted values cannot break out
        of the Telegram message formatting (e.g. to spoof an alert)."""
        return re.sub(r"([_*`\[\]])", r"\\\1", str(value))

    async def dispatch_telegram_alert(
        self, bot_token: str, chat_id: str, report: SecurityReport
    ) -> bool:
        """Send instant Telegram alert payload when high/critical risk breaches occur."""
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        msg = (
            f"🚨 *ReconX Security Alert: Email Breach Detected*\n\n"
            f"*Target Email:* `{self._markdown_safe(report.target_email)}`\n"
            f"*Risk Score:* {report.risk_assessment.score}/100 ({report.risk_assessment.severity})\n"
            f"*Total Breaches:* {len(report.breaches)}\n\n"
            f"*Risk Factors:*\n"
            + "\n".join([f"• {rf}" for rf in report.risk_assessment.risk_factors])
            + f"\n\n*Incident Response Action Links:*\n"
            + "\n".join([f"• {link}" for link in report.incident_response_urls])
        )

        payload = {
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        resp = await self._request_with_backoff("POST", url, json=payload)
        if resp and resp.status == 200:
            logger.info("Telegram notification successfully dispatched.")
            return True
        logger.error("Failed to dispatch Telegram notification.")
        return False

    # -------------------------------------------------------------------------
    # 5. Module Execution Workflow
    # -------------------------------------------------------------------------

    async def execute_full_assessment(
        self,
        email: str,
        password: Optional[str] = None,
        hibp_api_key: Optional[str] = None,
        emailrep_api_key: Optional[str] = None,
        kill_sessions: bool = False,
        session_dirs: Optional[List[Path]] = None,
        telegram_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
    ) -> SecurityReport:
        """Execute full async assessment pipeline."""
        console.print(
            Panel(
                f"[bold cyan]ReconX OSINT Email Security Audit[/bold cyan]\n"
                f"Target: [yellow]{escape(email)}[/yellow]",
                expand=False,
            )
        )

        # Run API Queries concurrently
        hibp_task = self.check_hibp_breaches(email, hibp_api_key)
        emailrep_task = self.check_emailrep(email, emailrep_api_key)
        pass_task = (
            self.check_pwned_password(password)
            if password
            else asyncio.sleep(0, result=None)
        )

        breaches, email_rep, pass_result = await asyncio.gather(
            hibp_task, emailrep_task, pass_task
        )

        # Risk Computation
        risk = self.compute_risk_score(breaches, pass_result, email_rep)
        ir_links = self.generate_incident_response_links(breaches)

        # Local Session Neutralization
        mitigation_actions = []
        if kill_sessions:
            if not session_dirs:
                # Refuse to sweep implicit paths such as $HOME/.config or the CWD:
                # an unbounded recursive delete is not recoverable.
                logger.warning(
                    "kill_sessions requested without session_dirs; refusing to "
                    "purge. Pass an explicit list of directories to allow."
                )
            else:
                purged = self.purge_local_sessions(email, session_dirs)
                mitigation_actions = [f"Purged session file: {p}" for p in purged]

        report = SecurityReport(
            target_email=email,
            timestamp=datetime.now(timezone.utc).isoformat(),
            breaches=breaches,
            password_check=pass_result,
            email_rep=email_rep,
            risk_assessment=risk,
            incident_response_urls=ir_links,
            mitigation_actions=mitigation_actions,
        )

        # Telegram Alert Dispatcher
        if telegram_token and telegram_chat_id and risk.score >= 35:
            await self.dispatch_telegram_alert(
                telegram_token, telegram_chat_id, report
            )

        self._render_console_report(report)
        return report

    def _render_console_report(self, report: SecurityReport) -> None:
        """Render beautiful CLI output tables using Rich."""
        # Risk Summary
        color = (
            "red"
            if report.risk_assessment.severity in ["HIGH", "CRITICAL"]
            else "yellow"
            if report.risk_assessment.severity == "MEDIUM"
            else "green"
        )
        console.print(
            f"\n[bold]Risk Score:[/bold] [{color}]{report.risk_assessment.score}/100 ({report.risk_assessment.severity})[/{color}]"
        )

        # Breaches Table
        if report.breaches:
            table = Table(title="Exposed Data Breaches", show_header=True)
            table.add_column("Title", style="cyan")
            table.add_column("Breach Date", style="magenta")
            table.add_column("Exposed Data Classes", style="red")

            for breach in report.breaches:
                table.add_row(
                    escape(breach.title),
                    escape(breach.breach_date),
                    escape(", ".join(breach.data_classes[:4])),
                )
            console.print(table)
        else:
            console.print("[green]✔ No public breach occurrences found.[/green]")

        # Incident Response Links
        if report.incident_response_urls:
            console.print("\n[bold cyan]Recommended Incident Response Password Reset Links:[/bold cyan]")
            for link in report.incident_response_urls:
                console.print(f"  • [link={link}]{link}[/link]")