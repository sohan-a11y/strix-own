from __future__ import annotations

import asyncio
import html
import imaplib
import re
import secrets
import string
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .security import TargetValidationError, require_same_origin

if TYPE_CHECKING:
    from .models import SignupRecipe


@dataclass
class TestAccount:
    email: str
    password: str = field(repr=False)


@dataclass(frozen=True)
class IMAPInbox:
    host: str
    port: int
    username: str
    password: str = field(repr=False)


def _password(length: int = 26) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%_-+=?"
    chars = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%_-+=?"),
    ]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _new_email(domain: str) -> str:
    if not domain or not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", domain):
        raise ValueError("Use a valid test-email domain you control.")
    return f"strix-test-{secrets.token_hex(6)}@{domain}"


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, (parsed.hostname or "").lower().rstrip("."), port


def extract_verification_link(
    raw_message: bytes,
    expected_email: str,
    target_url: str,
) -> str | None:
    """Return a same-origin verification link from an email addressed to this test account."""
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    recipient_headers: list[str] = []
    for header in ("to", "delivered-to", "x-original-to", "envelope-to"):
        recipient_headers.extend(str(value) for value in message.get_all(header, []))
    recipients = {
        address.lower()
        for _, address in getaddresses(recipient_headers)
        if address
    }
    if expected_email.lower() not in recipients:
        return None

    bodies: list[str] = []
    for part in message.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeDecodeError, AttributeError):
            continue
        if isinstance(content, str):
            bodies.append(html.unescape(content))

    for body in bodies:
        for match in re.findall(r"https?://[^\s<>\"']+", body):
            candidate = match.rstrip(".,);]}>")
            try:
                return require_same_origin(target_url, candidate)
            except TargetValidationError:
                continue
    return None


def wait_for_verification_link(
    inbox: IMAPInbox,
    expected_email: str,
    target_url: str,
    timeout_seconds: int = 180,
) -> str | None:
    """Poll a user-controlled IMAP inbox for a message and same-origin verification link."""
    deadline = time.monotonic() + timeout_seconds
    seen_uids: set[bytes] = set()
    while time.monotonic() < deadline:
        client: imaplib.IMAP4_SSL | None = None
        try:
            client = imaplib.IMAP4_SSL(inbox.host, inbox.port, timeout=10)
            client.login(inbox.username, inbox.password)
            status, _ = client.select("INBOX")
            if status != "OK":
                raise RuntimeError("The configured IMAP inbox could not be selected.")
            status, data = client.search(None, "ALL")
            if status == "OK" and data:
                for uid in reversed(data[0].split()[-40:]):
                    if uid in seen_uids:
                        continue
                    seen_uids.add(uid)
                    fetch_status, items = client.fetch(uid, "(RFC822)")
                    if fetch_status != "OK" or not items:
                        continue
                    for item in items:
                        if not isinstance(item, tuple) or not isinstance(item[1], bytes):
                            continue
                        link = extract_verification_link(item[1], expected_email, target_url)
                        if link:
                            return link
        except (imaplib.IMAP4.error, OSError) as exc:
            raise RuntimeError(
                "Could not access the configured IMAP inbox. Check the host, port, "
                "username, password, and IMAPS access."
            ) from exc
        finally:
            if client is not None:
                with suppress(imaplib.IMAP4.error, OSError):
                    client.logout()
        time.sleep(min(4, max(0, deadline - time.monotonic())))
    return None


async def provision_test_account(
    target_url: str,
    recipe: SignupRecipe,
    email_domain: str,
    pause_for_operator: Callable[[str], Awaitable[None]],
    imap_inbox: IMAPInbox | None = None,
) -> TestAccount:
    """Fill a target-origin signup form, optionally verify using a controlled IMAP inbox.

    The browser stays visible. Only verification URLs from email addressed to the generated
    test account and sharing the target origin are followed. CAPTCHA, MFA, and other human
    challenges are left to the operator.
    """
    try:
        from playwright.async_api import Error as PlaywrightError, async_playwright  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Account automation requires the optional Playwright dependency. "
            "Install Playwright into the Strix environment, then run "
            "'uv run python -m playwright install chromium'."
        ) from exc

    signup_url = require_same_origin(target_url, recipe.signup_url)
    account = TestAccount(email=_new_email(email_domain), password=_password())

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=False)
        context = await browser.new_context()
        page = await context.new_page()
        try:
            await page.goto(signup_url, wait_until="domcontentloaded", timeout=45_000)
            await page.locator(recipe.email_selector).first.fill(account.email, timeout=15_000)
            await page.locator(recipe.password_selector).first.fill(
                account.password, timeout=15_000
            )
            if recipe.confirm_password_selector:
                await page.locator(recipe.confirm_password_selector).first.fill(
                    account.password, timeout=10_000
                )
            if recipe.name_selector:
                await page.locator(recipe.name_selector).first.fill(
                    recipe.name_value, timeout=10_000
                )
            await page.locator(recipe.submit_selector).first.click(timeout=15_000)
            await page.wait_for_timeout(1800)

            body = ""
            try:
                body = (await page.locator("body").inner_text(timeout=3000)).lower()[:12000]
            except PlaywrightError:
                body = ""
            verification_markers = (
                "verify your email",
                "check your inbox",
                "confirm your email",
                "email verification",
                "confirmation link",
            )
            challenge_markers = (
                "captcha",
                "verify you are human",
                "two-factor",
                "one-time password",
                "authenticator",
                "security check",
            )
            success_markers = (
                "welcome",
                "account created",
                "registration complete",
                "sign out",
                "log out",
                "dashboard",
            )
            challenge_detected = any(marker in body for marker in challenge_markers)
            email_verification_needed = any(marker in body for marker in verification_markers)
            has_success_marker = any(marker in body for marker in success_markers)

            if (
                imap_inbox is not None
                and not challenge_detected
                and (email_verification_needed or not has_success_marker)
            ):
                link = await asyncio.to_thread(
                    wait_for_verification_link,
                    imap_inbox,
                    account.email,
                    target_url,
                )
                if link:
                    await page.goto(link, wait_until="domcontentloaded", timeout=45_000)
                    await page.wait_for_timeout(1200)
                    try:
                        body = (await page.locator("body").inner_text(timeout=3000)).lower()[:12000]
                    except PlaywrightError:
                        body = ""

            url = page.url
            still_has_form = False
            try:
                still_has_form = await page.locator(recipe.email_selector).first.is_visible(
                    timeout=1200
                )
            except PlaywrightError:
                still_has_form = False
            needs_operator = (
                challenge_detected
                or still_has_form
                or not any(marker in body for marker in success_markers)
                or _origin(url) != _origin(target_url)
            )
            if needs_operator:
                message = (
                    "Signup needs manual review. Complete any CAPTCHA, MFA, or verification "
                    "flow in the visible browser, return to the target application, then press "
                    "Continue. The controller will not bypass human challenges."
                )
                if email_verification_needed and imap_inbox is None:
                    message = (
                        "Email verification is required. Add IMAP details for an inbox you "
                        "control to automate same-origin verification, or finish verification "
                        "in the visible browser and press Continue."
                    )
                elif imap_inbox is not None and email_verification_needed:
                    message = (
                        "No matching same-origin verification link was completed automatically. "
                        "Finish the site's ordinary verification in the visible browser and press "
                        "Continue."
                    )
                await pause_for_operator(message)
                if _origin(page.url) != _origin(target_url):
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=30_000)
                if _origin(page.url) != _origin(target_url):
                    raise RuntimeError(
                        "Verification did not return to the target app origin."
                    )
            return account
        finally:
            await context.close()
            await browser.close()
