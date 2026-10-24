from __future__ import annotations

import asyncio
import re
import secrets
import string
from dataclasses import dataclass
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from .models import SignupRecipe
from .security import require_same_origin


@dataclass
class TestAccount:
    email: str
    password: str


def _password(length: int = 26) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%_-+=?"
    # Include one character from each class before filling the remainder.
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
    return parsed.scheme.lower(), (parsed.hostname or "").lower().rstrip("."), parsed.port


async def provision_test_account(
    target_url: str,
    recipe: SignupRecipe,
    email_domain: str,
    pause_for_operator: Callable[[str], Awaitable[None]],
) -> TestAccount:
    """Fill a target-origin signup form; leave CAPTCHA and verification to the operator.

    Playwright is optional and the browser is visible. When signup success is unclear, the
    operator can complete the site's ordinary verification flow before allowing the scan.
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Account automation requires the optional Playwright dependency. "
            "Install with: uv sync --extra oneclick-browser, then run "
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
            await page.locator(recipe.password_selector).first.fill(account.password, timeout=15_000)
            if recipe.confirm_password_selector:
                await page.locator(recipe.confirm_password_selector).first.fill(account.password, timeout=10_000)
            if recipe.name_selector:
                await page.locator(recipe.name_selector).first.fill(recipe.name_value, timeout=10_000)
            await page.locator(recipe.submit_selector).first.click(timeout=15_000)
            await page.wait_for_timeout(1800)

            body = ""
            try:
                body = (await page.locator("body").inner_text(timeout=3000)).lower()[:12000]
            except Exception:
                pass
            url = page.url
            verification_markers = (
                "verify your email", "check your inbox", "confirm your email",
                "email verification", "confirmation link", "captcha", "verify you are human",
                "two-factor", "one-time password",
            )
            success_markers = ("welcome", "account created", "registration complete", "sign out", "log out", "dashboard")
            still_has_form = False
            try:
                still_has_form = await page.locator(recipe.email_selector).first.is_visible(timeout=1200)
            except Exception:
                pass
            needs_operator = (
                any(marker in body for marker in verification_markers)
                or still_has_form
                or not any(marker in body for marker in success_markers)
                or _origin(url) != _origin(target_url)
            )
            if needs_operator:
                await pause_for_operator(
                    "The signup result needs review. Complete any normal email verification or "
                    "human challenge in the visible browser, return to the target application, "
                    "then use the dashboard's Continue button. Strix will not bypass CAPTCHA "
                    "or verification controls."
                )
                # The browser stays open during the pause. After the operator returns to the
                # application, check origin before accepting the resulting browser session.
                if _origin(page.url) != _origin(target_url):
                    await page.goto(target_url, wait_until="domcontentloaded", timeout=30_000)
                if _origin(page.url) != _origin(target_url):
                    raise RuntimeError("Verification did not return to the target application's origin.")
            return account
        finally:
            await context.close()
            await browser.close()
