from __future__ import annotations

from email.message import EmailMessage

import pytest

from strix.oneclick.accounts import extract_verification_link
from strix.oneclick.security import TargetValidationError, require_same_origin, validate_target_url


def test_private_target_requires_explicit_opt_in() -> None:
    with pytest.raises(TargetValidationError, match="private"):
        validate_target_url("http://127.0.0.1:8080")
    target = validate_target_url("http://127.0.0.1:8080", allow_private=True)
    assert target == "http://127.0.0.1:8080/"


def test_target_credentials_are_rejected() -> None:
    with pytest.raises(TargetValidationError, match="credentials"):
        validate_target_url("https://user:password@example.test")


def test_only_http_schemes_are_accepted() -> None:
    with pytest.raises(TargetValidationError, match="http"):
        validate_target_url("file:///etc/passwd")


def test_signup_must_use_same_origin() -> None:
    with pytest.raises(TargetValidationError, match="same origin"):
        require_same_origin("http://127.0.0.1:8080", "http://127.0.0.1:8081/register")


def test_same_origin_signup_normalizes_path() -> None:
    actual = require_same_origin("http://127.0.0.1:8080", "http://127.0.0.1:8080/register")
    assert actual == "http://127.0.0.1:8080/register"


def test_same_origin_normalizes_default_https_port() -> None:
    actual = require_same_origin(
        "https://127.0.0.1", "https://127.0.0.1:443/register"
    )
    assert actual == "https://127.0.0.1:443/register"


def test_email_verification_link_must_match_recipient_and_origin() -> None:
    message = EmailMessage()
    message["To"] = "strix-test-123@example.test"
    message["From"] = "noreply@example.test"
    message["Subject"] = "Verify account"
    message.set_content("Verify: http://127.0.0.1:8080/verify?token=abc")

    link = extract_verification_link(
        message.as_bytes(),
        "strix-test-123@example.test",
        "http://127.0.0.1:8080",
    )
    assert link == "http://127.0.0.1:8080/verify?token=abc"


def test_external_verification_link_is_not_followed() -> None:
    message = EmailMessage()
    message["To"] = "strix-test-123@example.test"
    message["From"] = "noreply@example.test"
    message.set_content("Verify: https://outside.example.test/verify?token=abc")

    link = extract_verification_link(
        message.as_bytes(),
        "strix-test-123@example.test",
        "http://127.0.0.1:8080",
    )
    assert link is None


def test_email_for_a_different_recipient_is_ignored() -> None:
    message = EmailMessage()
    message["To"] = "someone-else@example.test"
    message["From"] = "noreply@example.test"
    message.set_content("Verify: http://127.0.0.1:8080/verify?token=abc")

    link = extract_verification_link(
        message.as_bytes(),
        "strix-test-123@example.test",
        "http://127.0.0.1:8080",
    )
    assert link is None
