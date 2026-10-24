from __future__ import annotations

import pytest

from strix.oneclick.security import TargetValidationError, require_same_origin, validate_target_url


def test_private_target_requires_explicit_opt_in() -> None:
    with pytest.raises(TargetValidationError, match="private"):
        validate_target_url("http://127.0.0.1:8080")
    assert validate_target_url("http://127.0.0.1:8080", allow_private=True) == "http://127.0.0.1:8080/"


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
