from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator


class SignupRecipe(BaseModel):
    signup_url: str = Field(min_length=8, max_length=2048)
    email_selector: str = Field(min_length=1, max_length=200)
    password_selector: str = Field(min_length=1, max_length=200)
    submit_selector: str = Field(min_length=1, max_length=200)
    confirm_password_selector: str | None = Field(default=None, max_length=200)
    name_selector: str | None = Field(default=None, max_length=200)
    name_value: str = Field(default="Security Test User", max_length=120)


class ScanRequest(BaseModel):
    target_url: str = Field(min_length=8, max_length=2048)
    model: str = Field(min_length=1, max_length=160)
    api_key: SecretStr = Field(min_length=8)
    api_base: str | None = Field(default=None, max_length=2048)
    scan_mode: Literal["quick", "standard", "deep"] = "deep"
    max_budget_usd: float = Field(default=10.0, gt=0, le=500)
    max_runtime_minutes: int = Field(default=120, ge=5, le=360)
    authorized: bool = False
    allow_private_target: bool = False
    create_test_account: bool = False
    controlled_email_domain: str | None = Field(default=None, max_length=253)
    controlled_email_domain_confirmed: bool = False
    account_recipe: SignupRecipe | None = None
    existing_test_email: str | None = Field(default=None, max_length=320)
    existing_test_password: SecretStr | None = None

    @field_validator("model")
    @classmethod
    def clean_model(cls, value: str) -> str:
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            raise ValueError("Model ID must be non-empty and must not contain whitespace.")
        return value

    @field_validator("controlled_email_domain")
    @classmethod
    def clean_email_domain(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().lower().strip(".")
        if "@" in value or "/" in value or " " in value:
            raise ValueError("Enter a domain only, not an email address or URL.")
        return value or None
