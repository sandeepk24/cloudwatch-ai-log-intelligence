"""Sensitive data redaction before AI processing.

This module redacts PII, credentials, and other sensitive information
from log messages to prevent accidental exposure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from app.core.logging import get_logger

logger = get_logger(__name__)


class RedactionCategory(StrEnum):
    """Categories of sensitive data to redact."""

    CREDENTIALS = "credentials"
    PII = "pii"
    FINANCIAL = "financial"
    NETWORK = "network"
    SECRETS = "secrets"


@dataclass
class RedactionRule:
    """A rule for redacting sensitive data."""

    id: str
    name: str
    category: RedactionCategory
    pattern: str
    replacement: str = "[REDACTED]"
    enabled: bool = True
    _compiled: re.Pattern | None = field(default=None, repr=False)

    def __post_init__(self):
        """Compile the regex pattern."""
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def apply(self, text: str) -> tuple[str, int]:
        """Apply the redaction rule to text.

        Returns:
            Tuple of (redacted_text, count_of_redactions)
        """
        if not self.enabled or self._compiled is None:
            return text, 0

        result, count = self._compiled.subn(self.replacement, text)
        return result, count


# -----------------------------------------------------------------------------
# Default Redaction Rules
# -----------------------------------------------------------------------------

DEFAULT_REDACTION_RULES: list[RedactionRule] = [
    # AWS Credentials
    RedactionRule(
        id="aws_access_key",
        name="AWS Access Key ID",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"\b(AKIA[0-9A-Z]{16})\b",
        replacement="[AWS_ACCESS_KEY]",
    ),
    RedactionRule(
        id="aws_secret_key",
        name="AWS Secret Access Key",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"(?:aws_secret_access_key|secret_?key|secretaccesskey)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        replacement="[AWS_SECRET_KEY]",
    ),
    RedactionRule(
        id="aws_session_token",
        name="AWS Session Token",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"(?:aws_session_token|session_?token)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
        replacement="[AWS_SESSION_TOKEN]",
    ),
    # API Keys and Tokens
    RedactionRule(
        id="api_key",
        name="API Key",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"(?:api[_-]?key|apikey|api_token)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
        replacement="[API_KEY]",
    ),
    RedactionRule(
        id="bearer_token",
        name="Bearer Token",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"Bearer\s+([A-Za-z0-9_-]{20,})",
        replacement="Bearer [TOKEN]",
    ),
    RedactionRule(
        id="jwt_token",
        name="JWT Token",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"\b(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\b",
        replacement="[JWT]",
    ),
    RedactionRule(
        id="basic_auth",
        name="Basic Auth Header",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"Basic\s+([A-Za-z0-9+/=]{10,})",
        replacement="Basic [CREDENTIALS]",
    ),
    # Passwords
    RedactionRule(
        id="password_field",
        name="Password Field",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"(?:password|passwd|pwd|pass)\s*[=:]\s*['\"]?([^'\"\s,;}{]+)['\"]?",
        replacement="password=[REDACTED]",
    ),
    # SSH/Private Keys
    RedactionRule(
        id="ssh_private_key",
        name="SSH Private Key",
        category=RedactionCategory.SECRETS,
        pattern=r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        replacement="[PRIVATE_KEY]",
    ),
    RedactionRule(
        id="private_key_inline",
        name="Private Key Inline",
        category=RedactionCategory.SECRETS,
        pattern=r"(?:private[_-]?key|priv[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=\n]{50,})['\"]?",
        replacement="[PRIVATE_KEY]",
    ),
    # PII - Email
    RedactionRule(
        id="email",
        name="Email Address",
        category=RedactionCategory.PII,
        pattern=r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
        replacement="[EMAIL]",
    ),
    # PII - Phone Numbers
    RedactionRule(
        id="phone_us",
        name="US Phone Number",
        category=RedactionCategory.PII,
        pattern=r"\b(\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b",
        replacement="[PHONE]",
    ),
    # PII - SSN
    RedactionRule(
        id="ssn",
        name="Social Security Number",
        category=RedactionCategory.PII,
        pattern=r"\b(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b",
        replacement="[SSN]",
    ),
    # Financial - Credit Card
    RedactionRule(
        id="credit_card",
        name="Credit Card Number",
        category=RedactionCategory.FINANCIAL,
        pattern=r"\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b",
        replacement="[CREDIT_CARD]",
    ),
    RedactionRule(
        id="credit_card_partial",
        name="Credit Card Partial",
        category=RedactionCategory.FINANCIAL,
        pattern=r"(?:card[_-]?number|cc[_-]?num)\s*[=:]\s*['\"]?(\d{12,19})['\"]?",
        replacement="[CREDIT_CARD]",
    ),
    # Network - IP Addresses (optional - configurable)
    RedactionRule(
        id="ipv4_private",
        name="Private IPv4",
        category=RedactionCategory.NETWORK,
        pattern=r"\b((?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3})\b",
        replacement="[INTERNAL_IP]",
        enabled=False,  # Disabled by default - useful for debugging
    ),
    RedactionRule(
        id="ipv4_public",
        name="Public IPv4",
        category=RedactionCategory.NETWORK,
        pattern=r"\b((?:(?!10\.|127\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.){3}\d{1,3})\b",
        replacement="[PUBLIC_IP]",
        enabled=False,  # Disabled by default
    ),
    # Connection Strings
    RedactionRule(
        id="connection_string",
        name="Connection String",
        category=RedactionCategory.CREDENTIALS,
        pattern=r"(?:mongodb|postgres|mysql|redis|amqp|jdbc)://[^\s'\"]+",
        replacement="[CONNECTION_STRING]",
    ),
    # Generic Secrets
    RedactionRule(
        id="generic_secret",
        name="Generic Secret",
        category=RedactionCategory.SECRETS,
        pattern=r"(?:secret|token|key|auth)[_-]?(?:key|token|secret)?\s*[=:]\s*['\"]?([A-Za-z0-9_-]{32,})['\"]?",
        replacement="[SECRET]",
    ),
]


class Redactor:
    """Redact sensitive information from text."""

    def __init__(
        self,
        rules: list[RedactionRule] | None = None,
        enabled_categories: set[RedactionCategory] | None = None,
        custom_patterns: list[tuple[str, str]] | None = None,
    ):
        """Initialize the redactor.

        Args:
            rules: Custom rules to use instead of defaults
            enabled_categories: Only apply rules from these categories
            custom_patterns: Additional (pattern, replacement) pairs
        """
        self._rules = rules or list(DEFAULT_REDACTION_RULES)
        self._enabled_categories = enabled_categories
        self._custom_patterns: list[tuple[re.Pattern, str]] = []

        if custom_patterns:
            for pattern, replacement in custom_patterns:
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                    self._custom_patterns.append((compiled, replacement))
                except re.error as e:
                    logger.warning("Invalid custom redaction pattern %s: %s", pattern, e)

    def redact(self, text: str) -> tuple[str, dict[str, int]]:
        """Redact sensitive information from text.

        Args:
            text: The text to redact

        Returns:
            Tuple of (redacted_text, counts_by_rule_id)
        """
        result = text
        counts: dict[str, int] = {}

        # Apply built-in rules
        for rule in self._rules:
            if not rule.enabled:
                continue
            if (
                self._enabled_categories is not None
                and rule.category not in self._enabled_categories
            ):
                continue

            result, count = rule.apply(result)
            if count > 0:
                counts[rule.id] = count

        # Apply custom patterns
        for i, (pattern, replacement) in enumerate(self._custom_patterns):
            result, count = pattern.subn(replacement, result)
            if count > 0:
                counts[f"custom_{i}"] = count

        return result, counts

    def redact_dict(self, data: dict, keys_to_redact: set[str] | None = None) -> dict:
        """Redact sensitive information from a dictionary.

        Args:
            data: Dictionary to redact
            keys_to_redact: Additional keys whose values should be fully redacted

        Returns:
            Redacted dictionary
        """
        keys_to_redact = keys_to_redact or set()
        sensitive_key_patterns = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "credential",
            "auth",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
        }

        def should_redact_key(key: str) -> bool:
            key_lower = key.lower()
            return key_lower in keys_to_redact or any(
                pattern in key_lower for pattern in sensitive_key_patterns
            )

        def redact_value(key: str, value):
            if should_redact_key(key):
                return "[REDACTED]"
            if isinstance(value, str):
                redacted, _ = self.redact(value)
                return redacted
            if isinstance(value, dict):
                return self.redact_dict(value, keys_to_redact)
            if isinstance(value, list):
                return [redact_value(key, item) for item in value]
            return value

        return {k: redact_value(k, v) for k, v in data.items()}


# Global default redactor
_default_redactor: Redactor | None = None


def get_default_redactor() -> Redactor:
    """Get the default redactor instance."""
    global _default_redactor
    if _default_redactor is None:
        _default_redactor = Redactor()
    return _default_redactor


def redact_message(text: str) -> str:
    """Convenience function to redact a message using defaults."""
    redactor = get_default_redactor()
    redacted, _ = redactor.redact(text)
    return redacted


def redact_for_ai(text: str) -> str:
    """Redact text specifically for AI processing.

    This applies all redaction rules including PII to ensure
    no sensitive data is sent to AI models.
    """
    redactor = Redactor(
        enabled_categories={
            RedactionCategory.CREDENTIALS,
            RedactionCategory.PII,
            RedactionCategory.FINANCIAL,
            RedactionCategory.SECRETS,
        }
    )
    redacted, _ = redactor.redact(text)
    return redacted
