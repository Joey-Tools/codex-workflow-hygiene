"""Shared durable-history authority errors."""

from __future__ import annotations


class AuthorityError(RuntimeError):
    """Base error for durable publication authority failures."""


class HistoryValidationError(AuthorityError):
    """The retained publication history failed closed validation."""


class ProductionMarkerError(AuthorityError):
    """The owner-local production marker failed validation."""


class AutomationCutoverBlocked(AuthorityError):
    """The automation cutover cannot proceed safely."""


class ProviderCacheError(AuthorityError):
    """The owner-local provider cache failed validation."""


class ProviderCacheConflict(ProviderCacheError):
    """The provider cache conflicts with durable history."""
