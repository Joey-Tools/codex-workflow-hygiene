"""Shared deterministic locator patterns for working-zone validators."""

from __future__ import annotations

import re


BARE_PRIVATE_LOCATOR_RE = re.compile(
    r"(?i)\b(?:localhost|(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"(?:[a-z0-9-]+\.)+(?:corp|home|internal|intranet|lan|local))"
    r"(?::\d{1,5})?(?:/[^\s<>\"']*)?"
)
BARE_FQDN_RE = re.compile(
    r"(?i)(?<![a-z0-9_@-])"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})"
    r"(?::\d{1,5})?(?:/[^\s<>\"']*)?(?![a-z0-9_-])"
)
