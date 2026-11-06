"""Secret masking. Two independent layers:

1. Terraform's own sensitivity masks (before_sensitive / after_sensitive).
2. Name heuristics (password, secret, token, key, ...) plus a few value-shape
   patterns (private keys, cloud access key ids, URL credentials, JWTs).

Everything a tool prints about a value goes through here first.
"""

from __future__ import annotations

import re
from typing import Any

MASK = "(sensitive)"
UNKNOWN = "(known after apply)"

_NAME = re.compile(
    r"password|passwd|passphrase|^pass$|^pass[_\-.]|pwd|secret|token|credential|private|"
    r"authorization|signature|bearer|cookie|salt|connection[_\-]?string|"
    r"api[_\-]?key|access[_\-]?key|(^|[_\-.\s])key($|[_\-.\s])|_key|key_|[a-z]key$",
    re.IGNORECASE,
)

_VALUE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY"),
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\."),
    re.compile(r"\b(ghp|gho|ghs|github_pat|glpat|xox[abpr])[_\-][A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),
]
_URL_CRED = re.compile(r"(://[^/\s:@]*):([^/\s@]+)@")


def name_is_secret(name: object) -> bool:
    """True when an attribute/key name looks like it holds a credential."""
    return isinstance(name, str) and _NAME.search(name) is not None


def scrub_string(s: str) -> str:
    """Mask credential-shaped content inside a string that is otherwise shown."""
    for pat in _VALUE_PATTERNS:
        if pat.search(s):
            return MASK
    return _URL_CRED.sub(lambda m: m.group(1) + ":" + MASK + "@", s)


def _child(mask: Any, key: Any) -> Any:
    if mask is True:
        return True
    if isinstance(mask, dict):
        return mask.get(key, False)
    if isinstance(mask, list) and isinstance(key, int) and 0 <= key < len(mask):
        return mask[key]
    return False


def redact(value: Any, sens: Any = False, secret_name: bool = False, depth: int = 0) -> Any:
    """Return a copy of value with sensitive parts replaced by MASK.

    sens is a Terraform sensitivity mask (True / dict / list / False).
    """
    if sens is True or (secret_name and value is not None and not isinstance(value, bool)):
        return MASK
    if depth > 64:
        return "(nested too deep)"
    if isinstance(value, dict):
        return {
            k: redact(v, _child(sens, k), secret_name or name_is_secret(k), depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v, _child(sens, i), secret_name, depth + 1) for i, v in enumerate(value)]
    if isinstance(value, str):
        return scrub_string(value)
    return value
