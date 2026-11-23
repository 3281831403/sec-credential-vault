"""Credential vault package.

The public surface is exported from vault.api, which in turn only re-exports
the implementation in vault._impl.
"""

from .api import (
    check_scope,
    issue_lease,
    lease_batch,
    read_secret,
    revoke_actor,
    revoke_secret,
    rotate_secret,
    validate_policy,
)

__all__ = [
    "issue_lease",
    "read_secret",
    "revoke_actor",
    "revoke_secret",
    "check_scope",
    "rotate_secret",
    "validate_policy",
    "lease_batch",
]
