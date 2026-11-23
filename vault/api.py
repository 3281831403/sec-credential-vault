"""Public re-export facade for the credential vault.

This module only re-exports the eight public functions from the private
implementation module.  It contains no stubs and no business logic.
"""

from ._impl import (
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
