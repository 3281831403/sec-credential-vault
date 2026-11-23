"""Credential vault lease core.

This is the only implementation file.  The public facade re-exports these
functions, and the tests import them from the vault package.

Store schema (a plain dict, mutated in place):
    secrets: {secret_id: {"secret_id": str, "scope": str,
                           "material": str, "version": int}}
    leases: {lease_id: lease}
    revoked_actors: set[str]
    revoked_secrets: set[str]
    revoked_leases: set[str]
    audit: list[dict]
    next_lease_no: int
    caller: str | None

Lease fields:
    lease_id, actor, secret_id, scope, issued_at, expires_at, ttl, version,
    revoked, revoked_at.

Security contract:
    Lease duration: ttl is a positive integer number of seconds.  A lease
    issued at now has expires_at exactly equal to now + ttl and is valid only
    while issued_at <= now < expires_at.  Tolerance is exactly 0 seconds: at
    now == expires_at the lease is already expired, with no clock-skew grace.
    Revocation propagation: revoking an actor or a secret invalidates every
    lease already issued for that actor or secret and blocks new leases for
    it.  Rotation invalidates every lease for the previous secret version.
    Caller binding: the hosting application authenticates the caller in
    store["caller"]; a lease is usable only by the actor recorded at issue.
    Scope: exact domain equality, never a string-prefix or parent-domain
    match.
    Audit: every read attempt appends exactly one event, including every
    denial, so actions remain attributable.
    Determinism: no wall clock and no randomness; now, ttl, and material are
    supplied by the caller.  Lease IDs are allocated monotonically from
    store["next_lease_no"].
"""


def issue_lease(store, actor, secret_id, ttl, now) -> dict:
    """Issue a lease that binds actor, secret, scope, and secret version.

    ttl must be a positive integer.  The lease expires exactly at
    now + ttl, and the zero-tolerance boundary applies.  The lease is stored
    in store["leases"] and returned.  A revoked actor or revoked secret is
    rejected with PermissionError; an unknown secret raises KeyError; an
    invalid ttl raises ValueError.  Lease IDs are deterministic and allocated
    from store["next_lease_no"].
    """
    raise NotImplementedError


def read_secret(store, lease_id, now) -> dict:
    """Read secret material under lease_id at now.

    Checks, in order: known lease, store["caller"] equals lease["actor"],
    lease not revoked (lease flag, revoked_leases, revoked_actors, or
    revoked_secrets), now strictly before expires_at, lease scope still equals
    the secret scope, and lease version still equals the secret version.
    Every attempt appends exactly one audit event before returning or raising.
    Any denial raises PermissionError and is audited with one of these
    reasons: unknown_lease, actor_mismatch, revoked, expired, rotated,
    scope_mismatch, secret_missing.  There is no expiry tolerance.
    """
    raise NotImplementedError


def revoke_actor(store, actor, now) -> int:
    """Revoke actor and every lease already issued to that actor.

    The actor is recorded in store["revoked_actors"], all of its leases are
    marked revoked at now and added to store["revoked_leases"], and the number
    of leases newly revoked is returned.  The operation is idempotent.
    Propagation is complete: no previously issued lease for the actor remains
    usable, and future issue_lease calls for the actor are denied.
    """
    raise NotImplementedError


def revoke_secret(store, secret_id, now) -> int:
    """Revoke secret_id and propagate revocation to every issued lease.

    The secret is recorded in store["revoked_secrets"], every lease for the
    secret is marked revoked at now and added to store["revoked_leases"], and
    the number of leases newly revoked is returned.  The operation is
    idempotent.  Future issue_lease and read_secret calls for the secret are
    denied.
    """
    raise NotImplementedError


def check_scope(lease, secret) -> bool:
    """Return True only when the lease scope exactly covers the secret scope.

    Comparison is exact string equality.  Prefix matches, parent domains,
    sibling domains, and case-insensitive matches are all rejected.
    """
    raise NotImplementedError


def rotate_secret(store, secret_id, material, now) -> dict:
    """Rotate secret material and invalidate every lease for the old version.

    The secret version is incremented, material is replaced, and every lease
    for the secret is revoked at now.  Returns a dict with secret_id, version,
    material, rotated_at, and revoked_leases (the count newly revoked).  New
    leases use the new version; old leases are never allowed to keep reading
    old material by default.
    """
    raise NotImplementedError


def validate_policy(policy) -> list[str]:
    """Return the list of policy problems, in deterministic order.

    A valid policy has require_expiry, propagate_revocation, and enforce_scope
    set to exactly True, plus an integer max_ttl in the inclusive range
    1..3600.  Problem codes are: lease_never_expires,
    revocation_not_propagated, scope_not_restricted, max_ttl_invalid, and
    max_ttl_exceeds_limit.  A valid policy returns an empty list.
    """
    raise NotImplementedError


def lease_batch(requests, policy, now) -> dict:
    """Process lease requests independently with no lease reuse.

    Each request is a dict with store, actor, secret_id, and ttl.  The store is
    carried by each request because this function has no separate store
    argument; requests in one batch normally share the same store.  The policy
    is validated first and max_ttl is enforced per request.  Every request gets
    its own fresh lease; a failure in one request never stops or reuses
    another.  Returns:
        {
            "results": [
                {"index": int, "ok": True, "lease": dict},
                {"index": int, "ok": False, "error": str},
            ],
            "issued": int,
            "failed": int,
        }
    Results preserve request order.
    """
    raise NotImplementedError
