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


def _is_positive_int(value) -> bool:
    """True only for a genuine positive integer (bool is not accepted)."""
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _audit_read(store, lease, lease_id, now, reason=None) -> None:
    """Append exactly one secret.read event, allowing or denying."""
    event = {
        "event": "secret.read",
        "decision": "deny" if reason is not None else "allow",
        "actor": store.get("caller"),
        "secret_id": lease["secret_id"] if lease is not None else None,
        "lease_id": lease_id,
        "at": now,
    }
    if reason is not None:
        event["reason"] = reason
    store["audit"].append(event)


def _deny(store, lease, lease_id, now, reason):
    """Audit a denial and raise PermissionError for the given reason."""
    _audit_read(store, lease, lease_id, now, reason=reason)
    raise PermissionError(reason)


def _revoke_matching_leases(store, predicate, now) -> int:
    """Mark every matching, not-yet-revoked lease revoked; return the count."""
    newly_revoked = 0
    for lease_id, lease in store["leases"].items():
        if not predicate(lease):
            continue
        if lease["revoked"] or lease_id in store["revoked_leases"]:
            continue
        lease["revoked"] = True
        lease["revoked_at"] = now
        store["revoked_leases"].add(lease_id)
        newly_revoked += 1
    return newly_revoked


def issue_lease(store, actor, secret_id, ttl, now) -> dict:
    """Issue a lease that binds actor, secret, scope, and secret version.

    ttl must be a positive integer.  The lease expires exactly at
    now + ttl, and the zero-tolerance boundary applies.  The lease is stored
    in store["leases"] and returned.  A revoked actor or revoked secret is
    rejected with PermissionError; an unknown secret raises KeyError; an
    invalid ttl raises ValueError.  Lease IDs are deterministic and allocated
    from store["next_lease_no"].
    """
    if not _is_positive_int(ttl):
        raise ValueError("ttl must be a positive integer")

    # Defect 1/4/5: an expired-only lease is gone, and revoked actors or
    # secrets can never obtain new leases.
    if actor in store["revoked_actors"]:
        raise PermissionError("actor is revoked")

    if secret_id not in store["secrets"]:
        raise KeyError(secret_id)

    if secret_id in store["revoked_secrets"]:
        raise PermissionError("secret is revoked")

    secret = store["secrets"][secret_id]
    lease_no = store["next_lease_no"]
    store["next_lease_no"] = lease_no + 1

    lease = {
        "lease_id": "lease-%d" % lease_no,
        "actor": actor,
        "secret_id": secret_id,
        "scope": secret["scope"],
        "issued_at": now,
        "expires_at": now + ttl,
        "ttl": ttl,
        "version": secret["version"],
        "revoked": False,
        "revoked_at": None,
    }
    store["leases"][lease["lease_id"]] = lease
    return lease


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
    lease = store["leases"].get(lease_id)

    # Defect 1: unknown lease.
    if lease is None:
        _deny(store, None, lease_id, now, "unknown_lease")

    # Defect 2: lease is bound to the actor recorded at issue.
    if store.get("caller") != lease["actor"]:
        _deny(store, lease, lease_id, now, "actor_mismatch")

    # Defect 3/4/5: honour the lease flag and every revocation list.
    if (
        lease["revoked"]
        or lease_id in store["revoked_leases"]
        or lease["actor"] in store["revoked_actors"]
        or lease["secret_id"] in store["revoked_secrets"]
    ):
        _deny(store, lease, lease_id, now, "revoked")

    # Defect 1: hard expiry with zero tolerance.
    if now >= lease["expires_at"]:
        _deny(store, lease, lease_id, now, "expired")

    secret = store["secrets"].get(lease["secret_id"])
    if secret is None:
        _deny(store, lease, lease_id, now, "secret_missing")

    # Defect 6: exact domain equality only.
    if not check_scope(lease, secret):
        _deny(store, lease, lease_id, now, "scope_mismatch")

    # Defect 7: a rotated secret invalidates leases for the old version.
    if lease["version"] != secret["version"]:
        _deny(store, lease, lease_id, now, "rotated")

    # Defect 10: every read attempt is audited, including this allow.
    _audit_read(store, lease, lease_id, now)
    return dict(secret)


def revoke_actor(store, actor, now) -> int:
    """Revoke actor and every lease already issued to that actor.

    The actor is recorded in store["revoked_actors"], all of its leases are
    marked revoked at now and added to store["revoked_leases"], and the number
    of leases newly revoked is returned.  The operation is idempotent.
    Propagation is complete: no previously issued lease for the actor remains
    usable, and future issue_lease calls for the actor are denied.
    """
    # Defect 4: record the actor so future leases are blocked too.
    store["revoked_actors"].add(actor)
    return _revoke_matching_leases(
        store, lambda lease: lease["actor"] == actor, now
    )


def revoke_secret(store, secret_id, now) -> int:
    """Revoke secret_id and propagate revocation to every issued lease.

    The secret is recorded in store["revoked_secrets"], every lease for the
    secret is marked revoked at now and added to store["revoked_leases"], and
    the number of leases newly revoked is returned.  The operation is
    idempotent.  Future issue_lease and read_secret calls for the secret are
    denied.
    """
    # Defect 5: revocation propagates to every already-issued lease.
    store["revoked_secrets"].add(secret_id)
    return _revoke_matching_leases(
        store, lambda lease: lease["secret_id"] == secret_id, now
    )


def check_scope(lease, secret) -> bool:
    """Return True only when the lease scope exactly covers the secret scope.

    Comparison is exact string equality.  Prefix matches, parent domains,
    sibling domains, and case-insensitive matches are all rejected.
    """
    lease_scope = lease.get("scope")
    secret_scope = secret.get("scope")
    # Defect 6: no prefix matching, no case folding, no None == None success.
    return (
        isinstance(lease_scope, str)
        and isinstance(secret_scope, str)
        and lease_scope == secret_scope
    )


def rotate_secret(store, secret_id, material, now) -> dict:
    """Rotate secret material and invalidate every lease for the old version.

    The secret version is incremented, material is replaced, and every lease
    for the secret is revoked at now.  Returns a dict with secret_id, version,
    material, rotated_at, and revoked_leases (the count newly revoked).  New
    leases use the new version; old leases are never allowed to keep reading
    old material by default.
    """
    if secret_id not in store["secrets"]:
        raise KeyError(secret_id)

    secret = store["secrets"][secret_id]
    secret["version"] = secret.get("version", 0) + 1
    secret["material"] = material

    # Defect 7: old leases die immediately; only new-version leases work.
    revoked_count = _revoke_matching_leases(
        store, lambda lease: lease["secret_id"] == secret_id, now
    )

    return {
        "secret_id": secret_id,
        "version": secret["version"],
        "material": secret["material"],
        "rotated_at": now,
        "revoked_leases": revoked_count,
    }


def validate_policy(policy) -> list[str]:
    """Return the list of policy problems, in deterministic order.

    A valid policy has require_expiry, propagate_revocation, and enforce_scope
    set to exactly True, plus an integer max_ttl in the inclusive range
    1..3600.  Problem codes are: lease_never_expires,
    revocation_not_propagated, scope_not_restricted, max_ttl_invalid, and
    max_ttl_exceeds_limit.  A valid policy returns an empty list.
    """
    problems = []

    # Defect 8: every lease must carry an expiry.
    if policy.get("require_expiry") is not True:
        problems.append("lease_never_expires")

    # Defect 5/8: revocation must always propagate.
    if policy.get("propagate_revocation") is not True:
        problems.append("revocation_not_propagated")

    # Defect 6/8: scope must always be enforced (exactly).
    if policy.get("enforce_scope") is not True:
        problems.append("scope_not_restricted")

    # Defect 8: max_ttl must be a real integer within 1..3600.
    max_ttl = policy.get("max_ttl")
    if not isinstance(max_ttl, int) or isinstance(max_ttl, bool):
        problems.append("max_ttl_invalid")
    elif max_ttl > 3600:
        problems.append("max_ttl_exceeds_limit")
    elif max_ttl < 1:
        problems.append("max_ttl_invalid")

    return problems


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
    problems = validate_policy(policy)
    if problems:
        raise ValueError("invalid policy: " + ", ".join(problems))

    max_ttl = policy["max_ttl"]
    results = []
    issued = 0
    failed = 0

    for index, request in enumerate(requests):
        try:
            ttl = request["ttl"]
            if not _is_positive_int(ttl):
                raise ValueError("ttl must be a positive integer")
            if ttl > max_ttl:
                raise ValueError("ttl exceeds policy max_ttl")

            # Defect 9: each request issues its own fresh lease; nothing is
            # carried over from a previous request.
            lease = issue_lease(
                request["store"],
                request["actor"],
                request["secret_id"],
                ttl,
                now,
            )
        except (KeyError, PermissionError, ValueError) as exc:
            results.append(
                {
                    "index": index,
                    "ok": False,
                    "error": str(exc) or type(exc).__name__,
                }
            )
            failed += 1
        else:
            results.append({"index": index, "ok": True, "lease": lease})
            issued += 1

    return {"results": results, "issued": issued, "failed": failed}
