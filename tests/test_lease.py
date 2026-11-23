import pytest

from vault import (
    check_scope,
    issue_lease,
    lease_batch,
    read_secret,
    revoke_actor,
    revoke_secret,
    rotate_secret,
    validate_policy,
)


POLICY = {
    "require_expiry": True,
    "propagate_revocation": True,
    "enforce_scope": True,
    "max_ttl": 3600,
}


def _store():
    return {
        "secrets": {
            "db-prod": {
                "secret_id": "db-prod",
                "scope": "infra",
                "material": "db-v1",
                "version": 1,
            },
            "api-prod": {
                "secret_id": "api-prod",
                "scope": "edge",
                "material": "api-v1",
                "version": 1,
            },
            "payroll": {
                "secret_id": "payroll",
                "scope": "finance",
                "material": "pay-v1",
                "version": 1,
            },
        },
        "leases": {},
        "revoked_actors": set(),
        "revoked_secrets": set(),
        "revoked_leases": set(),
        "audit": [],
        "next_lease_no": 1,
        "caller": "alice",
    }


def _issue(store, actor, secret_id, ttl=60, now=1000):
    store["caller"] = actor
    return issue_lease(store, actor, secret_id, ttl, now)


def _read_as(store, actor, lease_id, now):
    store["caller"] = actor
    return read_secret(store, lease_id, now)


def _batch_request(store, actor, secret_id, ttl=60):
    return {
        "store": store,
        "actor": actor,
        "secret_id": secret_id,
        "ttl": ttl,
    }


def _assert_denied(store, lease_id, now, reason=None, actor=None):
    if actor is not None:
        store["caller"] = actor
    before = len(store["audit"])
    with pytest.raises(PermissionError):
        read_secret(store, lease_id, now)
    assert len(store["audit"]) == before + 1
    event = store["audit"][-1]
    assert event["event"] == "secret.read"
    assert event["decision"] == "deny"
    assert event["at"] == now
    if reason is not None:
        assert event["reason"] == reason


def test_defect_01_lease_must_carry_hard_expiry():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=60, now=1000)

    assert lease["issued_at"] == 1000
    assert lease["ttl"] == 60
    assert lease["expires_at"] == 1060
    assert lease["revoked"] is False
    assert store["leases"][lease["lease_id"]]["expires_at"] == 1060


def test_defect_02_lease_is_bound_to_actor():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=60, now=1000)

    store["caller"] = "bob"
    _assert_denied(store, lease["lease_id"], 1001, reason="actor_mismatch")
    assert _read_as(store, "alice", lease["lease_id"], 1001)["material"] == "db-v1"


def test_defect_03_read_consults_revocation_list():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=60, now=1000)

    store["revoked_leases"].add(lease["lease_id"])
    assert store["leases"][lease["lease_id"]]["revoked"] is False
    _assert_denied(
        store,
        lease["lease_id"],
        1001,
        reason="revoked",
        actor="alice",
    )


def test_defect_04_revoke_actor_revokes_all_actor_leases():
    store = _store()
    first = _issue(store, "alice", "db-prod", ttl=300, now=1000)
    second = _issue(store, "alice", "api-prod", ttl=300, now=1000)
    other = _issue(store, "bob", "db-prod", ttl=300, now=1000)

    assert revoke_actor(store, "alice", 1100) == 2
    _assert_denied(store, first["lease_id"], 1101, reason="revoked", actor="alice")
    _assert_denied(store, second["lease_id"], 1101, reason="revoked", actor="alice")
    assert _read_as(store, "bob", other["lease_id"], 1101)["material"] == "db-v1"
    with pytest.raises(PermissionError):
        issue_lease(store, "alice", "payroll", 60, 1102)


def test_defect_05_revoke_secret_propagates_to_issued_leases():
    store = _store()
    first = _issue(store, "alice", "db-prod", ttl=300, now=1000)
    second = _issue(store, "bob", "db-prod", ttl=300, now=1000)

    assert revoke_secret(store, "db-prod", 1200) == 2
    _assert_denied(store, first["lease_id"], 1201, reason="revoked", actor="alice")
    _assert_denied(store, second["lease_id"], 1201, reason="revoked", actor="bob")
    with pytest.raises(PermissionError):
        issue_lease(store, "alice", "db-prod", 60, 1202)


def test_defect_06_scope_check_is_not_prefix_match():
    assert check_scope({"scope": "prod"}, {"scope": "prod"}) is True
    assert check_scope({"scope": "prod"}, {"scope": "production"}) is False
    assert check_scope({"scope": "prod"}, {"scope": "prod:payments"}) is False
    assert check_scope({"scope": "prod-eu"}, {"scope": "prod"}) is False
    assert check_scope({"scope": "Prod"}, {"scope": "prod"}) is False


def test_defect_07_rotation_invalidates_old_leases():
    store = _store()
    old = _issue(store, "alice", "db-prod", ttl=300, now=1000)

    rotated = rotate_secret(store, "db-prod", "db-v2", 1100)
    assert rotated["secret_id"] == "db-prod"
    assert rotated["version"] == 2
    assert rotated["material"] == "db-v2"
    assert rotated["revoked_leases"] == 1
    _assert_denied(store, old["lease_id"], 1101, actor="alice")

    fresh = _issue(store, "alice", "db-prod", ttl=60, now=1102)
    assert fresh["version"] == 2
    assert _read_as(store, "alice", fresh["lease_id"], 1103)["material"] == "db-v2"


def test_defect_08_policy_rejects_ttl_over_limit():
    assert validate_policy(dict(POLICY)) == []

    too_long = dict(POLICY)
    too_long["max_ttl"] = 3601
    assert validate_policy(too_long) == ["max_ttl_exceeds_limit"]

    missing = dict(POLICY)
    del missing["max_ttl"]
    assert "max_ttl_invalid" in validate_policy(missing)


def test_defect_09_batch_does_not_reuse_lease():
    store = _store()
    batch = lease_batch(
        [
            _batch_request(store, "alice", "db-prod", ttl=120),
            _batch_request(store, "bob", "api-prod", ttl=120),
        ],
        POLICY,
        1300,
    )

    assert batch["issued"] == 2
    assert batch["failed"] == 0
    first = batch["results"][0]
    second = batch["results"][1]
    assert first["ok"] is True
    assert second["ok"] is True
    assert first["lease"]["lease_id"] != second["lease"]["lease_id"]
    assert first["lease"]["secret_id"] == "db-prod"
    assert second["lease"]["secret_id"] == "api-prod"
    assert first["lease"]["actor"] == "alice"
    assert second["lease"]["actor"] == "bob"
    assert _read_as(store, "alice", first["lease"]["lease_id"], 1301)["material"] == "db-v1"
    assert _read_as(store, "bob", second["lease"]["lease_id"], 1301)["material"] == "api-v1"


def test_defect_10_read_appends_audit_event():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=60, now=1000)

    assert _read_as(store, "alice", lease["lease_id"], 1001)["material"] == "db-v1"
    allowed = store["audit"][-1]
    assert allowed["event"] == "secret.read"
    assert allowed["decision"] == "allow"
    assert allowed["actor"] == "alice"
    assert allowed["secret_id"] == "db-prod"
    assert allowed["lease_id"] == lease["lease_id"]
    assert allowed["at"] == 1001

    store["revoked_leases"].add(lease["lease_id"])
    _assert_denied(store, lease["lease_id"], 1002, reason="revoked", actor="alice")
    denied = store["audit"][-1]
    assert denied["event"] == "secret.read"
    assert denied["decision"] == "deny"
    assert denied["actor"] == "alice"
    assert denied["secret_id"] == "db-prod"
    assert denied["lease_id"] == lease["lease_id"]
    assert denied["at"] == 1002
    assert denied["reason"] == "revoked"


def test_issue_and_read_roundtrip():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=120, now=500)

    assert lease["actor"] == "alice"
    assert lease["secret_id"] == "db-prod"
    assert lease["scope"] == "infra"
    assert lease["expires_at"] == 620

    secret = _read_as(store, "alice", lease["lease_id"], 500)
    assert secret["secret_id"] == "db-prod"
    assert secret["scope"] == "infra"
    assert secret["material"] == "db-v1"
    assert secret["version"] == 1


def test_expired_lease_is_rejected_at_boundary():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=30, now=2000)

    assert _read_as(store, "alice", lease["lease_id"], 2029)["material"] == "db-v1"
    _assert_denied(store, lease["lease_id"], 2030, reason="expired", actor="alice")


def test_revoked_lease_is_rejected():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=60, now=1000)

    assert revoke_actor(store, "alice", 1001) == 1
    _assert_denied(store, lease["lease_id"], 1002, reason="revoked", actor="alice")


def test_scope_mismatch_is_rejected():
    store = _store()
    lease = _issue(store, "alice", "db-prod", ttl=60, now=1000)

    store["secrets"]["db-prod"]["scope"] = "staging"
    _assert_denied(store, lease["lease_id"], 1001, reason="scope_mismatch", actor="alice")


def test_batch_matches_individual_processing():
    def requests_for(store):
        return [
            _batch_request(store, "alice", "db-prod"),
            _batch_request(store, "bob", "missing-secret"),
            _batch_request(store, "alice", "api-prod"),
        ]

    first_store = _store()
    first_batch = lease_batch(requests_for(first_store), POLICY, 2000)
    second_store = _store()
    second_batch = lease_batch(requests_for(second_store), POLICY, 2000)

    for batch in (first_batch, second_batch):
        assert batch["issued"] == 2
        assert batch["failed"] == 1
        assert len(batch["results"]) == 3
        assert batch["results"][0]["ok"] is True
        assert batch["results"][1]["ok"] is False
        assert batch["results"][2]["ok"] is True

    single_store = _store()
    first = _issue(single_store, "alice", "db-prod", ttl=60, now=2000)
    with pytest.raises(KeyError):
        issue_lease(single_store, "bob", "missing-secret", 60, 2000)
    third = _issue(single_store, "alice", "api-prod", ttl=60, now=2000)

    for batch, batch_store in ((first_batch, first_store), (second_batch, second_store)):
        for result, single in ((batch["results"][0], first), (batch["results"][2], third)):
            lease = result["lease"]
            for field in ("actor", "secret_id", "scope", "issued_at", "expires_at", "ttl", "version"):
                assert lease[field] == single[field]
            assert (
                _read_as(batch_store, lease["actor"], lease["lease_id"], 2001)["material"]
                == _read_as(single_store, single["actor"], single["lease_id"], 2001)["material"]
            )
