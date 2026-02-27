import pytest
from agentguard import Guard, Policy, RiskLevel, AutoApprover, AutoDenyApprover
from agentguard.exceptions import ApprovalDeniedError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_guard(approve=True, policy=None):
    approver = AutoApprover() if approve else AutoDenyApprover()
    return Guard(policy=policy or Policy.default(), approver=approver)


# ---------------------------------------------------------------------------
# Policy tests
# ---------------------------------------------------------------------------

def test_policy_detects_high_risk_by_name():
    policy = Policy.default()
    risk = policy.assess(lambda: None, (), {})
    # anonymous lambda name is '<lambda>' — unknown, should be MEDIUM
    assert risk == RiskLevel.MEDIUM


def test_policy_detects_delete():
    policy = Policy.default()

    def delete_user(): pass
    assert policy.assess(delete_user, (), {}) == RiskLevel.HIGH


def test_policy_detects_drop():
    policy = Policy.default()

    def drop_table(): pass
    assert policy.assess(drop_table, (), {}) == RiskLevel.HIGH


def test_policy_detects_write():
    policy = Policy.default()

    def write_file(): pass
    assert policy.assess(write_file, (), {}) == RiskLevel.MEDIUM


def test_policy_allowlist():
    policy = Policy(allowlist=["delete_user"])

    def delete_user(): pass
    assert policy.assess(delete_user, (), {}) == RiskLevel.SAFE


def test_policy_blocklist():
    policy = Policy(blocklist=["read_logs"])

    def read_logs(): pass
    assert policy.assess(read_logs, (), {}) == RiskLevel.HIGH


def test_policy_strict_unknown():
    policy = Policy.strict()

    def get_user(): pass
    assert policy.assess(get_user, (), {}) == RiskLevel.HIGH


def test_policy_permissive_unknown():
    policy = Policy.permissive()

    def get_user(): pass
    assert policy.assess(get_user, (), {}) == RiskLevel.SAFE


# ---------------------------------------------------------------------------
# Guard decorator tests
# ---------------------------------------------------------------------------

def test_safe_function_passes_through():
    guard = make_guard(approve=True, policy=Policy(allowlist=["read_data"]))

    @guard.watch
    def read_data():
        return "data"

    assert read_data() == "data"


def test_high_risk_approved():
    guard = make_guard(approve=True)

    @guard.watch
    def delete_record(id: int):
        return f"deleted {id}"

    result = delete_record(42)
    assert result == "deleted 42"


def test_high_risk_denied_raises():
    guard = make_guard(approve=False)

    @guard.watch
    def delete_record(id: int):
        return f"deleted {id}"

    with pytest.raises(ApprovalDeniedError):
        delete_record(42)


def test_risk_override():
    guard = make_guard(approve=True)

    @guard.watch(risk="high")
    def innocent_function():
        return "ran"

    result = innocent_function()
    assert result == "ran"


def test_audit_log_populated():
    guard = make_guard(approve=True)

    @guard.watch
    def delete_user(user_id: str):
        return "done"

    delete_user("abc123")
    assert len(guard.audit) == 1
    assert guard.audit[0]["function"] == "delete_user"
    assert guard.audit[0]["approved"] is True


def test_audit_log_denied():
    guard = make_guard(approve=False)

    @guard.watch
    def delete_user(user_id: str):
        return "done"

    with pytest.raises(ApprovalDeniedError):
        delete_user("abc123")

    assert guard.audit[0]["approved"] is False


def test_dry_run_does_not_execute():
    guard = Guard(policy=Policy.default(), dry_run=True)
    executed = []

    @guard.watch
    def delete_everything():
        executed.append(True)

    guard.watch(lambda: None)
    result = delete_everything()
    assert result is None
    assert len(executed) == 0


@pytest.mark.asyncio
async def test_async_function_approved():
    guard = make_guard(approve=True)

    @guard.watch
    async def delete_async(id: int):
        return f"async deleted {id}"

    result = await delete_async(99)
    assert result == "async deleted 99"


@pytest.mark.asyncio
async def test_async_function_denied():
    guard = make_guard(approve=False)

    @guard.watch
    async def delete_async(id: int):
        return f"async deleted {id}"

    with pytest.raises(ApprovalDeniedError):
        await delete_async(99)
