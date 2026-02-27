import functools
import inspect
import asyncio
from typing import Callable, Optional, Any
from .policy import Policy, RiskLevel
from .approvers import Approver, CLIApprover
from .exceptions import ActionBlockedError, ApprovalDeniedError


class Guard:
    """
    Wraps any callable (agent tool) and enforces policy-based approval gates
    before execution. Safe actions pass through. Destructive actions block
    until a human approves — via CLI, Slack, webhook, or custom approver.

    Usage:
        guard = Guard(policy=Policy.default())

        @guard.watch
        def delete_record(table: str, id: int):
            ...

        @guard.watch(risk="high", reason="Wipes entire table")
        def truncate_table(table: str):
            ...
    """

    def __init__(
        self,
        policy: Optional[Policy] = None,
        approver: Optional[Approver] = None,
        dry_run: bool = False,
    ):
        self.policy = policy or Policy.default()
        self.approver = approver or CLIApprover()
        self.dry_run = dry_run
        self._audit_log: list[dict] = []

    # ------------------------------------------------------------------
    # Decorator
    # ------------------------------------------------------------------

    def watch(self, fn: Optional[Callable] = None, *, risk: Optional[str] = None, reason: Optional[str] = None):
        """
        Decorator. Can be used as:
            @guard.watch
            @guard.watch()
            @guard.watch(risk="high", reason="...")
        """
        if fn is None:
            # Called with args: @guard.watch(risk="high")
            def decorator(f):
                return self._wrap(f, risk=risk, reason=reason)
            return decorator

        # Called bare: @guard.watch
        return self._wrap(fn, risk=risk, reason=reason)

    def _wrap(self, fn: Callable, risk: Optional[str], reason: Optional[str]):
        policy = self.policy
        approver = self.approver
        guard = self

        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                return await guard._execute_async(fn, args, kwargs, risk, reason)
            return async_wrapper
        else:
            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                return guard._execute_sync(fn, args, kwargs, risk, reason)
            return sync_wrapper

    # ------------------------------------------------------------------
    # Execution logic
    # ------------------------------------------------------------------

    def _assess(self, fn: Callable, args, kwargs, override_risk: Optional[str]) -> RiskLevel:
        """Determine risk level for this call."""
        if override_risk:
            return RiskLevel(override_risk)
        return self.policy.assess(fn, args, kwargs)

    def _build_context(self, fn: Callable, args, kwargs, reason: Optional[str]) -> dict:
        sig = inspect.signature(fn)
        try:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            params = dict(bound.arguments)
        except Exception:
            params = {"args": args, "kwargs": kwargs}

        return {
            "function": fn.__name__,
            "module": fn.__module__,
            "params": params,
            "reason": reason or fn.__doc__ or "No description provided.",
        }

    def _record(self, context: dict, risk: RiskLevel, approved: bool, result: Any = None):
        self._audit_log.append({
            "function": context["function"],
            "params": context["params"],
            "risk": risk.value,
            "approved": approved,
            "result": str(result) if result is not None else None,
        })

    def _execute_sync(self, fn, args, kwargs, override_risk, reason):
        risk = self._assess(fn, args, kwargs, override_risk)
        context = self._build_context(fn, args, kwargs, reason)

        if risk == RiskLevel.SAFE:
            result = fn(*args, **kwargs)
            self._record(context, risk, True, result)
            return result

        if self.dry_run:
            print(f"[AgentGuard DRY RUN] Would block: {fn.__name__} (risk={risk.value})")
            return None

        approved = self.approver.request_sync(context, risk)

        if not approved:
            self._record(context, risk, False)
            raise ApprovalDeniedError(
                f"Action '{fn.__name__}' was denied by approver."
            )

        self._record(context, risk, True)
        return fn(*args, **kwargs)

    async def _execute_async(self, fn, args, kwargs, override_risk, reason):
        risk = self._assess(fn, args, kwargs, override_risk)
        context = self._build_context(fn, args, kwargs, reason)

        if risk == RiskLevel.SAFE:
            result = await fn(*args, **kwargs)
            self._record(context, risk, True, result)
            return result

        if self.dry_run:
            print(f"[AgentGuard DRY RUN] Would block: {fn.__name__} (risk={risk.value})")
            return None

        approved = await self.approver.request_async(context, risk)

        if not approved:
            self._record(context, risk, False)
            raise ApprovalDeniedError(
                f"Action '{fn.__name__}' was denied by approver."
            )

        self._record(context, risk, True)
        return await fn(*args, **kwargs)

    # ------------------------------------------------------------------
    # Audit
    # ------------------------------------------------------------------

    @property
    def audit(self) -> list[dict]:
        """Full audit log of all watched calls."""
        return self._audit_log

    def clear_audit(self):
        self._audit_log.clear()
