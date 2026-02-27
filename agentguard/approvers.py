from __future__ import annotations
import abc
import asyncio
import json
import os
from typing import Optional
from .policy import RiskLevel


RISK_COLORS = {
    RiskLevel.SAFE: "\033[92m",    # green
    RiskLevel.MEDIUM: "\033[93m",  # yellow
    RiskLevel.HIGH: "\033[91m",    # red
}
RESET = "\033[0m"


class Approver(abc.ABC):
    """Base class for all approvers."""

    @abc.abstractmethod
    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        """Block and return True if approved, False if denied."""
        ...

    async def request_async(self, context: dict, risk: RiskLevel) -> bool:
        """Async version. Defaults to running sync version in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.request_sync, context, risk)


class CLIApprover(Approver):
    """
    Prints action details to stdout and waits for terminal input.
    Default approver — works with zero configuration.
    """

    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        color = RISK_COLORS.get(risk, "")
        print(f"\n{'='*60}")
        print(f"{color}[AgentGuard] ⚠️  APPROVAL REQUIRED [{risk.value.upper()}]{RESET}")
        print(f"{'='*60}")
        print(f"  Function : {context['function']}")
        print(f"  Params   : {json.dumps(context['params'], indent=4, default=str)}")
        if context.get("reason"):
            print(f"  Reason   : {context['reason']}")
        print(f"{'='*60}")

        while True:
            answer = input("  Allow this action? [y/N]: ").strip().lower()
            if answer in ("y", "yes"):
                print(f"  ✅ Approved\n")
                return True
            elif answer in ("", "n", "no"):
                print(f"  ❌ Denied\n")
                return False
            else:
                print("  Please enter y or n.")


class AutoApprover(Approver):
    """
    Automatically approves everything. Use in tests or trusted environments.
    """

    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        return True


class AutoDenyApprover(Approver):
    """
    Automatically denies everything. Useful for dry-run testing.
    """

    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        return False


class SlackApprover(Approver):
    """
    Sends an approval request to a Slack channel via webhook and
    polls for a response. Requires AGENTGUARD_SLACK_WEBHOOK env var.

    For production use, pair with a Slack app that posts back
    approve/deny to your endpoint.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        timeout_seconds: int = 300,
    ):
        self.webhook_url = webhook_url or os.environ.get("AGENTGUARD_SLACK_WEBHOOK")
        self.timeout_seconds = timeout_seconds

        if not self.webhook_url:
            raise ValueError(
                "SlackApprover requires a webhook URL. "
                "Pass it directly or set AGENTGUARD_SLACK_WEBHOOK."
            )

    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        try:
            import httpx
        except ImportError:
            raise ImportError("SlackApprover requires httpx: pip install httpx")

        emoji = "🔴" if risk == RiskLevel.HIGH else "🟡"
        text = (
            f"{emoji} *AgentGuard Approval Required* [{risk.value.upper()}]\n"
            f"*Function:* `{context['function']}`\n"
            f"*Params:* ```{json.dumps(context['params'], indent=2, default=str)}```\n"
            f"*Reason:* {context.get('reason', 'N/A')}\n\n"
            f"Reply with *approve* or *deny* in this thread."
        )

        response = httpx.post(self.webhook_url, json={"text": text})
        response.raise_for_status()

        # In a real integration, poll your own endpoint or use Slack's
        # interactive components. For now, fall back to CLI after notifying.
        print(f"\n[AgentGuard] Slack notification sent. Falling back to CLI approval.")
        fallback = CLIApprover()
        return fallback.request_sync(context, risk)


class WebhookApprover(Approver):
    """
    POSTs action details to a custom webhook URL and expects a JSON response
    with {"approved": true/false}. Useful for integrating with your own
    approval UI or workflow system.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        headers: Optional[dict] = None,
        timeout_seconds: int = 300,
    ):
        self.url = url or os.environ.get("AGENTGUARD_WEBHOOK_URL")
        self.headers = headers or {}
        self.timeout_seconds = timeout_seconds

        if not self.url:
            raise ValueError(
                "WebhookApprover requires a URL. "
                "Pass it directly or set AGENTGUARD_WEBHOOK_URL."
            )

    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        try:
            import httpx
        except ImportError:
            raise ImportError("WebhookApprover requires httpx: pip install httpx")

        payload = {
            "function": context["function"],
            "params": context["params"],
            "risk": risk.value,
            "reason": context.get("reason"),
        }

        response = httpx.post(
            self.url,
            json=payload,
            headers=self.headers,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        data = response.json()
        return bool(data.get("approved", False))
