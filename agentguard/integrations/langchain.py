"""
AgentGuard integration for LangChain tools.

Usage:
    from agentguard.integrations.langchain import GuardedTool
    from agentguard import Guard, Policy
    from langchain.tools import tool

    guard = Guard(policy=Policy.default())

    @tool
    def delete_user(user_id: str) -> str:
        \"\"\"Delete a user from the database.\"\"\"
        return f"Deleted user {user_id}"

    safe_tool = GuardedTool.from_langchain(delete_user, guard=guard)
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from ..guard import Guard
from ..policy import RiskLevel

if TYPE_CHECKING:
    pass


class GuardedTool:
    """Wraps a LangChain tool with AgentGuard approval gates."""

    @staticmethod
    def from_langchain(tool, guard: Guard, risk: str = None, reason: str = None):
        """
        Wrap a LangChain @tool with an approval gate.

        Args:
            tool: A LangChain BaseTool instance
            guard: An AgentGuard Guard instance
            risk: Optional risk override ("safe", "medium", "high")
            reason: Optional human-readable reason for the approval prompt

        Returns:
            A new tool with the same name/description but gated execution.
        """
        try:
            from langchain.tools import StructuredTool
        except ImportError:
            raise ImportError(
                "LangChain integration requires langchain: pip install langchain"
            )

        original_func = tool.func if hasattr(tool, "func") else tool._run

        guarded_func = guard.watch(original_func, risk=risk, reason=reason or tool.description)

        return StructuredTool(
            name=tool.name,
            description=tool.description,
            func=guarded_func,
            args_schema=tool.args_schema if hasattr(tool, "args_schema") else None,
        )

    @staticmethod
    def wrap_toolkit(tools: list, guard: Guard) -> list:
        """
        Wrap an entire list of LangChain tools with AgentGuard.
        Risk levels are inferred automatically by policy.
        """
        return [GuardedTool.from_langchain(t, guard=guard) for t in tools]
