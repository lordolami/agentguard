class AgentGuardError(Exception):
    """Base exception for AgentGuard."""


class ActionBlockedError(AgentGuardError):
    """Raised when an action is blocked by policy before approval is requested."""


class ApprovalDeniedError(AgentGuardError):
    """Raised when a human approver explicitly denies an action."""
