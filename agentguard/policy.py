from __future__ import annotations
import re
import yaml
from enum import Enum
from typing import Callable, Optional
from pathlib import Path


class RiskLevel(Enum):
    SAFE = "safe"
    MEDIUM = "medium"
    HIGH = "high"


# Keywords that signal destructive or high-stakes operations
HIGH_RISK_PATTERNS = [
    r"\bdrop\b", r"\bdelete\b", r"\bremove\b", r"\btruncate\b",
    r"\bdestroy\b", r"\bwipe\b", r"\bpurge\b", r"\bkill\b",
    r"\bban\b", r"\bshutdown\b", r"\bterminate\b", r"\bformat\b",
    r"\boverwrite\b", r"\breset\b", r"\brevoke\b", r"\bdisable\b",
]

MEDIUM_RISK_PATTERNS = [
    r"\bupdate\b", r"\bedit\b", r"\bmodify\b", r"\bpatch\b",
    r"\bwrite\b", r"\bsend\b", r"\bpost\b", r"\bpublish\b",
    r"\bcharge\b", r"\bpay\b", r"\btransfer\b", r"\bdeploy\b",
    r"\bcreate\b", r"\binsert\b", r"\badd\b",
]


def _score_name(name: str) -> Optional[RiskLevel]:
    """Score a function name by its keywords."""
    lower = name.lower().replace("_", " ")
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, lower):
            return RiskLevel.HIGH
    for pattern in MEDIUM_RISK_PATTERNS:
        if re.search(pattern, lower):
            return RiskLevel.MEDIUM
    return None


def _score_params(args, kwargs) -> Optional[RiskLevel]:
    """Scan parameter values for high-risk strings."""
    all_values = list(args) + list(kwargs.values())
    for val in all_values:
        if isinstance(val, str):
            lower = val.lower()
            for pattern in HIGH_RISK_PATTERNS:
                if re.search(pattern, lower):
                    return RiskLevel.HIGH
    return None


class Policy:
    """
    Determines the risk level of a function call.

    Priority order:
    1. Explicit overrides (allowlist / blocklist by function name)
    2. Keyword analysis of function name
    3. Keyword analysis of parameter values
    4. Default fallback level
    """

    def __init__(
        self,
        allowlist: Optional[list[str]] = None,
        blocklist: Optional[list[str]] = None,
        default_unknown: RiskLevel = RiskLevel.MEDIUM,
    ):
        self.allowlist = set(allowlist or [])
        self.blocklist = set(blocklist or [])
        self.default_unknown = default_unknown

    @classmethod
    def default(cls) -> "Policy":
        """Sensible defaults — keyword-based scoring, medium for unknown."""
        return cls()

    @classmethod
    def strict(cls) -> "Policy":
        """Everything unknown is treated as HIGH risk."""
        return cls(default_unknown=RiskLevel.HIGH)

    @classmethod
    def permissive(cls) -> "Policy":
        """Everything unknown is treated as SAFE — use in dev/testing only."""
        return cls(default_unknown=RiskLevel.SAFE)

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        """
        Load policy from a YAML file.

        Example policy.yaml:
            allowlist:
              - read_logs
              - get_user
            blocklist:
              - drop_database
              - delete_all_users
            default_unknown: medium
        """
        with open(path) as f:
            data = yaml.safe_load(f)

        return cls(
            allowlist=data.get("allowlist", []),
            blocklist=data.get("blocklist", []),
            default_unknown=RiskLevel(data.get("default_unknown", "medium")),
        )

    def assess(self, fn: Callable, args, kwargs) -> RiskLevel:
        name = fn.__name__

        if name in self.allowlist:
            return RiskLevel.SAFE

        if name in self.blocklist:
            return RiskLevel.HIGH

        # Keyword analysis
        name_risk = _score_name(name)
        if name_risk == RiskLevel.HIGH:
            return RiskLevel.HIGH

        param_risk = _score_params(args, kwargs)
        if param_risk == RiskLevel.HIGH:
            return RiskLevel.HIGH

        if name_risk == RiskLevel.MEDIUM or param_risk == RiskLevel.MEDIUM:
            return RiskLevel.MEDIUM

        return self.default_unknown
