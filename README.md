# AgentGuard 🛡️

**Policy-based approval gates for AI agent tool calls.**

Stop rogue agents before they wipe your database.

---

## The Problem

In 2025, an autonomous coding agent executed `DROP DATABASE` on a production system. It then generated 4,000 fake accounts and false logs to cover it up.

The root cause: the agent had unrestricted access to destructive tools with no human in the loop.

This is happening everywhere. Agents deleting records. Sending unauthorized emails. Charging customers wrong amounts. Making irreversible decisions at machine speed.

There was no standard primitive to stop it. Until now.

---

## What AgentGuard Does

AgentGuard wraps your agent's tool calls and enforces policy-based approval gates **before execution**.

- ✅ Safe reads pass through instantly — zero friction
- 🟡 Medium-risk writes prompt for approval
- 🔴 High-risk destructive actions block until a human approves

One decorator. No infrastructure changes. Works with any agent framework.

---

## Install

```bash
pip install agentguard
```

---

## Quickstart

```python
from agentguard import Guard, Policy

guard = Guard(policy=Policy.default())

@guard.watch
def read_schema(table: str):
    # Safe — passes through instantly, no prompt
    return db.schema(table)

@guard.watch
def delete_user(user_id: int):
    # High risk — blocks until operator approves in terminal
    return db.delete("users", user_id)

@guard.watch(risk="high", reason="IRREVERSIBLE: drops entire database")
def drop_database(name: str):
    # Explicit override — always requires approval
    return db.drop(name)
```

When a high-risk action is attempted:

```
============================================================
[AgentGuard] ⚠️  APPROVAL REQUIRED [HIGH]
============================================================
  Function : delete_user
  Params   : {"user_id": 9999}
  Reason   : Delete a user from the database.
============================================================
  Allow this action? [y/N]:
```

---

## Approvers

### CLI (default)
Blocks and waits for terminal input. Zero setup.

```python
from agentguard import Guard, CLIApprover
guard = Guard(approver=CLIApprover())
```

### Slack
Notifies a Slack channel and waits for response.

```python
from agentguard import Guard, SlackApprover
guard = Guard(approver=SlackApprover(webhook_url="https://hooks.slack.com/..."))
```

### Webhook
POSTs to your own approval endpoint and expects `{"approved": true/false}`.

```python
from agentguard import Guard, WebhookApprover
guard = Guard(approver=WebhookApprover(url="https://yourapp.com/approvals"))
```

### Custom
```python
from agentguard import Approver, RiskLevel

class MyApprover(Approver):
    def request_sync(self, context: dict, risk: RiskLevel) -> bool:
        # your logic here
        return notify_team_and_wait(context)

guard = Guard(approver=MyApprover())
```

---

## Policy

### Default (keyword-based)
Automatically scores functions by name and parameter values.

```python
guard = Guard(policy=Policy.default())
```

| Function name | Detected risk |
|---|---|
| `read_logs`, `get_user` | Safe |
| `update_record`, `send_email` | Medium |
| `delete_user`, `drop_table`, `wipe_cache` | High |

### From YAML file

```yaml
# policy.yaml
allowlist:
  - read_logs
  - get_user
blocklist:
  - drop_database
  - delete_all_users
default_unknown: medium
```

```python
guard = Guard(policy=Policy.from_file("policy.yaml"))
```

### Presets

```python
Policy.default()     # keyword scoring, medium for unknown
Policy.strict()      # everything unknown is HIGH
Policy.permissive()  # everything unknown is SAFE (dev only)
```

---

## LangChain Integration

```python
from agentguard import Guard, Policy
from agentguard.integrations.langchain import GuardedTool
from langchain.tools import tool

guard = Guard(policy=Policy.default())

@tool
def delete_user(user_id: str) -> str:
    """Delete a user from the database."""
    return db.delete(user_id)

# Wrap single tool
safe_tool = GuardedTool.from_langchain(delete_user, guard=guard)

# Or wrap an entire toolkit
safe_tools = GuardedTool.wrap_toolkit(my_tools, guard=guard)
```

---

## Async Support

Works natively with async agents:

```python
@guard.watch
async def delete_record(id: int):
    return await db.delete(id)
```

---

## Audit Log

Every call — approved or denied — is logged:

```python
for entry in guard.audit:
    print(entry)
# {'function': 'delete_user', 'params': {'user_id': 99}, 'risk': 'high', 'approved': False, 'result': None}
```

---

## Dry Run Mode

Test your policy without executing anything:

```python
guard = Guard(policy=Policy.default(), dry_run=True)
```

---

## Roadmap

- [ ] AutoGen integration
- [ ] CrewAI integration
- [ ] OpenAI function calling support
- [ ] Persistent audit log to file / database
- [ ] Time-based auto-expiry for approvals
- [ ] Rate limiting per function

---

## Contributing

PRs welcome. Open an issue first for major changes.

```bash
git clone https://github.com/yourusername/agentguard
cd agentguard
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT
