"""
Example: Rogue agent simulation.

This is the scenario that inspired AgentGuard:
An AI coding agent executing DROP DATABASE on production.

Run this to see AgentGuard in action:
    python examples/rogue_agent.py
"""

from agentguard import Guard, Policy, CLIApprover
from agentguard.exceptions import ApprovalDeniedError


# --- Simulated database tools an agent might use ---

guard = Guard(
    policy=Policy.default(),
    approver=CLIApprover(),  # swap for SlackApprover or WebhookApprover in prod
)


@guard.watch
def read_schema(table: str) -> dict:
    """Read table schema — safe, passes through instantly."""
    return {"table": table, "columns": ["id", "name", "email"]}


@guard.watch
def insert_user(name: str, email: str) -> str:
    """Insert a new user into the database."""
    return f"Inserted user {name}"


@guard.watch
def delete_user(user_id: int) -> str:
    """Delete a user from the database."""
    return f"Deleted user {user_id}"


@guard.watch(risk="high", reason="IRREVERSIBLE: drops entire table and all data.")
def drop_table(table_name: str) -> str:
    """Drop a table from the database — cannot be undone."""
    return f"Table {table_name} dropped."


@guard.watch(risk="high", reason="CRITICAL: wipes entire production database.")
def drop_database(db_name: str) -> str:
    """Drop the entire database. This is what the rogue agent tried to do."""
    return f"Database {db_name} destroyed."


# --- Simulate an agent running a series of actions ---

if __name__ == "__main__":
    print("\n🤖 Agent starting task: 'Clean up old test data'\n")

    # Safe — no prompt
    schema = read_schema("users")
    print(f"✅ read_schema passed through: {schema}\n")

    # Medium risk — approval prompt
    print("Agent wants to insert a record...")
    try:
        result = insert_user("Test User", "test@example.com")
        print(f"Result: {result}\n")
    except ApprovalDeniedError:
        print("❌ insert_user denied by operator.\n")

    # High risk — approval prompt
    print("Agent wants to delete a user...")
    try:
        result = delete_user(9999)
        print(f"Result: {result}\n")
    except ApprovalDeniedError:
        print("❌ delete_user denied by operator.\n")

    # Critical — approval prompt — THIS is the one that wiped production
    print("Agent wants to drop the production database...")
    try:
        result = drop_database("production")
        print(f"Result: {result}\n")
    except ApprovalDeniedError:
        print("🛡️  drop_database BLOCKED. Production saved.\n")

    print("\n📋 Audit log:")
    for entry in guard.audit:
        status = "✅" if entry["approved"] else "❌"
        print(f"  {status} {entry['function']} | risk={entry['risk']} | approved={entry['approved']}")
