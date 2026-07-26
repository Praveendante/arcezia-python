"""
Tests for client/arcezia/integrations/ — the SaaS HTTP client wrappers.

All tests mock az.verify() because the client makes live HTTP calls.
The tests verify:
  - az.verify() is called with the correct action_type, action_description, domain
  - BLOCK raises the appropriate exception (RuntimeError / ToolException)
  - REVIEW raises the appropriate exception with missing constraints listed
  - ALLOW executes the underlying function and returns its result
  - Domain inference maps tool names to the correct domain
  - Fabrication flag is surfaced in error messages

Tests the HTTP client wrappers (importing from arcezia.*).
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

# Make the client package importable from this test file
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arcezia.client import Arcezia, ArceziaCertificate, ArceziaBlockError


# ── Certificate factories ──────────────────────────────────────────────────────

def _make_cert(
    verdict: str = "ALLOW",
    status: str = "ALLOWED",
    trust_score: float = 0.95,
    fabrication_detected: bool = False,
    fabricated_constraints: list | None = None,
    violated: list | None = None,
    missing: list | None = None,
    summary: str = "Action permitted.",
) -> ArceziaCertificate:
    return ArceziaCertificate(
        verdict=verdict,
        status=status,
        precondition_score=0.9,
        trust_score=trust_score,
        summary=summary,
        violated=violated or [],
        missing=missing or [],
        fabrication_detected=fabrication_detected,
        fabricated_constraints=fabricated_constraints or [],
        constraints=[],
        signature="fakesig",
        credential={"token": "cred_xyz"} if verdict == "ALLOW" else None,
    )


def _allow() -> ArceziaCertificate:
    return _make_cert(verdict="ALLOW", status="ALLOWED")


def _block(violated: list | None = None, fabricated: bool = False) -> ArceziaCertificate:
    return _make_cert(
        verdict="BLOCK",
        status="BLOCKED",
        trust_score=0.1,
        fabrication_detected=fabricated,
        fabricated_constraints=["action_within_task_scope"] if fabricated else [],
        violated=violated or ["no_unsafe_operations"],
        summary="Action blocked: unsafe SQL detected.",
    )


def _review(missing: list | None = None) -> ArceziaCertificate:
    return _make_cert(
        verdict="REVIEW",
        status="INSUFFICIENT_EVIDENCE",
        trust_score=0.5,
        missing=missing or ["user_explicit_authorization"],
        summary="Human confirmation required.",
    )


def _fake_az(cert: ArceziaCertificate) -> MagicMock:
    """Return a mock Arcezia instance whose verify() returns cert."""
    az = MagicMock(spec=Arcezia)
    az.verify.return_value = cert
    return az


# ── AutoGen integration ────────────────────────────────────────────────────────

class TestAutoGenGuard(unittest.TestCase):

    def _guard(self, cert):
        from arcezia.integrations.autogen import ArceziaAutoGenGuard
        az = _fake_az(cert)
        return ArceziaAutoGenGuard(az), az

    def test_allow_calls_original_function(self):
        guard, az = self._guard(_allow())
        fn = MagicMock(return_value="ok")
        safe = guard.wrap("execute_sql", fn, domain="database_ops")
        result = safe(query="SELECT 1")
        self.assertEqual(result, "ok")
        fn.assert_called_once_with(query="SELECT 1")

    def test_allow_verify_receives_correct_args(self):
        guard, az = self._guard(_allow())
        fn = MagicMock(return_value="ok")
        safe = guard.wrap("execute_sql", fn, domain="database_ops")
        safe(query="SELECT 1")
        az.verify.assert_called_once()
        call_kwargs = az.verify.call_args.kwargs
        self.assertEqual(call_kwargs["action_type"], "execute_sql")
        self.assertEqual(call_kwargs["domain"], "database_ops")
        self.assertIn("SELECT 1", call_kwargs["action_description"])

    def test_block_raises_runtime_error(self):
        guard, _ = self._guard(_block())
        fn = MagicMock()
        safe = guard.wrap("execute_sql", fn, domain="database_ops")
        with self.assertRaises(RuntimeError) as ctx:
            safe(query="DROP TABLE users")
        self.assertIn("BLOCK", str(ctx.exception))
        fn.assert_not_called()

    def test_block_includes_violated_constraints(self):
        guard, _ = self._guard(_block(violated=["no_unsafe_operations"]))
        fn = MagicMock()
        safe = guard.wrap("execute_sql", fn, domain="database_ops")
        with self.assertRaises(RuntimeError) as ctx:
            safe(query="DROP TABLE users")
        self.assertIn("no_unsafe_operations", str(ctx.exception))

    def test_block_includes_fabrication_flag(self):
        guard, _ = self._guard(_block(fabricated=True))
        fn = MagicMock()
        safe = guard.wrap("execute_sql", fn, domain="database_ops")
        with self.assertRaises(RuntimeError) as ctx:
            safe(query="DROP TABLE users")
        self.assertIn("FABRICATION", str(ctx.exception))

    def test_review_raises_runtime_error(self):
        guard, _ = self._guard(_review(missing=["user_explicit_authorization"]))
        fn = MagicMock()
        safe = guard.wrap("send_email", fn, domain="agent_action")
        with self.assertRaises(RuntimeError) as ctx:
            safe(to="user@example.com")
        self.assertIn("REVIEW", str(ctx.exception))
        self.assertIn("user_explicit_authorization", str(ctx.exception))
        fn.assert_not_called()

    def test_domain_inferred_from_name(self):
        guard, az = self._guard(_allow())
        fn = MagicMock(return_value="ok")
        safe = guard.wrap("run_sql_query", fn)   # no domain arg
        safe("SELECT 1")
        call_kwargs = az.verify.call_args.kwargs
        self.assertEqual(call_kwargs["domain"], "database_ops")

    def test_wrap_many_returns_dict(self):
        guard, _ = self._guard(_allow())
        fns = [
            ("execute_sql", MagicMock(return_value="sql_ok"), "database_ops"),
            ("write_file",  MagicMock(return_value="file_ok"), "filesystem_ops"),
        ]
        wrapped = guard.wrap_many(fns)
        self.assertIn("execute_sql", wrapped)
        self.assertIn("write_file", wrapped)

    def test_async_allow_calls_coroutine(self):
        guard, az = self._guard(_allow())
        az.verify = MagicMock(return_value=_allow())

        async def _coro(query: str) -> str:
            return f"result:{query}"

        safe = guard.wrap_async("execute_sql", _coro, domain="database_ops")

        with patch("asyncio.to_thread", new=AsyncMock(return_value=_allow())):
            result = asyncio.run(
                safe(query="SELECT 1")
            )
        self.assertEqual(result, "result:SELECT 1")

    def test_async_block_raises(self):
        guard, _ = self._guard(_block())

        async def _coro(query: str) -> str:
            return "should not reach"

        safe = guard.wrap_async("execute_sql", _coro, domain="database_ops")

        with patch("asyncio.to_thread", new=AsyncMock(return_value=_block())):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(safe(query="DROP TABLE users"))
        self.assertIn("BLOCK", str(ctx.exception))

    def test_wrap_sync_as_async_calls_in_thread(self):
        guard, az = self._guard(_allow())

        def _sync_fn(query: str) -> str:
            return f"sync:{query}"

        safe = guard.wrap_sync_as_async("execute_sql", _sync_fn, domain="database_ops")

        verify_mock = AsyncMock(return_value=_allow())
        fn_mock = AsyncMock(return_value="sync:SELECT 1")
        with patch("asyncio.to_thread", side_effect=[_allow(), "sync:SELECT 1"]):
            result = asyncio.run(
                safe(query="SELECT 1")
            )
        # Function was called — result comes from the thread-pool call
        self.assertIsNotNone(result)


# ── LangChain integration ──────────────────────────────────────────────────────

_LANGCHAIN_AVAILABLE = True
try:
    from langchain.tools import BaseTool
    try:
        from langchain_core.tools.base import ToolException
    except ImportError:
        from langchain.tools.base import ToolException
except ImportError:
    _LANGCHAIN_AVAILABLE = False


@unittest.skipUnless(_LANGCHAIN_AVAILABLE, "langchain not installed")
class TestLangChainToolkit(unittest.TestCase):

    def _make_tool(self, name: str, return_value: str = "tool_result") -> "BaseTool":
        tool = MagicMock(spec=BaseTool)
        tool.name = name
        tool.description = f"A {name} tool"
        tool.run = MagicMock(return_value=return_value)
        return tool

    def test_allow_calls_underlying_tool(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool("execute_sql")
        az = _fake_az(_allow())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        result = wrapped.run("SELECT 1")
        tool.run.assert_called_once_with("SELECT 1")
        self.assertIn("tool_result", result)

    def test_allow_appends_trust_score(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool("execute_sql")
        az = _fake_az(_allow())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        result = wrapped.run("SELECT 1")
        self.assertIn("Arcezia ALLOW", result)
        self.assertIn("trust=", result)

    def test_block_raises_tool_exception(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool("execute_sql")
        az = _fake_az(_block())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        with self.assertRaises(ToolException) as ctx:
            wrapped.run("DROP TABLE users")
        self.assertIn("BLOCK", str(ctx.exception))
        tool.run.assert_not_called()

    def test_review_raises_tool_exception_with_missing(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool("send_email")
        az = _fake_az(_review(missing=["user_explicit_authorization"]))
        wrapped = ArceziaTool(tool, az, domain="agent_action")
        with self.assertRaises(ToolException) as ctx:
            wrapped.run("Send report")
        self.assertIn("REVIEW", str(ctx.exception))
        self.assertIn("user_explicit_authorization", str(ctx.exception))

    def test_block_does_not_call_original(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool("execute_sql")
        az = _fake_az(_block())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        with self.assertRaises(ToolException):
            wrapped.run("DROP TABLE users")
        tool.run.assert_not_called()

    def test_toolkit_wraps_multiple_tools(self):
        from arcezia.integrations.langchain import ArceziaToolkit, ArceziaTool
        az = _fake_az(_allow())
        toolkit = ArceziaToolkit(az)
        tools = [self._make_tool("execute_sql"), self._make_tool("write_file")]
        wrapped = toolkit.wrap(tools)
        self.assertEqual(len(wrapped), 2)
        self.assertIsInstance(wrapped[0], ArceziaTool)
        self.assertIsInstance(wrapped[1], ArceziaTool)

    def test_toolkit_domain_override(self):
        from arcezia.integrations.langchain import ArceziaToolkit
        az = _fake_az(_allow())
        toolkit = ArceziaToolkit(az)
        tool = self._make_tool("my_custom_tool")
        wrapped = toolkit.wrap([tool], domain_overrides={"my_custom_tool": "payment_ops"})
        wrapped[0].run("do something")
        call_kwargs = az.verify.call_args.kwargs
        self.assertEqual(call_kwargs["domain"], "payment_ops")

    def test_domain_inferred_from_tool_name(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool("shell_executor")
        az = _fake_az(_allow())
        wrapped = ArceziaTool(tool, az)   # no domain override
        wrapped.run("ls -la")
        call_kwargs = az.verify.call_args.kwargs
        self.assertEqual(call_kwargs["domain"], "filesystem_ops")


# ── OpenAI / CrewAI integration ───────────────────────────────────────────────

class TestOpenAIGuard(unittest.TestCase):

    def _guard(self, cert):
        from arcezia.integrations.openai import ArceziaGuard
        az = _fake_az(cert)
        return ArceziaGuard(az), az

    def _make_tool_call(self, name: str, args_json: str):
        tc = MagicMock()
        tc.function.name = name
        tc.function.arguments = args_json
        return tc

    def test_allow_executes_implementation(self):
        guard, _ = self._guard(_allow())
        fn = MagicMock(return_value="rows")
        result = guard.execute_tool_call(
            self._make_tool_call("execute_sql", '{"query": "SELECT 1"}'),
            tool_implementations={"execute_sql": fn},
        )
        self.assertFalse(result["blocked"])
        self.assertEqual(result["result"], "rows")
        fn.assert_called_once_with(query="SELECT 1")

    def test_block_returns_blocked_dict(self):
        guard, _ = self._guard(_block())
        fn = MagicMock()
        result = guard.execute_tool_call(
            self._make_tool_call("execute_sql", '{"query": "DROP TABLE users"}'),
            tool_implementations={"execute_sql": fn},
        )
        self.assertTrue(result["blocked"])
        self.assertIsNone(result["result"])
        self.assertIn("BLOCK", result["error"])
        fn.assert_not_called()

    def test_block_with_fabrication_in_error(self):
        guard, _ = self._guard(_block(fabricated=True))
        fn = MagicMock()
        result = guard.execute_tool_call(
            self._make_tool_call("execute_sql", '{"query": "DROP TABLE users"}'),
            tool_implementations={"execute_sql": fn},
        )
        self.assertIn("FABRICATION", result["error"])

    def test_review_returns_needs_review(self):
        guard, _ = self._guard(_review())
        fn = MagicMock()
        result = guard.execute_tool_call(
            self._make_tool_call("send_email", '{"to": "user@example.com"}'),
            tool_implementations={"send_email": fn},
        )
        self.assertTrue(result.get("needs_review"))
        self.assertIsNone(result["result"])

    def test_dict_tool_call_also_supported(self):
        guard, _ = self._guard(_allow())
        fn = MagicMock(return_value="ok")
        result = guard.execute_tool_call(
            {"name": "write_file", "arguments": '{"path": "/tmp/out.txt"}'},
            tool_implementations={"write_file": fn},
        )
        self.assertFalse(result["blocked"])

    def test_wrap_function_allow(self):
        guard, _ = self._guard(_allow())
        fn = MagicMock(return_value="result")
        safe = guard.wrap_function("execute_sql", fn, domain="database_ops")
        result = safe(query="SELECT 1")
        self.assertEqual(result, "result")

    def test_wrap_function_block_raises(self):
        guard, _ = self._guard(_block())
        fn = MagicMock()
        safe = guard.wrap_function("execute_sql", fn, domain="database_ops")
        with self.assertRaises(RuntimeError) as ctx:
            safe(query="DROP TABLE users")
        self.assertIn("BLOCK", str(ctx.exception))
        fn.assert_not_called()

    def test_wrap_function_review_raises(self):
        guard, _ = self._guard(_review(missing=["user_explicit_authorization"]))
        fn = MagicMock()
        safe = guard.wrap_function("send_email", fn, domain="agent_action")
        with self.assertRaises(RuntimeError) as ctx:
            safe(to="user@example.com")
        self.assertIn("REVIEW", str(ctx.exception))
        self.assertIn("user_explicit_authorization", str(ctx.exception))


class TestCrewAITool(unittest.TestCase):

    def _make_tool_class(self, cert):
        from arcezia.integrations.openai import ArceziaCrewTool
        az = _fake_az(cert)

        class MyDBTool(ArceziaCrewTool):
            name = "execute_sql"
            domain = "database_ops"
            description = "Run SQL"

            def _run(self, sql: str) -> str:
                return f"result:{sql}"

        tool = MyDBTool()
        tool.az = az
        return tool, az

    def test_allow_calls_run(self):
        tool, _ = self._make_tool_class(_allow())
        result = tool.run("SELECT 1")
        self.assertEqual(result, "result:SELECT 1")

    def test_block_raises_runtime_error(self):
        tool, _ = self._make_tool_class(_block())
        with self.assertRaises(RuntimeError) as ctx:
            tool.run("DROP TABLE users")
        self.assertIn("BLOCK", str(ctx.exception))

    def test_review_raises_with_missing(self):
        tool, _ = self._make_tool_class(_review(missing=["user_explicit_authorization"]))
        with self.assertRaises(RuntimeError) as ctx:
            tool.run("DELETE FROM users")
        self.assertIn("REVIEW", str(ctx.exception))
        self.assertIn("user_explicit_authorization", str(ctx.exception))

    def test_block_raises_not_returns_string(self):
        """Critical: CrewAI integration must raise, never return a string.
        Returning a string hands the block message to the LLM which may retry."""
        tool, _ = self._make_tool_class(_block())
        try:
            result = tool.run("DROP TABLE users")
            # If we reach here, a string was returned — this is wrong
            self.fail(
                f"Expected RuntimeError, got string result: {result!r}. "
                "Integration must raise on BLOCK, not return a string."
            )
        except RuntimeError:
            pass  # Correct behaviour

    def test_fabrication_in_error_message(self):
        tool, _ = self._make_tool_class(_block(fabricated=True))
        with self.assertRaises(RuntimeError) as ctx:
            tool.run("DROP TABLE users")
        self.assertIn("FABRICATION", str(ctx.exception))


# ── Anthropic integration ─────────────────────────────────────────────────────

class TestAnthropicGuard(unittest.TestCase):

    def _guard(self, cert, raise_on_block=True):
        from arcezia.integrations.anthropic import ArceziaAnthropicGuard
        az = _fake_az(cert)
        return ArceziaAnthropicGuard(az, raise_on_block=raise_on_block), az

    def _make_block(self, name: str, input_dict: dict):
        block = MagicMock()
        block.type = "tool_use"
        block.name = name
        block.input = input_dict
        block.id = f"tu_{name}"
        return block

    def test_allow_in_filter(self):
        guard, _ = self._guard(_allow(), raise_on_block=False)
        blocks = [self._make_block("execute_sql", {"query": "SELECT 1"})]
        safe, blocked = guard.filter_tool_uses(blocks)
        self.assertEqual(len(safe), 1)
        self.assertEqual(len(blocked), 0)

    def test_block_in_filter(self):
        guard, _ = self._guard(_block(), raise_on_block=False)
        blocks = [self._make_block("execute_sql", {"query": "DROP TABLE users"})]
        safe, blocked = guard.filter_tool_uses(blocks)
        self.assertEqual(len(safe), 0)
        self.assertEqual(len(blocked), 1)
        self.assertIs(blocked[0][0], blocks[0])

    def test_non_tool_use_blocks_pass_through(self):
        guard, _ = self._guard(_allow(), raise_on_block=False)
        text_block = MagicMock()
        text_block.type = "text"
        safe, blocked = guard.filter_tool_uses([text_block])
        self.assertEqual(len(safe), 1)
        self.assertEqual(len(blocked), 0)

    def test_verify_tool_use_block_raises_when_raise_on_block(self):
        guard, _ = self._guard(_block(), raise_on_block=True)
        with self.assertRaises(ArceziaBlockError):
            guard.verify_tool_use("execute_sql", {"query": "DROP TABLE users"})

    def test_verify_tool_use_allow_returns_cert(self):
        guard, _ = self._guard(_allow())
        cert = guard.verify_tool_use("execute_sql", {"query": "SELECT 1"})
        self.assertTrue(cert.allow)

    def test_run_tools_allow_calls_dispatch(self):
        guard, _ = self._guard(_allow())
        dispatch = MagicMock(return_value="query_result")
        blocks = [self._make_block("execute_sql", {"query": "SELECT 1"})]
        results = guard.run_tools(blocks, tool_dispatch=dispatch)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"], "query_result")
        dispatch.assert_called_once_with("execute_sql", {"query": "SELECT 1"})

    def test_run_tools_block_raises(self):
        guard, _ = self._guard(_block(), raise_on_block=True)
        dispatch = MagicMock()
        blocks = [self._make_block("execute_sql", {"query": "DROP TABLE users"})]
        with self.assertRaises(ArceziaBlockError):
            guard.run_tools(blocks, tool_dispatch=dispatch)
        dispatch.assert_not_called()

    def test_domain_map_override(self):
        from arcezia.integrations.anthropic import ArceziaAnthropicGuard
        az = _fake_az(_allow())
        guard = ArceziaAnthropicGuard(az, domain_map={"my_custom_tool": "payment_ops"})
        guard.verify_tool_use("my_custom_tool", {})
        call_kwargs = az.verify.call_args.kwargs
        self.assertEqual(call_kwargs["domain"], "payment_ops")

    def test_domain_pattern_inference(self):
        guard, az = self._guard(_allow())
        guard.verify_tool_use("run_sql_query", {"query": "SELECT 1"})
        call_kwargs = az.verify.call_args.kwargs
        self.assertEqual(call_kwargs["domain"], "database_ops")

    def test_description_uses_meaningful_field(self):
        """Description should surface the query/command, not just the tool name."""
        guard, az = self._guard(_allow())
        guard.verify_tool_use("execute_sql", {"query": "SELECT id FROM users LIMIT 1"})
        call_kwargs = az.verify.call_args.kwargs
        self.assertIn("SELECT id FROM users", call_kwargs["action_description"])


# ── Real scenario tests (cross-adapter) ───────────────────────────────────────

class TestRealScenarios(unittest.TestCase):
    """
    Scenario tests validating safety enforcement across adapters.

    Each test corresponds to a real incident class from the Arcezia Failure Lab.
    """

    def test_drop_table_blocked_in_autogen(self):
        """DROP TABLE on production must be BLOCK in AutoGen adapter."""
        from arcezia.integrations.autogen import ArceziaAutoGenGuard
        az = _fake_az(_block(violated=["no_unsafe_operations", "action_within_task_scope"]))
        guard = ArceziaAutoGenGuard(az)
        fn = MagicMock()
        safe = guard.wrap("execute_sql", fn, domain="database_ops")
        with self.assertRaises(RuntimeError) as ctx:
            safe(query="DROP TABLE users")
        self.assertIn("BLOCK", str(ctx.exception))
        fn.assert_not_called()

    def test_drop_table_blocked_in_crewai(self):
        """DROP TABLE on production must be BLOCK in CrewAI adapter."""
        from arcezia.integrations.openai import ArceziaCrewTool
        az = _fake_az(_block())

        class DropTool(ArceziaCrewTool):
            name = "execute_sql"
            domain = "database_ops"
            description = "Run SQL"
            def _run(self, sql: str) -> str:
                return db.execute(sql)  # noqa: F821 — unreachable

        tool = DropTool()
        tool.az = az
        with self.assertRaises(RuntimeError):
            tool.run("DROP TABLE users")

    @unittest.skipUnless(_LANGCHAIN_AVAILABLE, "langchain not installed")
    def test_drop_table_blocked_in_langchain(self):
        """DROP TABLE on production must raise ToolException in LangChain adapter."""
        from arcezia.integrations.langchain import ArceziaTool
        tool = MagicMock()
        tool.name = "execute_sql"
        tool.description = "Run SQL"
        az = _fake_az(_block())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        try:
            from langchain_core.tools.base import ToolException
        except ImportError:
            from langchain.tools.base import ToolException
        with self.assertRaises(ToolException):
            wrapped.run("DROP TABLE users")
        tool.run.assert_not_called()

    def test_fabrication_blocked_in_autogen(self):
        """
        Agent claims action_within_task_scope=True for an out-of-scope action.
        The engine detects fabricated evidence → BLOCK regardless of other constraints.
        Fabrication always overrides an otherwise-permissive result.
        """
        from arcezia.integrations.autogen import ArceziaAutoGenGuard
        az = _fake_az(_block(fabricated=True))
        guard = ArceziaAutoGenGuard(az)
        fn = MagicMock()
        safe = guard.wrap("delete_user", fn, domain="database_ops")
        with self.assertRaises(RuntimeError) as ctx:
            safe(user_id=42)
        self.assertIn("FABRICATION", str(ctx.exception))
        fn.assert_not_called()

    def test_review_surfaces_missing_constraint_in_crewai(self):
        """
        REVIEW must name the missing constraint so the caller knows what to ground.
        user_explicit_authorization is pending — human must authorize.
        """
        from arcezia.integrations.openai import ArceziaCrewTool
        az = _fake_az(_review(missing=["user_explicit_authorization"]))

        class EmailTool(ArceziaCrewTool):
            name = "send_email"
            domain = "agent_action"
            description = "Send email"
            def _run(self, to: str) -> str:
                return "sent"

        tool = EmailTool()
        tool.az = az
        with self.assertRaises(RuntimeError) as ctx:
            tool.run("user@example.com")
        self.assertIn("user_explicit_authorization", str(ctx.exception))

    def test_anthropic_filters_mixed_content(self):
        """
        A Claude response with mixed text + tool_use blocks:
        text blocks pass through, blocked tool_use blocks appear in blocked list.
        """
        from arcezia.integrations.anthropic import ArceziaAnthropicGuard

        # First call: allow; second call: block (different tool names)
        certs = [_allow(), _block()]
        az = MagicMock(spec=Arcezia)
        az.verify.side_effect = certs

        guard = ArceziaAnthropicGuard(az, raise_on_block=False)

        text_block = MagicMock()
        text_block.type = "text"

        tool_allow = MagicMock()
        tool_allow.type = "tool_use"
        tool_allow.name = "read_file"
        tool_allow.input = {"path": "/tmp/report.txt"}
        tool_allow.id = "tu_1"

        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.name = "execute_sql"
        tool_block.input = {"query": "DROP TABLE users"}
        tool_block.id = "tu_2"

        safe, blocked = guard.filter_tool_uses([text_block, tool_allow, tool_block])
        # text_block + tool_allow pass through
        self.assertEqual(len(safe), 2)
        # tool_block is blocked
        self.assertEqual(len(blocked), 1)
        self.assertIs(blocked[0][0], tool_block)


# ── LangGraph (via real BaseTool wrapper) ─────────────────────────────────────

class TestLangGraphTool(unittest.TestCase):
    """
    The SaaS client's as_langgraph_tool / wrap_for_langgraph produce genuine
    BaseTool objects that LangGraph's ToolNode accepts and that verify (over the
    HTTP client) before executing.
    """

    def setUp(self):
        try:
            import langgraph  # noqa: F401
            from langchain_core.tools import BaseTool, ToolException, tool
        except ImportError:
            self.skipTest("langgraph/langchain not installed")
        self.BaseTool = BaseTool
        self.ToolException = ToolException

        @tool
        def write_file(path: str) -> str:
            """Write a file."""
            return f"wrote {path}"

        self.tool = write_file

    def test_wrapper_is_real_basetool(self):
        from arcezia.integrations.langchain import as_langgraph_tool
        wrapped = as_langgraph_tool(self.tool, _fake_az(_allow()))
        self.assertIsInstance(wrapped, self.BaseTool)

    def test_langgraph_toolnode_accepts_wrapper(self):
        from arcezia.integrations.langchain import as_langgraph_tool
        from langgraph.prebuilt import ToolNode
        wrapped = as_langgraph_tool(self.tool, _fake_az(_allow()))
        self.assertIsNotNone(ToolNode([wrapped]))

    def test_allow_invoke_runs_underlying_tool(self):
        from arcezia.integrations.langchain import as_langgraph_tool
        wrapped = as_langgraph_tool(self.tool, _fake_az(_allow()))
        self.assertIn("wrote /tmp/x", wrapped.invoke({"path": "/tmp/x"}))

    def test_block_invoke_raises_toolexception(self):
        from arcezia.integrations.langchain import as_langgraph_tool
        wrapped = as_langgraph_tool(self.tool, _fake_az(_block()))
        with self.assertRaises(self.ToolException):
            wrapped.invoke({"path": "/tmp/x"})

    def test_toolkit_wrap_for_langgraph_returns_basetools(self):
        from arcezia.integrations.langchain import ArceziaToolkit
        tools = ArceziaToolkit(_fake_az(_allow())).wrap_for_langgraph([self.tool])
        self.assertIsInstance(tools[0], self.BaseTool)


# ── Convenience constructors (docs use api_key=/task=) ────────────────────────

class TestConvenienceConstructors(unittest.TestCase):
    """
    Every integration must accept BOTH an existing client (positional ``az``)
    and inline credentials (``api_key=``/``task=``) — the latter is what the
    developer docs show. Guards against doc/code drift.
    """

    _K = "ar_test_localdev"
    _U = "http://localhost:8000"

    def _az_of(self, obj):
        return getattr(obj, "_az", None) or getattr(obj, "az", None)

    def test_langchain_toolkit_inline_credentials(self):
        from arcezia.integrations.langchain import ArceziaToolkit
        tk = ArceziaToolkit(api_key=self._K, task="t", api_url=self._U)
        self.assertIsNotNone(self._az_of(tk))

    def test_openai_guard_inline_credentials(self):
        from arcezia.integrations.openai import ArceziaGuard
        g = ArceziaGuard(api_key=self._K, task="t", api_url=self._U)
        self.assertIsNotNone(self._az_of(g))

    def test_anthropic_guard_inline_credentials(self):
        from arcezia.integrations.anthropic import ArceziaAnthropicGuard
        g = ArceziaAnthropicGuard(api_key=self._K, task="t", api_url=self._U)
        self.assertIsNotNone(self._az_of(g))

    def test_autogen_guard_inline_credentials(self):
        from arcezia.integrations.autogen import ArceziaAutoGenGuard
        g = ArceziaAutoGenGuard(api_key=self._K, task="t", api_url=self._U)
        self.assertIsNotNone(self._az_of(g))

    def test_positional_az_still_supported(self):
        from arcezia.integrations.openai import ArceziaGuard
        from arcezia.integrations.langchain import ArceziaToolkit
        az = ArceziaGuard(api_key=self._K, task="t", api_url=self._U)._az
        self.assertIsNotNone(self._az_of(ArceziaToolkit(az)))


# ── Universal guard (framework-agnostic) ──────────────────────────────────────

class TestUniversalGuard(unittest.TestCase):
    """guard_callable / guard wrap ANY plain callable — covers Pydantic AI,
    smolagents, OpenAI Agents SDK, Google ADK, Strands, etc."""

    def test_allow_runs_callable(self):
        from arcezia.integrations.universal import guard_callable
        fn = lambda q: f"ran:{q}"
        safe = guard_callable(fn, _fake_az(_allow()), action_type="run_sql")
        self.assertEqual(safe("SELECT 1"), "ran:SELECT 1")

    def test_block_raises_block_error(self):
        from arcezia.integrations.universal import guard_callable
        from arcezia.client import ArceziaBlockError
        safe = guard_callable(lambda q: q, _fake_az(_block()), action_type="run_sql")
        with self.assertRaises(ArceziaBlockError):
            safe("DROP TABLE users")

    def test_review_raises_review_error_by_default(self):
        from arcezia.integrations.universal import guard_callable
        from arcezia.client import ArceziaReviewError
        safe = guard_callable(lambda q: q, _fake_az(_review()), action_type="send_email")
        with self.assertRaises(ArceziaReviewError):
            safe("to=user@example.com")

    def test_review_passes_through_when_disabled(self):
        from arcezia.integrations.universal import guard_callable
        safe = guard_callable(lambda q: f"sent:{q}", _fake_az(_review()),
                              action_type="send_email", block_on_review=False)
        self.assertEqual(safe("hi"), "sent:hi")

    def test_signature_preserved_for_schema_introspection(self):
        import inspect
        from arcezia.integrations.universal import guard_callable
        def write_file(path: str, content: str) -> str:
            """Write a file."""
            return "ok"
        safe = guard_callable(write_file, _fake_az(_allow()))
        self.assertEqual(list(inspect.signature(safe).parameters), ["path", "content"])
        self.assertEqual(safe.__name__, "write_file")
        self.assertEqual(safe.__doc__, "Write a file.")

    def test_decorator_form(self):
        from arcezia.integrations.universal import guard
        @guard(_fake_az(_allow()), domain="database_ops")
        def run_query(sql: str) -> str:
            return f"rows for {sql}"
        self.assertEqual(run_query("SELECT 1"), "rows for SELECT 1")

    def test_async_allow_runs(self):
        from arcezia.integrations.universal import guard_callable
        async def fetch(url: str) -> str:
            return f"got:{url}"
        safe = guard_callable(fetch, _fake_az(_allow()), action_type="http_get")
        self.assertTrue(asyncio.iscoroutinefunction(safe))
        self.assertEqual(asyncio.run(safe("x")), "got:x")

    def test_async_block_raises(self):
        from arcezia.integrations.universal import guard_callable
        from arcezia.client import ArceziaBlockError
        async def fetch(url: str) -> str:
            return "should not run"
        safe = guard_callable(fetch, _fake_az(_block()), action_type="http_get")
        with self.assertRaises(ArceziaBlockError):
            asyncio.run(safe("x"))


# ── LlamaIndex ────────────────────────────────────────────────────────────────

class TestLlamaIndexTool(unittest.TestCase):
    """guard_tool wraps a LlamaIndex FunctionTool, preserving its schema."""

    def setUp(self):
        try:
            from llama_index.core.tools import FunctionTool
        except ImportError:
            self.skipTest("llama-index-core not installed")
        self.FunctionTool = FunctionTool

        def run_sql(query: str) -> str:
            """Run a SQL query."""
            return f"rows:{query}"

        self.tool = FunctionTool.from_defaults(fn=run_sql)

    def test_guard_tool_returns_functiontool(self):
        from arcezia.integrations.llamaindex import guard_tool
        safe = guard_tool(self.tool, _fake_az(_allow()))
        self.assertIsInstance(safe, self.FunctionTool)
        self.assertEqual(safe.metadata.name, "run_sql")

    def test_allow_runs_tool(self):
        from arcezia.integrations.llamaindex import guard_tool
        safe = guard_tool(self.tool, _fake_az(_allow()))
        out = safe.call(query="SELECT 1")
        self.assertIn("rows:SELECT 1", str(out))

    def test_block_raises(self):
        from arcezia.integrations.llamaindex import guard_tool
        from arcezia.client import ArceziaBlockError
        safe = guard_tool(self.tool, _fake_az(_block()))
        with self.assertRaises(ArceziaBlockError):
            safe.call(query="DROP TABLE users")

    def test_toolkit_wrap(self):
        from arcezia.integrations.llamaindex import ArceziaLlamaToolkit
        tools = ArceziaLlamaToolkit(_fake_az(_allow())).wrap([self.tool])
        self.assertEqual(len(tools), 1)
        self.assertIsInstance(tools[0], self.FunctionTool)


@unittest.skipUnless(_LANGCHAIN_AVAILABLE, "langchain not installed")
class TestLangChainNoBypass(unittest.TestCase):
    """Regression: every execution entry point on ArceziaTool must be gated.

    ArceziaTool proxies unknown attributes to the wrapped tool. Before this was
    constrained, `.invoke()` — the standard modern LangChain entry point — fell
    through to the UNWRAPPED tool, so the action executed with no verification
    at all (az.verify was never called). Only `.run()` was gated.
    """

    def _make_tool(self, name: str = "execute_sql", return_value: str = "EXECUTED"):
        tool = MagicMock(spec=BaseTool)
        tool.name = name
        tool.description = f"A {name} tool"
        tool.run = MagicMock(return_value=return_value)
        tool.invoke = MagicMock(return_value=return_value)
        return tool

    def test_invoke_is_gated_on_block(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool()
        az = _fake_az(_block())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        with self.assertRaises(ToolException):
            wrapped.invoke({"q": "SELECT 1"})
        az.verify.assert_called_once()          # the gate actually ran
        tool.invoke.assert_not_called()         # the tool never executed

    def test_ainvoke_is_gated_on_block(self):
        import asyncio
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool()

        async def _ainvoke(*a, **k):            # pragma: no cover - must not run
            return "EXECUTED"
        tool.ainvoke = _ainvoke
        az = _fake_az(_block())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        with self.assertRaises(ToolException):
            asyncio.run(wrapped.ainvoke({"q": "SELECT 1"}))
        az.verify.assert_called_once()

    def test_invoke_allows_and_delegates(self):
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool()
        az = _fake_az(_allow())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        result = wrapped.invoke({"q": "SELECT 1"})
        az.verify.assert_called_once()
        tool.invoke.assert_called_once()
        self.assertEqual(result, "EXECUTED")

    def test_ungated_exec_attr_raises_instead_of_bypassing(self):
        """An execution entry point we do not gate must fail loudly, never
        silently proxy to the unwrapped tool."""
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool()
        az = _fake_az(_block())
        wrapped = ArceziaTool(tool, az, domain="database_ops")
        for attr in ("_run", "batch", "abatch", "stream", "astream", "func"):
            with self.subTest(attr=attr):
                with self.assertRaises(AttributeError):
                    getattr(wrapped, attr)

    def test_non_exec_attrs_still_proxy(self):
        """Ordinary attributes must still pass through to the wrapped tool."""
        from arcezia.integrations.langchain import ArceziaTool
        tool = self._make_tool()
        tool.args_schema = {"type": "object"}
        wrapped = ArceziaTool(tool, _fake_az(_allow()), domain="database_ops")
        self.assertEqual(wrapped.args_schema, {"type": "object"})


class TestCrewToolNoBypass(unittest.TestCase):
    """Regression: the gate must sit on the method that executes.

    ArceziaCrewTool gated run(), but subclasses implement _run() and CrewAI
    calls _run() directly in several versions — which skipped the gate. The
    gate is now installed onto the subclass's _run by __init_subclass__.
    """

    def _tool_cls(self, executed: list):
        from arcezia.integrations.openai import ArceziaCrewTool

        class SafeDBTool(ArceziaCrewTool):
            domain = "database_ops"
            name = "execute_sql"
            description = "d"

            def _run(self, sql: str) -> str:
                executed.append(sql)
                return "EXECUTED"

        return SafeDBTool

    def test_run_is_gated(self):
        executed: list = []
        cls = self._tool_cls(executed)
        cls.az = _fake_az(_block())
        with self.assertRaises(RuntimeError):
            cls().run("SELECT 1")
        self.assertEqual(executed, [])

    def test_private_run_called_directly_is_gated(self):
        executed: list = []
        cls = self._tool_cls(executed)
        cls.az = _fake_az(_block())
        with self.assertRaises(RuntimeError):
            cls()._run("SELECT 1")
        self.assertEqual(executed, [], "_run executed despite BLOCK")

    def test_allow_verifies_exactly_once(self):
        executed: list = []
        cls = self._tool_cls(executed)
        az = _fake_az(_allow())
        cls.az = az
        result = cls().run("SELECT 1")
        self.assertEqual(result, "EXECUTED")
        self.assertEqual(executed, ["SELECT 1"])
        self.assertEqual(az.verify.call_count, 1, "double-gated")


try:
    from crewai.tools import BaseTool as _CrewBaseTool
    _CREWAI_AVAILABLE = True
except ImportError:
    _CREWAI_AVAILABLE = False


@unittest.skipUnless(_CREWAI_AVAILABLE, "crewai not installed")
class TestCrewToolCoInheritance(unittest.TestCase):
    """ArceziaCrewTool must co-inherit cleanly with CrewAI's pydantic BaseTool.

    CrewAI's BaseTool is a pydantic model. Unannotated class attributes on
    ArceziaCrewTool surfaced as inherited fields (PydanticUserError), and
    declaring name/description made pydantic warn that the subclass field
    shadowed a parent attribute — so the documented CrewAI pattern did not
    actually work against real CrewAI.
    """

    def _build(self, executed: list):
        import typing
        from arcezia.integrations.openai import ArceziaCrewTool

        class SafeSQLTool(ArceziaCrewTool, _CrewBaseTool):
            name: str = "execute_sql"
            description: str = "Execute SQL"
            domain: typing.ClassVar[str] = "database_ops"

            def _run(self, sql: str) -> str:
                executed.append(sql)
                return "EXECUTED"

        return SafeSQLTool

    def test_subclass_builds_without_pydantic_warnings(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            self._build([])          # must not raise

    def test_both_crewai_entry_points_gated(self):
        # crewai calls _run() directly in its openai-agents tool adapter, and
        # via run() in BaseTool — both must gate.
        for entry in ("run", "_run"):
            with self.subTest(entry=entry):
                executed: list = []
                cls = self._build(executed)
                cls.az = _fake_az(_block())
                with self.assertRaises(RuntimeError):
                    getattr(cls(), entry)(sql="SELECT 1")
                self.assertEqual(executed, [])

    def test_action_type_resolves_to_crewai_field(self):
        executed: list = []
        cls = self._build(executed)
        az = _fake_az(_block())
        cls.az = az
        with self.assertRaises(RuntimeError):
            cls().run(sql="SELECT 1")
        self.assertEqual(az.verify.call_args.kwargs["action_type"], "execute_sql")


class TestAdaptersRefuseDegradedCerts(unittest.TestCase):
    """The safety net behind on_error="fail_open".

    In fail_open the client returns a synthetic ALLOW so a non-critical action
    can proceed during an outage. That verdict is always `degraded` and carries
    no credential — nothing was verified. Every adapter must refuse it, so an
    agent wired through an adapter cannot execute an unverified action even
    when the application opted into fail_open.
    """

    def _degraded_allow(self):
        from arcezia.client import ArceziaCertificate
        # Shape of the synthetic verdict the client builds when unreachable.
        return ArceziaCertificate(
            verdict="ALLOW", status="ALLOWED",
            precondition_score=0.0, trust_score=0.0,
            summary="Arcezia unreachable; degraded to ALLOW per on_error policy.",
            violated=[], missing=[], fabrication_detected=False,
            fabricated_constraints=[], constraints=[],
            signature="",            # synthetic — not a signed verdict
            credential=None,
        )

    def test_degraded_cert_is_recognised(self):
        cert = self._degraded_allow()
        self.assertTrue(cert.degraded)
        self.assertTrue(cert.allow)          # verdict says ALLOW …
        self.assertIsNone(cert.credential)   # … but nothing was verified

    def test_universal_guard_refuses_degraded(self):
        from arcezia.integrations.universal import guard_callable
        from arcezia.client import ArceziaUnavailableError
        ran = []
        az = _fake_az(self._degraded_allow())
        safe = guard_callable(lambda **k: ran.append(1), az)
        with self.assertRaises(ArceziaUnavailableError):
            safe(q="x")
        self.assertEqual(ran, [], "tool executed on an unverified certificate")

    def test_openclaw_dispatch_refuses_degraded(self):
        from arcezia.integrations.openclaw import DispatchGuard
        from arcezia.client import ArceziaUnavailableError
        ran = []
        guard = DispatchGuard(_fake_az(self._degraded_allow()))
        with self.assertRaises(ArceziaUnavailableError):
            guard.dispatch("write_file", {"path": "x"}, fn=lambda **k: ran.append(1))
        self.assertEqual(ran, [])

    @unittest.skipUnless(_LANGCHAIN_AVAILABLE, "langchain not installed")
    def test_langchain_refuses_degraded_on_every_entry_point(self):
        from arcezia.integrations.langchain import ArceziaTool
        from arcezia.client import ArceziaUnavailableError
        for entry, arg in (("run", "SELECT 1"), ("invoke", {"q": "SELECT 1"})):
            with self.subTest(entry=entry):
                tool = MagicMock(spec=BaseTool)
                tool.name, tool.description = "execute_sql", "d"
                wrapped = ArceziaTool(tool, _fake_az(self._degraded_allow()))
                with self.assertRaises(ArceziaUnavailableError):
                    getattr(wrapped, entry)(arg)
                tool.run.assert_not_called()
                tool.invoke.assert_not_called()


class TestUniformClientAccessor(unittest.TestCase):
    """Every adapter must expose the same client under the same name (.az),
    so Levels 2-4 (verify_chain / verify_outcome / authorize) are reachable
    without touching private attributes."""

    def test_adapters_expose_az(self):
        sentinel = MagicMock(name="client")
        cases = []

        from arcezia.integrations.openai import ArceziaGuard
        from arcezia.integrations.openclaw import DispatchGuard
        from arcezia.integrations.anthropic import ArceziaAnthropicGuard
        from arcezia.integrations.autogen import ArceziaAutoGenGuard
        cases += [
            ("ArceziaGuard", ArceziaGuard(sentinel)),
            ("DispatchGuard", DispatchGuard(sentinel)),
            ("ArceziaAnthropicGuard", ArceziaAnthropicGuard(sentinel)),
            ("ArceziaAutoGenGuard", ArceziaAutoGenGuard(sentinel)),
        ]
        if _LANGCHAIN_AVAILABLE:
            from arcezia.integrations.langchain import ArceziaToolkit, ArceziaTool
            tool = MagicMock(spec=BaseTool)
            tool.name = "execute_sql"
            tool.description = "d"
            cases += [
                ("ArceziaToolkit", ArceziaToolkit(sentinel)),
                ("ArceziaTool", ArceziaTool(tool, sentinel)),
            ]

        for name, obj in cases:
            with self.subTest(adapter=name):
                self.assertIs(obj.az, sentinel, f"{name}.az is not the client")


if __name__ == "__main__":
    unittest.main()
