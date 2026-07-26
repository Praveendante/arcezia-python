"""Documentation must match the real API.

Four wrong examples shipped in the README and integration docstrings because
they were written from the method *names* without ever calling them:

    verify_outcome(actual=...)          -> no such parameter (it is `outcome`)
    verify_outcome(...)                 -> omitted required `action_description`
    verify_chain({"steps":[{"id":...}]})-> the request field is `step_id`
    result["verdict"]                   -> the chain response key is
                                           `overall_verdict`

Each would raise TypeError or KeyError on copy-paste. This test parses every
documented call to a client method and checks it against the real signature,
so a doc example that could not run is a test failure.
"""
from __future__ import annotations

import ast
import inspect
import pathlib
import re
import unittest

from arcezia.client import Arcezia

_CLIENT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Client methods whose documented calls we validate.
_CHECKED = ("verify", "verify_chain", "verify_outcome", "authorize",
            "start_session", "verify_outcome")


def _adapter_methods() -> dict[str, list]:
    """{method_name: [callable, ...]} across every adapter class.

    Adapter methods were originally NOT validated, which let a wrong AutoGen
    example ship: the README showed `guard.wrap(my_function)` while the real
    signature is `wrap(name, fn, domain=None)`, so the function bound to `name`
    and the call raised. Documented adapter calls are checked here too.
    """
    import importlib
    import inspect as _i
    out: dict[str, list] = {}
    for mod_name in ("langchain", "openai", "anthropic", "autogen",
                     "llamaindex", "openclaw", "universal", "n8n"):
        try:
            mod = importlib.import_module(f"arcezia.integrations.{mod_name}")
        except ImportError:
            continue                      # optional framework not installed
        for _, obj in _i.getmembers(mod, _i.isclass):
            if not obj.__module__.startswith("arcezia."):
                continue
            for name, fn in _i.getmembers(obj, _i.isfunction):
                if not name.startswith("_"):
                    out.setdefault(name, []).append(fn)
    return out


def _python_snippets() -> list[tuple[str, str]]:
    """(source_label, code) for every documented Python snippet."""
    out: list[tuple[str, str]] = []

    readme = _CLIENT_ROOT / "README.md"
    if readme.exists():
        for i, block in enumerate(re.findall(r"```python\n(.*?)```", readme.read_text(), re.S)):
            out.append((f"README.md block {i + 1}", block))

    for py in sorted((_CLIENT_ROOT / "arcezia").rglob("*.py")):
        try:
            mod = ast.parse(py.read_text())
        except SyntaxError:                                  # pragma: no cover
            continue
        doc = ast.get_docstring(mod)
        if doc:
            out.append((str(py.relative_to(_CLIENT_ROOT)), doc))
    return out


def _indented_calls(code: str) -> list[ast.Call]:
    """Parse a snippet leniently and return its Call nodes.

    Docstring snippets are indented and reference undefined names; we only need
    the parse tree, never execution. Lines that cannot parse are skipped.
    """
    calls: list[ast.Call] = []
    text = inspect.cleandoc(code)
    # Try whole-snippet parse first, then fall back to per-statement recovery.
    try:
        trees = [ast.parse(text)]
    except SyntaxError:
        trees = []
        for chunk in re.findall(r"^\s*[\w.]+\([^)]*\)", text, re.M | re.S):
            try:
                trees.append(ast.parse(inspect.cleandoc(chunk)))
            except SyntaxError:
                continue
    for t in trees:
        for n in ast.walk(t):
            if isinstance(n, ast.Call):
                calls.append(n)
    return calls


class TestRequestHeaders(unittest.TestCase):
    """The API is behind a WAF that 403s the stdlib default user agent.

    httpx sends its own agent, but httpx is an OPTIONAL dependency — the
    package declares `dependencies = []` and falls back to urllib.request. A
    plain `pip install arcezia` therefore takes the urllib path, and without an
    explicit User-Agent every call was rejected at the edge with 403
    (Cloudflare error 1010) before reaching the API. Verified live.
    """

    def _client(self):
        return Arcezia(api_key="ar_test_headers", task="t",
                       api_url="https://api.arcezia.com")

    def test_user_agent_is_sent(self):
        h = self._client()._headers()
        self.assertIn("User-Agent", h, "no User-Agent: urllib installs get 403")
        self.assertTrue(h["User-Agent"].strip())

    def test_user_agent_is_not_the_stdlib_default(self):
        ua = self._client()._headers()["User-Agent"]
        self.assertNotIn("Python-urllib", ua)
        self.assertTrue(
            ua.startswith("arcezia-"),
            f"User-Agent should identify the SDK, got {ua!r}",
        )

    def test_auth_and_content_type_still_present(self):
        h = self._client()._headers()
        self.assertTrue(h["Authorization"].startswith("Bearer "))
        self.assertEqual(h["Content-Type"], "application/json")


class TestDocumentedCallsMatchSignatures(unittest.TestCase):

    def test_documented_kwargs_exist_and_required_present(self):
        problems: list[str] = []

        for label, code in _python_snippets():
            for call in _indented_calls(code):
                fn = call.func
                if not isinstance(fn, ast.Attribute) or fn.attr not in _CHECKED:
                    continue
                method = getattr(Arcezia, fn.attr, None)
                if method is None:
                    continue
                sig = inspect.signature(method)
                params = sig.parameters
                accepts_kwargs = any(
                    p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()
                )

                used = {kw.arg for kw in call.keywords if kw.arg}
                # 1. every documented kwarg must exist
                for name in sorted(used):
                    if name not in params and not accepts_kwargs:
                        problems.append(
                            f"{label}: {fn.attr}({name}=...) — no such parameter. "
                            f"Valid: {sorted(p for p in params if p != 'self')}"
                        )

                # 2. required params must be supplied (positional or keyword)
                positional = len(call.args)
                required = [
                    n for n, p in params.items()
                    if n != "self"
                    and p.default is inspect.Parameter.empty
                    and p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                   inspect.Parameter.KEYWORD_ONLY)
                ]
                for idx, name in enumerate(required):
                    if idx < positional or name in used:
                        continue
                    problems.append(
                        f"{label}: {fn.attr}(...) — missing required "
                        f"argument {name!r}"
                    )

        self.assertEqual(
            problems, [],
            "Documented examples do not match the real API:\n  "
            + "\n  ".join(problems),
        )

    def test_documented_adapter_calls_are_satisfiable(self):
        """A documented adapter call must bind against the real signature.

        Only flags a call when EVERY overload of that method name rejects it,
        so a name shared by several adapters does not produce false failures.
        """
        adapters = _adapter_methods()
        problems: list[str] = []

        for label, code in _python_snippets():
            for call in _indented_calls(code):
                fn = call.func
                if not isinstance(fn, ast.Attribute):
                    continue
                cands = adapters.get(fn.attr)
                if not cands or fn.attr in _CHECKED:
                    continue
                kwargs = {kw.arg for kw in call.keywords if kw.arg}
                nargs = len(call.args)
                # Prose mentions a method as `wrap()` with no arguments; that is
                # a reference, not a usage example. Only check real calls.
                if nargs == 0 and not kwargs:
                    continue

                def binds(f) -> bool:
                    try:
                        sig = inspect.signature(f)
                        sig.bind_partial(
                            None, *([object()] * nargs),
                            **{k: object() for k in kwargs},
                        )
                        # every required param must be covered
                        supplied = nargs + len(kwargs)
                        required = [
                            n for n, p in sig.parameters.items()
                            if n != "self"
                            and p.default is inspect.Parameter.empty
                            and p.kind in (inspect.Parameter.POSITIONAL_OR_KEYWORD,
                                           inspect.Parameter.KEYWORD_ONLY)
                        ]
                        return supplied >= len(required)
                    except TypeError:
                        return False

                if not any(binds(f) for f in cands):
                    sigs = " | ".join(
                        f"{f.__qualname__}{inspect.signature(f)}" for f in cands[:3]
                    )
                    problems.append(
                        f"{label}: .{fn.attr}() with {nargs} positional + "
                        f"{sorted(kwargs)} does not match any real signature: {sigs}"
                    )

        self.assertEqual(
            problems, [],
            "Documented adapter calls do not match the real API:\n  "
            + "\n  ".join(problems),
        )

    def test_chain_response_key_is_overall_verdict(self):
        """The chain response has no top-level 'verdict'; docs must not use it."""
        offenders = []
        for label, code in _python_snippets():
            if "verify_chain" not in code:
                continue
            for m in re.finditer(r'result\[\s*"(\w+)"\s*\]', code):
                if m.group(1) == "verdict":
                    offenders.append(f'{label}: result["verdict"] — use "overall_verdict"')
        self.assertEqual(offenders, [], "\n  ".join(offenders))

    def test_chain_step_field_is_step_id(self):
        """The chain REQUEST uses step_id (the response's steps[] use id)."""
        offenders = []
        for label, code in _python_snippets():
            if "verify_chain" not in code:
                continue
            for block in re.findall(r'verify_chain\((.*?)\n\s*\}\)', code, re.S):
                if re.search(r'"id"\s*:', block):
                    offenders.append(f'{label}: chain step uses "id" — should be "step_id"')
        self.assertEqual(offenders, [], "\n  ".join(offenders))


if __name__ == "__main__":
    unittest.main()
