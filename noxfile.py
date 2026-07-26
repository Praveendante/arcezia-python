"""
Multi-version compatibility matrix for the Arcezia framework integrations.

Run a single set:      nox -s integrations
Run the whole matrix:  nox            (parametrized over LangChain version sets)

Each session installs a specific (langchain, langchain-core, langgraph) version
set, then runs the adapter tests against it. This turns "backward compatibility
is defensively coded" into "backward compatibility is proven per release."

The OpenAI / Anthropic / CrewAI / AutoGen adapters are version-tolerant by design
(they operate on dicts / plain callables), so the matrix focuses on the LangChain
+ LangGraph axis where the import surface actually shifts across versions.
"""
import nox

nox.options.reuse_existing_virtualenvs = True

# Validated version sets. "min" entries are the lowest versions the adapters are
# guaranteed against; "latest" tracks the current major line.
LANGCHAIN_SETS = {
    "lc0.2": ["langchain~=0.2.0", "langgraph~=0.2.0"],
    "lc0.3": ["langchain~=0.3.0", "langgraph~=0.3.0"],
    "lc1":   ["langchain>=1,<2", "langgraph>=1,<2"],
}

_ADAPTER_TESTS = "tests/test_integrations.py"
_K = ("LangChain or LangGraph or TestTool or CrewAI or OpenAI or AutoGen or "
      "Anthropic or Convenience or Universal or LlamaIndex")


@nox.session(python=["3.10", "3.11", "3.12"])
@nox.parametrize("lcset", list(LANGCHAIN_SETS))
def integrations(session, lcset):
    """Run the integration adapter tests against one LangChain version set."""
    session.install("pytest")
    session.install(*LANGCHAIN_SETS[lcset])
    # The remaining framework adapters are version-tolerant; install current.
    session.install("openai>=1.30", "anthropic>=0.28", "llama-index-core>=0.11")
    session.install("-e", ".")
    session.run(
        "pytest", _ADAPTER_TESTS, "-q",
        "-k", _K,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )


@nox.session(python=["3.11"])
def autogen_compat(session):
    """AutoGen adapter is version-agnostic — prove it against legacy AND modern."""
    session.install("pytest", "-e", ".")
    # Legacy 0.2 line
    session.install("pyautogen~=0.2")
    session.run("pytest", _ADAPTER_TESTS, "-q", "-k", "AutoGen")
    # Modern agentchat line
    session.install("autogen-agentchat>=0.4")
    session.run("pytest", _ADAPTER_TESTS, "-q", "-k", "AutoGen")
