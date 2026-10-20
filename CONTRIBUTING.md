# Contributing

Thank you for helping. agent-off-switch values output a reviewer can trace back to a line of an export over breadth: a rule earns its place when it is computed from an export a team can already take, without a network call, and comes with its fix.

## Ground rules

- **Standard library only at run time.** Python 3.10 is the floor, and every change must pass on Linux, macOS and Windows. Open files with `encoding="utf-8"` (`utf-8-sig` for exports).
- **No network calls, no processes.** The package reads files and prints. `tests/test_cli_repo.py` fails if a module imports a network or subprocess module.
- **Print, never run.** `off` produces commands for a person. Every change step needs a read-only verification command.
- **No secret values.** Show key ids by their last four characters. Never read or print secret text, tokens or private keys.
- **Tests come with code.** Build inputs inside the test with the helpers in `tests/conftest.py`. Use made-up names, `example.com` addresses, obviously fake GUIDs and the documentation AWS account `111122223333`. `AKIAIOSFODNN7EXAMPLE` is the only access key id allowed in the repository; a test enforces it.
- **A rule change needs a before and after.** One input the rule now flags and one it must keep accepting, plus a line in [docs/scoring.md](docs/scoring.md) when a score changes.
- **Plain language.** British spelling, no em-dashes, no marketing words, no claims the repository cannot back.

## Layout

| Path | What it holds |
|---|---|
| `src/agent_off_switch/exports.py` | one reader per platform, filling the model |
| `src/agent_off_switch/model.py` | `Identity`, `Credential`, `Grant` |
| `src/agent_off_switch/scoring.py` | blast-radius rules |
| `src/agent_off_switch/inventory.py`, `review.py`, `runbook.py`, `drift.py` | the four subcommands and their renderers |
| `examples/demo-tenant/` | the synthetic tenant used by the README, the tests and CI |

## Running the checks

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
ruff format . && ruff check .
python -m pytest -q
aos review examples/demo-tenant
```

`tests/test_properties.py` uses [Hypothesis](https://hypothesis.readthedocs.io/) (installed by `.[dev]`) to feed the parsers random values and to run every command on copies of the demo tenant with values of the wrong type. A new reader should keep that test passing: bad input ends with exit code 2 and a message, never a traceback.

## Pull requests

- One topic per pull request; say what changed, why, and how you tested it.
- If you change the demo tenant, update the README transcript with real output.
- By contributing you agree that your contribution is licensed under the MIT licence of this repository.

See [docs/good-first-issues.md](docs/good-first-issues.md) for starting points and [SECURITY.md](SECURITY.md) for security reports.
