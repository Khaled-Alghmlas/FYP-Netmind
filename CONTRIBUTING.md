# Contributing to NetMind

## Workflow

1. Pick an issue from the [Project board](../../projects) (one issue per task). Assign yourself.
2. Branch from `main`: `git checkout -b <issue-number>-short-description`.
3. Make small, focused commits. Reference the issue (`Closes #N`) in the PR description.
4. Before pushing, run locally:

   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   make lint     # ruff
   make test     # pytest (unit tests, no lab needed)
   ```

5. Open a pull request against `main`. A PR can be merged only when
   **one teammate has approved it and CI is green**. Do not push directly to `main`.
6. Address review comments with new commits; the reviewer (or author, once approved) merges.

## Code conventions

- Python 3.11, formatted/linted with `ruff` (config defaults).
- Anything that changes device state (power-off, firewall rules, credentials)
  must go through the confirmation guard in `agent/agent_core.py`
  (`DESTRUCTIVE_TOOLS`) so it is confirmed by the user and written to the audit log.
- New behaviour needs a unit test in `tests/`. Tests must not require Docker,
  a lab, or a Groq key (see `tests/test_firewall.py` for how Docker is faked).
- Never commit secrets (`.env`), `topology/registry.json`, or `logs/`.

## Testing against the lab

```bash
make up                                    # build images, bridges, deploy, registry
NETMIND_INTEGRATION=1 pytest -m integration -v   # needs the running lab
make down
```

## Repository settings (maintainers)

GitHub → Settings → Branches → rule for `main`: require a pull request with
1 approving review, require the `lint-and-test` status check, and
dismiss stale approvals.
