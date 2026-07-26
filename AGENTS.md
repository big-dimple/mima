# Repository Instructions

Before changing Mima, read `README.md`, `LLMWIKI.md`, `SECURITY.md` and, for runtime work, `DEPLOYMENT.md`.

- Source code, SQL and generated API specifications are the implementation source of truth.
- Preserve every invariant under `LLMWIKI.md#不可破坏的契约`.
- Never commit secrets, `.mima/`, `deploy/runtime.env`, database dumps or recovery materials.
- Existing SQL migrations are immutable. Add a migration and update the migration lock instead.
- Keep public documentation limited to `README.md`, `DEPLOYMENT.md`, `SECURITY.md`, `LLMWIKI.md`, `AGENTS.md` and `CLAUDE.md`.
- Run the focused tests first, then the repository gates listed in `README.md`.
- Do not weaken E2EE, authorization, concurrency or failure-closed behavior to make a test pass.
