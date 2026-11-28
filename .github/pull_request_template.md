## Summary

<!-- Describe what this PR changes and why. -->

- **Linked Issue / Workflow:** <!-- e.g., Closes #123 / Workflow WF-01..WF-08 -->

## Verification Checklist

- [ ] Formatting & tests pass locally: `gofmt -l .` is clean and `go test -race ./...` passes with `>= 80%` total coverage
- [ ] Linter clean: `golangci-lint run --config=golangci.yaml` reports `0` issues
- [ ] Modular hygiene: modified/added files adhere to `<= 500L` per-file size budget
- [ ] Showcase & Quiet UI checks pass (when touching `/web` or `site/`): `python3 scripts/build_github_showcase.py --check` and Quiet UI verification
- [ ] Documentation updated: `docs/WORKFLOWS.md` and/or `skills/` updated if tool behavior or workflows changed
