# Contributing to AegisProxy

Thanks for your interest in AegisProxy! Contributions — bug reports, docs, tests
and code — are very welcome.

## Ground rules

- **Be kind.** This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- **Security issues are not public.** Never open a public issue for a
  vulnerability — follow [SECURITY.md](SECURITY.md) instead.
- **Discuss big changes first.** For anything beyond a small fix, open an issue
  so we can agree on the approach before you invest time.

## Development setup

Requirements: Go ≥ 1.27.3, Python ≥ 3.12 with mitmproxy 12.3, Node.js 24, Docker.

```bash
make test                 # Go (race detector), Python, console build, Helm lint
make build                # control-plane binary and console
npm --prefix frontend run dev   # console dev server on :5173 (proxies /api to :8081)
```

Please make sure `make test` passes before opening a pull request. Match the
style of the surrounding code, keep changes focused, and add tests for new
behavior. Each pull request should describe *what* changed and *why*.

## Commit and PR hygiene

- Small, logically scoped commits with clear messages.
- Reference the issue a PR addresses (`Fixes #123`).
- Update docs and `CHANGELOG.md` when behavior changes.

## Licensing of contributions (please read)

AegisProxy is distributed under the [PolyForm Noncommercial License 1.0.0](LICENSE),
and the maintainer also offers **commercial** licenses. So that the project can
keep doing both, we ask every contributor to agree:

> By submitting a contribution, you certify that you wrote it (or have the right
> to submit it) and you grant the maintainer a perpetual, worldwide,
> royalty-free license to use, modify and distribute your contribution **as part
> of AegisProxy under both the PolyForm Noncommercial License and under separate
> commercial license terms.** You retain copyright in your contribution.

This is the common "inbound = outbound, plus a commercial grant" model used by
dual-licensed projects. If your employer owns your work, make sure you have
permission before contributing. Questions? **licensing@broeer.org**.
