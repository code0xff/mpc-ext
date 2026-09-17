# Contributing

## Getting set up

```bash
make setup
make check   # must pass before you commit
```

## Ground rules

- Read [AGENTS.md](AGENTS.md) and the relevant pages under [`docs/`](docs/) before starting.
- **Write everything in English** — code, comments, documentation, UI strings and commit
  messages.
- If the implementation and the documentation disagree, **fix the documentation first.**
- Record hard-to-reverse decisions as ADRs under [`docs/adr/`](docs/adr/).
- Use [Conventional Commits](https://www.conventionalcommits.org/).
- No direct pushes to `main`; merge through pull requests.
- Never merge crypto or protocol code without tests.
- **Never commit real keys or secrets**, not even in test fixtures. Use dummy values.
- For every new dependency, read the licence text and record why you need it in the PR. No
  copyleft (GPL/AGPL/LGPL).

## Security

Report vulnerabilities through the process in [SECURITY.md](SECURITY.md), not as issues.
