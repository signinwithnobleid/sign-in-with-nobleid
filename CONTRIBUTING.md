# Contributing

## Ground rules

- **No real credentials, ever.** Not in code, tests, fixtures, docs, issues
  or commit messages. Use the fake values in `test/clients.json` and the
  placeholders `nbcl_your_client_id` / `nbcs_your_client_secret`.
- Everything is tested against the local mock (`mock-oidc/`), never against
  the live service.
- Do not hand-roll cryptography. Use a maintained OIDC/JOSE library.
- Never log tokens, codes or secrets, even in examples.
- Keep claims honest: document only what the provider does today. Planned
  features go in `docs/roadmap.md`, marked as such.

## Running the tests

Requirements: Node 22+. Other languages only for their own examples.

```sh
npm ci                      # root workspace (mock, Node helper, Node example)
npm test                    # everything your machine has a toolchain for
npm run test:mock           # the mock's protocol conformance
npm run test:sdk            # the browser SDK and researcher badge
node test/run-example.mjs go-nethttp     # one example end to end
```

Examples whose toolchain is missing are reported as SKIPPED, not passed.
CI (`.github/workflows/ci.yml`) runs every language. See
[test/README.md](test/README.md) for how the end-to-end driver works and the
contract every example follows.

For Python, the runner creates a venv under test/.build unless you point it at one:
`PYTHON=/path/to/venv/bin/python node test/run-example.mjs python-flask-authlib`.

## Adding an example

1. Follow the route contract in `test/README.md`.
2. Add `examples/<name>/e2e.json`, a `README.md` and a `.env.example`.
3. Pin exact dependency versions and commit the lockfile.
4. Make `node test/run-example.mjs <name>` pass all scenarios.
5. Add a CI job.

## Style

- Small and readable beats clever. Comments say why, not what.
- JavaScript: ES modules for Node code; the browser SDK stays ES5 syntax and
  dependency-free. Format with the repository's existing style (2 spaces,
  double quotes).
- Other languages: the language's standard formatter (`gofmt`, `rustfmt`,
  `black`-compatible, PSR-12, …).
- Docs: plain Markdown, short sentences, no marketing.

## Sign-off

A `Signed-off-by:` line (Developer Certificate of Origin, https://developercertificate.org/)
is welcome but optional.

## Licence

By contributing you agree that your contribution is licensed under the
Apache License, Version 2.0.
