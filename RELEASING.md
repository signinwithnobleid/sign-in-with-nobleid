# Releasing

1. Set the new version everywhere it appears, then check:
   `packages/node/package.json` (and `package-lock.json`),
   `packages/python/pyproject.toml` and `src/nobleid_signin/__init__.py`,
   `packages/rust/Cargo.toml` (and its `Cargo.lock`).
   `node test/check-versions.mjs` must pass; CI runs it too.
2. Add the version to [CHANGELOG.md](CHANGELOG.md).
3. Merge to `main` with CI green.
4. Publish a GitHub release with the tag `vX.Y.Z` on that commit.
   [`publish.yml`](.github/workflows/publish.yml) then checks that every
   package carries the tag's version and publishes each one whose repository
   variable is `true`: `PUBLISH_NPM`, `PUBLISH_PYPI`, `PUBLISH_CRATES`.

To publish an existing tag again (for example after turning a registry on),
run **Actions → publish → Run workflow** with the tag.

## How the registries trust this repository

No registry token is stored here. Each registry is told, once, to accept
releases from this repository's `publish.yml`, in a GitHub environment of
the same name:

| Registry | Package | Where | GitHub environment |
|---|---|---|---|
| npm | `nobleid-signin` | npmjs.com → package → Settings → Trusted publishing | `npm` |
| PyPI | `nobleid-signin` | pypi.org → Account → Publishing (a "pending publisher" works before the first upload) | `pypi` |
| crates.io | `nobleid-signin` | crates.io → crate → Settings → Trusted Publishing | `crates-io` |

For each: owner `signinwithnobleid`, repository `sign-in-with-nobleid`,
workflow `publish.yml`. npm and crates.io accept a trusted publisher only for
a package that already exists, so their very first version is uploaded by a
maintainer by hand; every later one comes from the workflow. After that, turn
off token publishing where the registry allows it (npm: Settings →
Publishing access → "Require two-factor authentication and disallow tokens").

Go (`nobleid.org/signin`) and PHP (`nobleid/signin` on Packagist) are not
published yet: Go needs a `go-import` meta tag at `https://nobleid.org/signin`,
and Packagist needs the PHP package in a repository of its own.
