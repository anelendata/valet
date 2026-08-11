# Contributing to valet

Thanks for your interest! valet is early and moving fast, so expect some rough
edges. Bug reports, small fixes, and focused PRs are all welcome.

## Development setup

Requires Python 3.11+.

```bash
git clone https://github.com/anelendata/valet.git
cd valet
python -m venv venv
. venv/bin/activate
pip install -e ".[test]"
```

This installs valet in editable mode with the test extras. The `valet` command
is now on your PATH and points at your working tree.

## Running the tests

```bash
python -m pytest -q
```

There is no separate linter or formatter configured — match the style of the
surrounding code (its naming, comment density, and idioms). Keep changes small
and add tests for anything that isn't obviously covered.

## Project layout

- `valet/` — the package. `cli.py` is the entry point (`valet = valet.cli:main`).
- `tests/` — pytest suite.
- `docs/` — threat model, roadmap, and how-tos.
- `contrib/sandbox-exec/` — the macOS Seatbelt profile and standalone helpers.

### Runtime assets must ship inside the package

`valet init` reads `valet/config.example.toml` and (on macOS)
`valet/workspace.sb`. These live **inside** the `valet/` package and are declared
in `[tool.setuptools.package-data]` so they end up in the built wheel — a file at
the repo root would not be found by an installed copy. `valet/workspace.sb` is a
copy of `contrib/sandbox-exec/workspace.sb`; a test asserts the two stay
byte-identical, so update both together.

## Reporting issues

Open an issue at https://github.com/anelendata/valet/issues. For anything
security-sensitive, please describe the concern without including real secrets.

## Releasing (maintainers)

Releases publish to PyPI as [`valet-ai`](https://pypi.org/project/valet-ai/) via
GitHub Actions **Trusted Publishing** (OIDC) — no API token is stored in the
repo. To cut a release:

1. Add a new section at the top of [`HISTORY.md`](HISTORY.md) for the version.
2. Bump `version` in `pyproject.toml`.
3. Commit both.
4. Tag and push:

   ```bash
   git push origin main
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   The `v*` tag triggers `.github/workflows/release.yml`, which builds and
   publishes. Approve the `pypi` environment deployment if GitHub prompts.

Notes:

- **PyPI versions are immutable.** A version can never be re-uploaded, so a
  broken build means bumping to the next patch — never reusing a number.
- Keep the tag and `pyproject.toml` `version` in sync (`vX.Y.Z` ↔ `X.Y.Z`).
- The README renders as the PyPI description; it only updates on a new release.
  Reference images by absolute URL (PyPI can't resolve relative paths and its
  image proxy rejects SVG — use a raster PNG).
