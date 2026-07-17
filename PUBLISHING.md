# Publishing Introspectre to crates.io

A short checklist for cutting a release to [crates.io](https://crates.io). Publishing
is **irreversible**: the crate name is claimed permanently, and a published version
can only be *yanked* (hidden from new dependents), never deleted.

## Prerequisites
- A crates.io account (sign in at crates.io with GitHub) and an **API token**
  (Account Settings → API Tokens). This is a **crates.io** token — a GitHub token
  does **not** work for `cargo publish`.
- On Windows, build with the MinGW/GNU toolchain on PATH (this repo has no MSVC):
  `$env:Path = "$env:USERPROFILE\mingw64\bin;$env:Path"`.

## Steps
1. **Bump the version** in `Cargo.toml` (`version = "X.Y.Z"`) following SemVer, and add
   a matching `CHANGELOG.md` section and README version line. The CLI banner reads the
   crate version automatically.
2. **Verify the package contents** — confirm no private/copyrighted files are included
   and the report assets are:
   ```
   cargo package --list
   ```
   Expected: `src/**` (including `src/vendor/*.js` and `src/visual_template.html`),
   `Cargo.toml`, `README.md`, `LICENSE`, and the public docs. **Must NOT contain**
   `RESEARCH.md`, `PRESENTATION.md`, `NOTES-ENTERPRISE.md`, or `resources/*`
   (these are covered by `exclude` in `Cargo.toml`).
3. **Dry-run** the publish (packages + builds from the packaged tree, uploads nothing):
   ```
   cargo publish --dry-run
   ```
4. **Authenticate and publish**:
   ```
   cargo login <your-crates-io-token>
   cargo publish
   ```
5. After it appears on crates.io, users can install with `cargo install introspectre`.

## Notes
- `cargo install --git https://github.com/m3m0rydmp/Introspectre` works without a
  crates.io release, if you prefer not to publish.
- If a bad version ships, `cargo yank --version X.Y.Z` stops new projects from
  depending on it (existing users are unaffected); it cannot be un-published.
