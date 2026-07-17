# Releases (maintainers)

## Artifacts

Each GitHub Release should include:

| Asset | Platform |
|--------|----------|
| `hackpress-windows-x86_64.exe` | Windows x86_64 |
| `hackpress-linux-arm64` | Linux aarch64 |
| `hackpress-macos-arm64` | macOS Apple Silicon |

Prebuilt binaries are also listed on the [Releases](https://github.com/SimulatedSecurity/hackpress/releases) page.

## Local release workflow (not published)

Multi-platform builds are done with a **local-only** GitHub Actions workflow:

- Path: `.github/workflows/release.yml`
- That file is **gitignored** so it is not pushed to the public repo.
- Keep a copy on your machine (or restore from backup) before cutting a release.

### What the workflow does

- Triggers on `v*` tags, or manually via `workflow_dispatch` with a `tag` input.
- Builds on:
  - `windows-latest` → `hackpress-windows-x86_64.exe`
  - `ubuntu-24.04-arm` → `hackpress-linux-arm64`
  - `macos-latest` → `hackpress-macos-arm64`
- Uploads each binary to the matching GitHub Release (`gh release upload … --clobber`).

### Typical release steps

1. Bump `version` in `Cargo.toml` (and lockfile if needed).
2. Commit on `main`, then tag and push the tag:

   ```bash
   git tag v0.X.Y
   git push origin main
   git push origin v0.X.Y
   ```

3. Create the release (notes only; assets come from CI):

   ```bash
   gh release create v0.X.Y --title "v0.X.Y" --generate-notes
   ```

4. Temporarily enable the local workflow on GitHub so Actions can run it:

   ```bash
   git add -f .github/workflows/release.yml
   git commit -m "tmp: enable release workflow"
   git push origin main
   ```

5. Run the workflow against the tag:

   ```bash
   gh workflow run release.yml -f tag=v0.X.Y
   gh run watch
   ```

6. Confirm assets on the release:

   ```bash
   gh release view v0.X.Y
   ```

7. Remove the workflow from the repo again (leave the local file; it stays gitignored):

   ```bash
   git rm --cached .github/workflows/release.yml
   git commit -m "tmp: hide release workflow"
   git push origin main
   ```

### Manual upload (without Actions)

Build on each platform (or use your own CI), then:

```bash
gh release upload v0.X.Y \
  hackpress-windows-x86_64.exe \
  hackpress-linux-arm64 \
  hackpress-macos-arm64 \
  --clobber
```

### Prerequisites

- [GitHub CLI](https://cli.github.com/) (`gh`) authenticated (`gh auth login`)
- `gh` on `PATH` (new terminal after install, or refresh PATH)
- Write access to the repo (token needs `repo` + `workflow` for Actions)
