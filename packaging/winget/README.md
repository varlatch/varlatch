# winget manifest

The manifest of the `varlatch` CLI for the Windows Package Manager, laid out
as [`microsoft/winget-pkgs`](https://github.com/microsoft/winget-pkgs)
expects it (`manifests/v/Varlatch/Varlatch/<version>/`), in its current
schema, 1.28.0. **The owner submits it; nothing here submits or publishes
anything** (internal docs/design/go-step6.md, decision O4).

- **Package:** `Varlatch.Varlatch`, publisher Varlatch, moniker `varlatch`:
  `winget install varlatch`, `winget upgrade varlatch`. A copy winget
  installed is the package manager's to update: `varlatch self-update`
  refuses it and names `winget upgrade varlatch`.
- **Installer:** `portable`: winget downloads the release's
  `varlatch-<version>-windows-<amd64|arm64>.exe` and puts it on `PATH` as
  `varlatch`. No installer runs and nothing is elevated.
- **The stable manifest is for `0.50.0`.** Both installer checksums match
  the signed `SHA256SUMS` for the `v0.50.0` release and the binaries
  downloaded from the manifest URLs.

## For a release

For the version `X.Y.Z` to submit:

1. Download the release's checksums, their signature, and a CLI for this
   machine, then check the signature (or check it with cosign, as
   [Verifying a release](../../docs/operations/verify-release.md) shows):

   ```sh
   gh release download vX.Y.Z --repo varlatch/varlatch \
     --pattern SHA256SUMS --pattern SHA256SUMS.sigstore.json --pattern 'varlatch-X.Y.Z-linux-amd64'
   chmod +x varlatch-X.Y.Z-linux-amd64
   ./varlatch-X.Y.Z-linux-amd64 verify-release --version X.Y.Z --sums SHA256SUMS --bundle SHA256SUMS.sigstore.json
   grep windows SHA256SUMS
   ```

2. Copy the directory to `manifests/v/Varlatch/Varlatch/X.Y.Z/`, and in
   all three files set `PackageVersion: X.Y.Z`; in the installer file, each
   `InstallerUrl` to `vX.Y.Z/varlatch-X.Y.Z-windows-<arch>.exe`, each
   `InstallerSha256` to that file's line in `SHA256SUMS` in capitals, and
   `ReleaseDate`; in the locale file, `ReleaseNotesUrl`.

3. Validate on Windows: `winget validate --manifest <directory>`, and try
   it: `winget install --manifest <directory>`, then `varlatch --version`.

4. Submit: a pull request to `microsoft/winget-pkgs` adding the directory
   (or `wingetcreate submit <directory>`). Its automated checks install the
   package in a sandbox.

A prerelease is not for winget: submit final releases only.
