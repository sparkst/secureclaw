# SecureClaw — Follow-Up Items

## Post-MVP Security Hardening

### App Sandbox + Entitlements
- Add macOS App Sandbox with `com.apple.security.files.user-selected.read-only` entitlement
- Restricts the app to only reading folders the user explicitly picks via folder picker
- Needs testing with PyInstaller (sandboxing can conflict with how PyInstaller unpacks)
- Required if Mac App Store distribution is ever pursued
- Source: Marcus persona review (P1, downgraded to P2 for MVP)

### Reproducible Builds
- Pin all dependency versions with hashes in requirements.txt
- Document exact build environment (Python version, PyInstaller version, macOS version)
- Move builds to GitHub Actions CI so there's a public audit trail: source commit → published binary
- True byte-for-byte reproducibility with PyInstaller is hard (timestamps/paths baked in) — pragmatic version is "CI builds from tagged commits with published checksums"
- Source: Marcus persona review (P1, downgraded to P2 for MVP)

### Apple Developer ID + Notarization
- $99/year Apple Developer Program membership
- Eliminates Gatekeeper "unidentified developer" warning entirely
- All 4 concept reviewers flagged ad-hoc signing as a problem
- Purchase when app traction is proven
- Source: All concept reviews (P0 consensus, PO deferred to post-beta)
