# Changelog

## 0.1.3 (2026-09-13)
- Cleanup: removed the superseded STAGE2 plan doc, merged the duplicate
  DoH/public-DNS constant, dropped the unused `run(check)` param and stale
  docstrings, removed stale VM snaps/logs (~3 GB)
- Tests: revert-under-FINAL now really invokes the command (expects exit 4);
  FORTRESS statuses updated to done

## 0.1.2 (2026-09-13)
- VPN safety: killer ignores system paths (`/usr`, `/opt`), so VPN clients
  and their bundled helpers survive package updates; path-pinned allowlist
  (`name:/path`) with auto-snapshot at setup; rename-to-allowlisted-name attack
  still killed (path must match)

## 0.1.1 (2026-09-13)
- Repository switched to English (docs + CLI)
- Chromium policy fix: Chrome 153 only honors bare-hostname URLBlocklist entries
  (scheme patterns are silently ignored — kept for Firefox); covered by VM measurement
- `enforce` now also verifies browser policies (a browser installed after setup
  gets covered on the next tick)

## 0.1.0 (2026-09-13) — first verified release
- L1: hosts + nft (IP/DoT/DoH/hardcoded-DNS) + browser policies
  (Chromium/Firefox/ESR/Brave/Vivaldi/Opera) + 30s watchdog + pacman hook +
  killer of post-setup bypass tools + allowlist + punish ladder + infra stoplist
- L2: eBPF TC SNI filter with ClientHello parsing and domain-boundary matching
  (substring matching false-positived on lookalikes — fixed),
  port parameterized; NFQUEUE daemon is the second carrier (unit tests, not run live)
- L3: finalization ceremony — 6-check gate, fresh sbctl key, UKI,
  sbsign+sbverify, enroll, shred of the whole store, FINAL flag (revert answers 4),
  early-restore systemd unit in initramfs, boot entry
- Measured in a VM (see vm/RESULTS.md): L1 matrix, L2 SNI measurements
  (target/subdomain dead, foreign host 200 in ~4ms, lookalike spared),
  live Chromium, full L1+L2+L3 cycle from scratch + reboot into signed UKI
  under Secure Boot
- Field fixes: stuck `enable --now` timer, unlock at apply start,
  pipefail+head (SIGPIPE 141), ESP parsing via sysfs, ESP copy only after enroll,
  sh shebang in initramfs, run_latehook never fires under systemd (unit instead),
  explicit wants-symlink, optional microcode

## Honest gaps of 0.1.x
- ECH targets expose only outer SNI (caught by DNS/IP layers)
- Second device / brand-new mirror / physical BIOS reset — out of perimeter
- NFQUEUE carrier never attached live (logic + tests only)
- Firefox WebsiteFilter verified at file level, not in a live run
