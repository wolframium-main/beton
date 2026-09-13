# VM runs (mandatory before touching a live system)

Requires: Arch VM with a "before beton" snapshot, internet access, 2 terminals.

## 0. Base
- [ ] VM snapshot. `python3 test_beton.py` — 21/21 OK, `l2/test_sni.py` 12/12,
      `l2/test_nfqueue.py` 6/6, `l3/test_gate.py` 6/6.
- [ ] `./beton dry-run <your sites>` — plan without changes.

## 1. Install
- [ ] `sudo ./beton block <sites> --yes-i-understand-this-is-forever --countdown 3`
- [ ] `sudo ./beton status` — hosts OK, nft OK, timer active.
- [ ] Site dead: `getent hosts <domain>` = 0.0.0.0, browser shows timeout, not a block page.

## 2. Attack matrix (each must lose; record hack time)
- [ ] `sudo sed -i` cutting the block out of /etc/hosts → back within 30s, enforce in log.
- [ ] `sudo nft flush ruleset` / delete table → table back.
- [ ] `sudo systemctl stop beton-enforce.timer` + removal → `enforce` restores everything.
- [ ] Install tor after setup and run it → process killed, kill in log.
- [ ] Renamed tunnel binary (different comm) → KNOWN MVP GAP: record it,
      closed only by the eBPF connection filter (FORTRESS L2).
- [ ] `ssh -D` SOCKS tunnel → KNOWN MVP GAP: record time/fact of bypass.
- [ ] Hardcoded 8.8.8.8:53 DNS in an app → dropped by the pubdns set.
- [ ] Portable browser (AppImage//tmp unpack) → policies miss, hosts+nft hold;
      record as pre-eBPF gap.
- [ ] Brave/Vivaldi/Opera/Firefox-ESR → policies in place.
- [ ] Live browser check (Chromium headless): bare-hostname entries block the target
      and subdomains, control host alive (scheme-only patterns are ignored by
      Chrome 153 — keep both formats: bare for Chrome, scheme for Firefox).
- [ ] Allowlisted process (name in /var/lib/beton/allowlist-procs.txt) → NOT killed.
- [ ] 3 removals in 10 min → punish active (`status`), QUIC throttled, auto-lift after 15 min.
- [ ] DNS switched to 8.8.8.8 → blocked names still dead.
- [ ] Second browser without policies → hosts+nft still hold.
- [ ] `sudo ./beton revert-for-testing` → clean: no markers in hosts, no tables, no timer.

## 3. L2 in VM (two carriers, hack-time measurement)
- [ ] `test_sni.py` 12/12, `test_nfqueue.py` 6/6, `gen-ebpf` matches codegen.
- [ ] TC: `build.sh` → `--attach eth0` → `curl youtube.com` dies, `example.com` 200.
- [ ] Renamed tunnel and /tmp portable → connection to the target dead.
- [ ] ECH target → record SNI-layer miss, DNS/IP pickup verified.
- [ ] NFQUEUE: daemon on queue 7 → same 4 checks. Pick the carrier with fewer
      misses; the other stays as fallback.

## 4. L3 ceremony in VM (with snapshot; host — never)
- [ ] `python3 l3/gate.py` red before install (proof of the gate).
- [ ] Setup Mode + SecureBoot on in VM firmware; `block` + matrix §2–§4 green.
- [ ] ALLOW_FINAL + VM_MATRIX_OK → `finalize.sh --i-am-sure` → key shred in log.
- [ ] Reboot: signed UKI boots, SecureBoot on, block in place.
- [ ] `revert-for-testing` → refusal with code 4. hosts+nft removal + reboot →
      initramfs restored before network, timer covers the rest.

## 5. Invisibility (while not attacking)
- [ ] Normal sites open with no slowdown and no popups.
- [ ] `pacman -Syu` works, hook runs silently.
- [ ] Reboot → block in place.

## 6. Release stop-conditions
- [ ] `block google.com` without the flag — refusal with explanation.
- [ ] No run touched /home.
- [ ] Logs only local (/var/log/beton.log), no network exfiltration.
