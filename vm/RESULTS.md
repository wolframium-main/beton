# Lab measurements (VM qemu/kvm, hermetic lab-DNS/TLS, 2026-09-13)

## L1 (userspace)
- apply: hosts OK, nft OK (set holds 192.0.2.10 from lab DNS), timer active, backup made
- manual hosts+nft removal → timer auto-restore (~30–50s in VM), tamper=1 in log
- manual enforce → restore + tamper++
- killer: /tmp/tor (comm=tor, exe newer than install) killed, logged
- allowlist: listed tor survived enforce
- 3 removals/10min → punish ACTIVE (beton_punish table, QUIC-drop), auto-lift on expiry
- pacman -U → hook fired (enforce, silent since compliant)
- curl: megablock.test → getent 0.0.0.0 + 000; fine.test → 200 (200 under punish too)
- revert → clean (no hosts markers, no tables, no timer)
- FINDING: `enable --now` after reinstall leaves the timer elapsed with no ticks.
  Fixed in beton: enable + restart with check (code + re-measured OK).
- FINDING: Chrome 153 ignores `*://` URLBlocklist patterns; bare hostnames block
  exact host + subdomains (measured matrix). Generator emits both formats
  (bare for Chrome, scheme for Firefox).

## L2 (eBPF TC egress, pattern megablock.test, lab port 18443)
- v1 substring: target dead, but notmegablock.test dead too (false positive) →
  rewritten to real SNI parsing
- v2 SNI parser: megablock.test 000, music.megablock.test 000,
  fine.test 200 in ~4ms, notmegablock.test 200
- fixed along the way: missing linux/in.h, 512B window too small for real hellos
  (now 1024 + min(ext_end,end) clamp), parameterized port (BETON_PORT)
- verifier accepted both versions; v2 attached and measured
- live Chromium vs policy layer: target+sub BLOCKED-BY-POLICY, control alive

## L3 — finalization in VM (SecureBoot + custom keys + signed UKI)
- gate: 6 checks; red on host, green in VM (Setup Mode → enroll → SB on)
- ceremony: SHA256 bundle → sbctl create-keys → ukify → sbsign → sbverify →
  enroll-keys --custom --tpm-eventlog (swtpm in VM) → shred of /var/lib/sbctl →
  FINAL → boot entry. EXIT:0
- after: no keys anywhere (find), revert answers 4, boot entry first
- reboot: SecureBoot Enabled, BootCurrent=signed UKI, cmdline beton.final=1,
  block (hosts/nft/timer) survived
- early restore: systemd unit beton-restore.service in initramfs
  (run_latehook never fires under systemd — proven by missing kmsg;
  wants-symlink must be explicit — add_systemd_unit does not create it)
- window measurement: hosts+nft removal + instant reboot → at t+25s (nft still
  PENDING, timer not ticked yet) hosts already restored by the unit,
  getent 0.0.0.0
- field fixes: pipefail+head (SIGPIPE 141), ESP parsing via sysfs
  (PKNAME + /sys partition, not sed), ESP copy only after enroll success,
  unlock at apply start, enable+restart timer, optional microcode,
  sh shebang in initramfs, unit removed from live system after packing
