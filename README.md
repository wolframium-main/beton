# beton — the invisible guard dog

**beton permanently blocks websites you choose. Removing the block requires
reinstalling the OS — that is the design, not a bug.**

One command, no thinking required. In normal life it does not exist: no icons,
no popups, everything else untouched. Target sites just look dead. Any attempt
to bypass or remove it is silently killed and rolled back.

> **WARNING: after finalization there is no undo.** Use only on your own machine,
> only with a backup. Run `VM_TESTS.md` first.

## Quick start (Arch Linux)

```
./install.sh              # installs to /usr/local/bin (applies nothing)
./beton dry-run youtube.com   # shows the plan, changes nothing, no sudo needed
sudo ./beton              # interactive: asks for sites and does everything itself
sudo ./beton status       # check that it holds
```

## How it holds (6 layers, all measured in a VM — see vm/RESULTS.md)

1. DNS/hosts + nftables (IP / DoT / DoH / hardcoded-DNS) — names are dead everywhere
2. Browser enterprise policies (Chromium / Firefox / ESR / Brave / Vivaldi / Opera)
3. systemd watchdog (30s) + pacman hook + early-boot unit in initramfs
4. Killer of bypass tools installed *after* setup (allowlist for your work tools)
5. Escalation ladder: silent restore → persistence → temporary QUIC punishment
6. L2 eBPF SNI filter + L3 finalization ceremony (Secure Boot, signing key destroyed)

## Your VPN stays alive

The killer only hunts user-dropped bypass binaries (`/tmp`, `/home`, …).
System locations (`/usr`, `/opt` — where VPN clients and their helpers live)
are never kill targets, so package updates cannot turn your own VPN into
collateral damage. At setup, beton snapshots your running tools into an
allowlist (`name:/path` lines in `/var/lib/beton/allowlist-procs.txt`).

## Rollback

- Before finalization (VM tests): `sudo ./beton revert-for-testing`
- After `l3/finalize.sh`: no rollback, `revert` answers with exit code 4

## Honest limits

A second device, a brand-new mirror with a new domain+IP, or a physical BIOS
reset are outside one PC's perimeter. ECH hides the real SNI (DNS/IP layers
catch it instead). Details: FORTRESS.md, l2/README.md, l3/README.md.

## Layout

- `beton` — the tool itself (stdlib only), `test_beton.py` — 21+ tests
- `l2/` — SNI core, eBPF filter, NFQUEUE daemon, codegen
- `l3/` — gate and finalization ceremony (VM only)
- `vm/` — lab: VM scripts, lab DNS/TLS, attack matrix, measurements

License: MIT (see LICENSE).
