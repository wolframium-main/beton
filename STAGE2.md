# STAGE 2 — irreversibility without reinstall (plan, now implemented in l3/)

The MVP holds via: hosts + nft (IP/DoT/DoH) + browser policies + 30s systemd
timer + pacman hook + chattr +i.

That is not enough against `sudo nft flush` + LiveUSB. Hence the final:

1. Precise SNI filter in nft/eBPF instead of blanket IP bans.
   Otherwise we hit someone else's CDN and the guard becomes visible.
2. Bypass-process killer: Tor/VPN clients installed after setup get killed;
   the work VPN from the allowlist lives (honest hole, documented).
3. Verity image + Unified Kernel Image with the baked blocklist.
   Signed with a Secure Boot key; the private key is destroyed ceremonially.
   Even with root the policy cannot be re-signed.
4. BIOS password + USB-boot ban + Secure Boot + LUKS — manual steps before apply.
   The password is not held by the user.
5. The `--final-irreversible` gate:
   - requires /etc/beton/ALLOW_FINAL + confirmed backup + passed VM matrix
   - removes `revert-for-testing`
   - after it, removal = hardware reset + reinstall

Without p.3–4, "sudo stays + cannot remove" does not technically add up.
The MVP shows this honestly: strong, angry, but removable in a VM.
