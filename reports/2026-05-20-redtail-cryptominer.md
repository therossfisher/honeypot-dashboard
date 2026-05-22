# Redtail Cryptominer Deployment Captured
**Date:** 22 May 2026  
**Sensor:** SANS ISC DShield Honeypot — San Diego, CA  
**Analyst:** Ross Fisher

---

## Summary

While analyzing logs from my internet-facing DShield honeypot sensor 
using AI-assisted triage, I identified what appears to be a Redtail 
cryptominer deployment attempt against my SSH honeypot. The attacking 
IP `130.12.180.51` was observed across three consecutive days and 
successfully deployed a full attack chain in under 35 seconds. This 
sensor contributes data to the SANS Internet Storm Center global 
threat intelligence network.

---

## Timeline

The attacker was first observed on 20 May 2026 and returned on 
21 and 22 May 2026 — three consecutive days of activity from the 
same IP address.

On 20 May 2026 at 05:05:31 PDT the attacker authenticated 
successfully using credentials `root:password`. What followed 
was a fully automated attack chain that completed in approximately 
34 seconds.

---

## Technical Details

Once inside the honeypot the attacker immediately executed a 
two-stage script sequence:

**Stage 1 — clean.sh**  
A cleanup script that killed a competing cryptominer 
(`c3pool_miner`) if present, scrubbed all crontabs of existing 
malware persistence mechanisms, and wiped common staging 
directories (`/tmp`, `/var/tmp`, `/dev/shm`). This tells us 
the operator knows compromised servers often have multiple 
infections and eliminates the competition before installing 
their own payload.

**Stage 2 — setup.sh**  
An architecture detection and deployment script that identified 
the host CPU type, selected the matching compiled binary from 
four options (ARM 32-bit, ARM 64-bit, Intel 32-bit, Intel 
64-bit), executed it under a randomized hidden filename, then 
deleted all traces of itself.

**Persistence mechanism**  
Before exiting the attacker used `chattr -ia` to remove 
filesystem-level immutable and append-only protections from 
`~/.ssh/authorized_keys` — a defense some administrators use 
to prevent unauthorized key installation. They then wrote their 
own RSA public key to that file, establishing an SSH backdoor 
that would survive password changes.

**Files captured by Cowrie:**

| Filename | SHA256 Hash |
|----------|-------------|
| SSH backdoor key | [`8a68d1c08ea31250063f70b1ccb5051db1f7ab6e17d46e9dd3cc292b9849878b`](https://www.virustotal.com/gui/file/8a68d1c08ea31250063f70b1ccb5051db1f7ab6e17d46e9dd3cc292b9849878b) |
| clean.sh | [`d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e`](https://www.virustotal.com/gui/file/d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e) |
| setup.sh | [`783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59`](https://www.virustotal.com/gui/file/783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59) |
| redtail.arm7 | [`3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f`](https://www.virustotal.com/gui/file/3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f) |
| redtail.arm8 | [`dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9`](https://www.virustotal.com/gui/file/dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9) |
| redtail.i686 | [`048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7`](https://www.virustotal.com/gui/file/048e374baac36d8cf68dd32e48313ef8eb517d647548b1bf5f26d2d0e2e3cdc7) |
| redtail.x86_64 | [`59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5`](https://www.virustotal.com/gui/file/59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5) |

---

## What is Redtail?

Redtail is a Monero cryptocurrency miner that has been active 
since at least December 2023. Unlike simple miners it runs 
entirely in memory rather than writing to disk, making it 
significantly harder to detect. It uses SSH-agent sockets to 
encrypt its communications with the operator's infrastructure.

Akamai has noted that Redtail's operational tactics — including 
the use of private mining pools and advanced anti-debugging 
techniques — mirror methods associated with North Korea's 
Lazarus Group, though formal attribution has not been confirmed.

---

## Why This is Significant

- **Cross-platform targeting** — four compiled binaries covering 
  every major Linux architecture means this campaign targets 
  everything from cloud servers to IoT devices to Raspberry Pis
- **Speed** — the entire attack chain from login to cleanup 
  completed in 34 seconds, indicating full automation
- **Competitor awareness** — specifically killing `c3pool_miner` 
  shows these criminal operations are actively competing for 
  the same pool of compromised hosts
- **Longevity** — the attacker's SSH key was generated in June 
  2023, suggesting this campaign has been running continuously 
  for nearly three years
- **Persistence** — bypassing `chattr` protections shows 
  knowledge of defensive hardening techniques

---

## Indicators of Compromise

| Type | Value |
|------|-------|
| IP Address | `130.12.180.51` |
| SSH Key Date | `rsa-key-20230629` |
| SSH Public Key | `AAAAB3NzaC1yc2EAAAADAQABAAABAQCqHrvnL6l7rT/mt1AdgdY9tC1GPK216q0q/7neNVqm7AgvfJIM3ZKniGC3S5x6KOEApk+83GM4IKjCPfq007SvT07qh9AscVxegv66I5yuZTEaDAG6cPXxg3/0oXHTOTvxelgbRrMzfU5SEDAEi8+ByKMefE+pDVALgSTBYhol96hu1GthAMtPAFahqxrvaRR4nL4ijxOsmSLREoAb1lxiX7yvoYLT45/1c5dJdrJrQ60uKyieQ6FieWpO2xF6tzfdmHbiVdSmdw0BiCRwe+fuknZYQxIC1owAj2p5bc+nzVTi3mtBEk9rGpgBnJ1hcEUslEf/zevIcX8+6H7kUMRr` |
| clean.sh | `d46555af1173d22f07c37ef9c1e0e74fd68db022f2b6fb3ab5388d2c5bc6a98e` |
| setup.sh | `783adb7ad6b16fe9818f3e6d48b937c3ca1994ef24e50865282eeedeab7e0d59` |
| redtail.arm7 | `3625d068896953595e75df328676a08bc071977ac1ff95d44b745bbcb7018c6f` |
| redtail.arm8 | `dbb7ebb960dc0d5a480f97ddde3a227a2d83fcaca7d37ae672e6a0a6785631e9` |
| redtail.i686 | `048e374baac36d8cf68dd32e48313ef8eb517d647548b1ff95d44b745bbcb7018c6f` |
| redtail.x86_64 | `59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5` |

---

## Conclusion

This capture illustrates how automated and sophisticated 
modern cryptomining operations have become. The attack chain 
was fully automated, architecture-aware, self-cleaning, and 
designed to evict competing malware — all executed in under 
35 seconds against what the attacker believed was a real 
production server.

For system administrators: changing default passwords is the 
single most effective mitigation against this class of attack. 
Moving SSH to a non-standard port, disabling password 
authentication in favor of key-based auth, and monitoring for 
`chattr` commands in shell history are all worth implementing.

*This analysis was conducted using a SANS ISC DShield honeypot 
sensor on a Raspberry Pi 4 with AI-assisted log triage. I'm 
relatively new to threat intelligence work and sharing these 
findings as part of my learning process. The live sensor 
dashboard is available at dashboard.therossfisher.xyz*

---
*Ross Fisher — San Diego, CA — May 2026*  
*SANS ISC Sensor ID: 3000055796*
