# Outlaw IRC Botnet — Still Active in 2026
**Date:** 24 May 2026  
**Sensor:** SANS ISC DShield Honeypot — San Diego, CA  
**Analyst:** Ross Fisher

---

## Summary

While analyzing honeypot traffic using AI-assisted log triage, I 
observed 72 unique IP addresses deploying the same SSH backdoor key 
in a single day — May 24, 2026. The key carries the comment 
`mdrfckr` and is a well-known indicator of compromise linked to the 
Outlaw cybergang, also known as "Dota." This group was originally 
discovered by Trend Micro in 2018 and has been continuously active 
or intermittently resurging ever since. What makes this finding 
notable is that the exact same SSH public key documented in a 2020 
Yoroi security report is still being deployed in 2026 — unchanged 
after more than six years of active campaigning.

This sensor contributes data to the SANS Internet Storm Center 
global threat intelligence network.

---

## Observations From My Sensor

Over six days of data from May 19-24, 2026, I observed the 
following activity patterns:

- **May 19-20:** Low baseline activity, 21-40 SSH attempts per day
- **May 21:** Volume spiked 30x overnight to 1,199 attempts
- **May 22:** 2,357 attempts
- **May 23:** 4,474 attempts — peak activity
- **May 24:** 72 unique IPs deployed the mdrfckr backdoor key in 
  120 separate sessions

The sudden volume increase on May 21 suggests the sensor IP was 
added to active botnet scanning lists after becoming visible on the 
internet. This is consistent with how the Outlaw botnet propagates — 
compromised machines continuously scan for new targets and add 
discovered IPs to shared target lists.

The attack sequence on May 24 was consistent across all 72 IPs:
Sessions were short — typically under 30 seconds. The sole purpose 
was installing the backdoor key, not immediate exploitation. This is 
Stage 1 of a two-stage operation: establish persistent access now, 
return later with the full payload.

---

## Technical Details

**The Outlaw infection chain** begins with SSH brute force using 
weak or default credentials. Once access is obtained the attacker 
installs a persistent SSH backdoor key, then returns later to deploy 
the full `dota.tar.gz` payload. This archive contains three 
components stored in a hidden `.rsync` directory:

**Folder a — Cryptominer**
An XMRig-based Monero miner named `kswapd0` — deliberately named 
after a legitimate Linux kernel memory management process to evade 
detection. Configured to mine to private pools, some accessible 
via Tor.

**Folder b — Backdoor**
A Perl-based Shellbot IRC client that connects to a C2 server and 
waits for commands. The bot can execute arbitrary commands, conduct 
DDoS attacks, perform port scans, and download files. Each infected 
machine is assigned a nickname in the format `sEx-[random number]`.

**Folder c — Propagation**
A custom SSH brute-force scanner called "Faster Than Lite" (tsm) 
that scans for new targets and spreads the infection. On ARM 
architecture it uses 75 threads, on x86 it uses 515 threads. This 
is why 72 different IPs deployed the same key in one day — each of 
those machines is itself a previously compromised server now 
doing the scanning work.

**The persistence mechanism** uses `chattr -ia` to remove immutable 
file protections from `~/.ssh/authorized_keys` before writing the 
backdoor key — the same technique observed in the Redtail deployment 
captured by this sensor on May 20, 2026. Elastic Security Labs noted 
in April 2025 that `redtail` appears as a variant name in the same 
malware family as Outlaw, suggesting possible shared infrastructure 
or operator overlap.

**The miner disguise** is particularly effective. Running as 
`kswapd0` it blends in with legitimate kernel processes. Unless an 
administrator specifically checks CPU usage or running process 
names, a compromised server could mine Monero indefinitely without 
detection.

---

## Attribution and History

The Outlaw cybergang, named from the Romanian word *haiduc*, has 
been tracked since at least 2018. Research suggests the operators 
are likely Romanian based on IRC channel comments in Romanian and 
the group's operational patterns matching Central European business 
hours. IRC handles observed in early research include `luci`, 
`lucian`, `dragos`, `mazy`, `hydra`, and `poseidon`.

**Timeline of documented activity:**
- **2018** — First discovered by Trend Micro targeting IoT and 
  Linux servers
- **2020** — Updated toolkit documented by Trend Micro and Yoroi; 
  same mdrfckr SSH key confirmed in active use
- **2022** — Multiple honeypot operators document continued activity
- **2024** — Active through November 2024
- **Dec 2024 – Feb 2025** — Period of dormancy
- **March 2025** — Sudden resurgence documented by Kaspersky
- **May 2026** — Active on this sensor with 72 IPs in one day

The group's longevity is remarkable. Using the same SSH key for 
over six years suggests either extreme confidence in their 
operational security or a deliberate decision that changing the key 
provides no meaningful protection since defenders who detect it will 
block the IP regardless.

---

## Indicators of Compromise

| Type | Value |
|------|-------|
| SSH Key Comment | `mdrfckr` |
| SSH Public Key | `AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== mdrfckr` |
| Backdoor Key Hash | [`a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`](https://www.virustotal.com/gui/file/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2) |
| Miner Process Name | `kswapd0` |
| Hidden Directory | `~/.rsync/` or `~/.configrc/` |
| First Stage Script | `tddwrt7s.sh` |
| Payload Archive | `dota.tar.gz` or `dota3.tar.gz` |
| C2 Method | IRC over non-standard ports including 443 |
| Mining Pool | Tor-accessible private pool |
| HASSH Fingerprint | `f555226df1963d1d3c09daf865abdc9a` (libssh_0.9.6) |

**Sample IPs observed May 24, 2026 (partial list):**
`103.143.231.102`, `103.255.65.6`, `217.234.90.116`, 
`119.18.55.118`, `165.154.6.66`, `20.153.204.5`, 
`212.199.105.109`, `114.130.85.36`, `202.51.214.98`,
`165.154.6.49`, `103.200.25.198`, `190.6.32.107`

**Detection:** Monitor `~/.ssh/authorized_keys` for the mdrfckr 
key. Alert on `chattr -ia` commands targeting `.ssh` directories. 
Watch for processes named `kswapd0` consuming high CPU.

---

## References

- Trend Micro, November 2018 — *Perl-Based Shellbot Looks to 
  Target Organizations via C&C*
- Trend Micro, February 2020 — *Outlaw Updates Kit to Kill Older 
  Miner Versions*
- Yoroi, April 2020 — *Outlaw is Back, a New Crypto-Botnet Targets 
  European Organizations*
- Kaspersky Securelist, April 2025 — *Outlaw Botnet Detected in 
  an Incident*
- Elastic Security Labs, April 2025 — *Outlaw Linux Malware: 
  Persistent, Unsophisticated, and Surprisingly Effective*

---

## Conclusion

The Outlaw botnet is not sophisticated by modern standards — it 
uses publicly available tools, an IRC protocol that's been around 
since the 1990s, and the same SSH key for six-plus years. And yet 
it keeps working. That's the uncomfortable truth this finding 
illustrates: you don't need to be sophisticated when most of the 
internet is running SSH with weak passwords.

72 compromised servers deployed this backdoor to my honeypot in 
a single day. Each of those servers is itself a victim — someone's 
cloud instance, home server, or business machine that got 
compromised because of a weak password. They're now doing the 
attacker's scanning work for them, looking for the next victim.

The mitigation is simple and has been the same for years: disable 
SSH password authentication, use key-based auth, move SSH off 
port 22. The Outlaw group will still be running this campaign in 
another six years if the internet keeps giving them easy targets.

*Analysis conducted using a SANS ISC DShield honeypot sensor on a 
Raspberry Pi 4 with AI-assisted log triage. Live sensor dashboard: 
dashboard.therossfisher.xyz*

---
*Ross Fisher — San Diego, CA — May 2026*  
*SANS ISC Sensor ID: 3000055796*
