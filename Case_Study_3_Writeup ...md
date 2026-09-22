# Case Study 3: Automated Endpoint Incident Response Playbook

**Analytical Objective:** Write a PowerShell script that automates the first-response
steps against the infected host found in Case Study 2 — detect the C2 connection,
block it, pull evidence off the endpoint, and package it up, without doing each step
by hand.

**Scenario:** Case 2 traced six FormBook/XLoader C2 check-ins back to internal host
`DESKTOP-5NLV63K`, MAC `00:12:f0:28:d4:34`, and tied the infection to domain user
`rvance` (Raymond Vance) through Kerberos traffic. Once you already know the infected
host and the six bad IPs, redoing that investigation manually every time doesn't make
sense — this case study turns the response into a single script with four phases:
**Detect → Contain → Investigate → Preserve.**

---

## Phase 1: Detect

**Goal:** Check if the host is still talking to any of the six C2 IPs, and if it is,
find out which process is doing it.

**Approach:** Pulls every live TCP connection with `Get-NetTCPConnection` and checks
each one against the six IPs from the Case 2 pcap. Any match gets traced back to its
PID and process name with `Get-Process` — basically automating the "check netstat
against the IOC list" step you'd normally do by hand.

**Result:** Ran clean on a non-infected machine — no matches against any of the six
IPs. That's expected here, and it confirms the detection logic actually works before
it's needed on a real infection.

**Evidence:**
![Phase 1 - Detect](phase%201.jpeg)

---

## Phase 2: Contain

**Goal:** Cut the connection to the six C2 IPs right away, without taking the machine
fully offline.

**Approach:** Asks for a typed "yes" before touching anything — no silent changes.
Once confirmed, it loops through the six IPs and adds a firewall rule for each with
`New-NetFirewallRule`, named `Block-C2-<IP>` so they're easy to find and remove later.

**Result:** All six rules created:

```
Blocked 172.64.155.76
Blocked 146.59.71.167
Blocked 38.182.168.246
Blocked 45.130.41.161
Blocked 172.67.162.153
Blocked 121.54.163.148
```

Only those six IPs are blocked outbound — nothing else about the firewall changes, and
the rules can be removed with `Remove-NetFirewallRule`.

**Evidence:**
![Phase 2 - Contain](phase%202.jpeg)

---

## Phase 3: Investigate

**Goal:** Pull evidence off the endpoint now that it's contained — persistence,
a hash of the malicious file if there is one, and what's currently running.

**Approach:** Checks the Registry Run keys under `HKCU` and `HKLM`, since that's
usually where malware sets itself up to survive a reboot. If Phase 1 caught an active
connection, it hashes that process's file with `Get-FileHash -Algorithm SHA256` — the
kind of hash you'd throw into VirusTotal. Then it grabs a snapshot of running services
and scheduled tasks with `Get-Service` and `Get-ScheduledTask`.

**Note:** the terminal output for services/tasks was capped to the first 4 entries each
(`-First 4`) just so it'd actually fit in a screenshot. That cap only affects what
prints to the screen — Phase 4 saves the full, uncapped list to file.

**Result:** No suspicious entries in either Run key. Nothing to hash since Phase 1
didn't flag a live connection. Services and scheduled tasks both pulled fine.

**Evidence:**
![Phase 3 - Investigate](phase%203.jpeg)

---

## Phase 4: Preserve

**Goal:** Package everything collected into something you could actually hand off.

**Approach:** Builds a folder name from the computer name plus a timestamp
(`DESKTOP-5NLV63K_Triage_Data_<timestamp>`), saved under a `SOC-Triage` folder instead
of dumping it on the Desktop. Each piece of evidence — Registry output, running
services, scheduled tasks, and detection results if any — gets written to its own
`.txt` file inside that folder. The whole folder then gets zipped with
`Compress-Archive`.

**Result:** Evidence saved and zipped successfully, confirmed by the script's final
output line.

**Evidence:**
![Phase 4 - Preserve](phase%204.jpeg)

---

## Cleanup

Once all four phases were verified, the six firewall rules from Phase 2 were removed
to put the machine back to normal:

```powershell
$C2_IPs | ForEach-Object { Remove-NetFirewallRule -DisplayName "Block-C2-$_" }
```

Confirmed removed by re-running `Get-NetFirewallRule -DisplayName "Block-C2-*"` and
getting nothing back.

---

## Why It Matters

Case 2 was the manual side of the job — reading a raw pcap to trace an infection to a
host and a user. Case 3 is the other half: once you know what you're dealing with, you
shouldn't have to redo that same detect-block-investigate-document process by hand
every time it happens again. This script handles all four steps on its own, so what
normally takes an analyst several minutes of manual work happens in seconds, and still
leaves a clean, organized evidence trail behind.
