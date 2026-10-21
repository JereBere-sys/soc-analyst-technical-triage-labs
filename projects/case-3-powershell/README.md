# Case 3: PowerShell Incident Response Playbook

This case focuses on automating the initial triage and containment workflow for the compromised host identified in the Wireshark investigation.

## Overview

The playbook follows a four-phase response model:

1. Detect
2. Contain
3. Investigate
4. Preserve

The goal is to reduce time-to-response while creating a clean evidence trail.

## Scenario

Case 2 traced C2 beaconing back to internal host `DESKTOP-5NLV63K` and tied the activity to a compromised domain user. Once the malicious IPs are known, the response process should be repeatable and fast.

This script automates the workflow by:
- checking for active connections to known C2 IPs
- blocking the malicious outbound destinations
- reviewing persistence targets and runtime indicators
- exporting evidence into a triage folder

## Script

File: [Case3_IR_Playbook Code.ps1](./Case3_IR_Playbook%20Code.ps1)

## Phases

### Phase 1: Detect
The script enumerates active TCP connections and compares them to the known malicious IP list.

If a match is found, it resolves the owning PID and process details.

### Phase 2: Contain
The operator confirms a run, and the script adds outbound firewall blocks for the identified C2 IPs.

### Phase 3: Investigate
The script reviews:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- running services
- scheduled tasks
- process hashes for any detected malicious process

### Phase 4: Preserve
The script creates a timestamped evidence directory under `C:\Users\<user>\SOC-Triage` and saves the outputs before zipping the folder.

## Supporting Evidence

The original screenshots for this case are stored in the repo root and can be moved into this project folder later for cleaner local organization.

- `phase 1.jpeg`
- `phase 2.jpeg`
- `phase 3.jpeg`
- `phase 4.jpeg`

## Why It Matters

This project demonstrates the transition from manual investigation to structured endpoint response. In a real SOC environment, analysts need repeatable methods to detect malicious traffic, stop it quickly, and preserve evidence without losing context.
