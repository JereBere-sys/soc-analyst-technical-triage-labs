# Case Study 1: Network Reconnaissance & Asset Triage (Nmap)

## 1. Analytical Objective

Conduct systematic network discovery and service enumeration across the authorized lab subnet `172.16.8.0/24`. The objectives were to identify live hosts, fingerprint operating systems where possible, enumerate open TCP and UDP ports, identify service versions, and develop a prioritized asset triage matrix with candidate vulnerability tracking.

The assessment focused on identifying exposed services, documenting observable security weaknesses, and translating scan results into actionable recommendations.

## 2. Scope and Environment

- **Lab subnet:** `172.16.8.0/24`
- **Scanner:** Ubuntu laptop, `172.16.8.1`
- **Target 1:** Metasploitable 2, `172.16.8.20`
- **Target 2:** Ubuntu Server lab stand-in, `172.16.8.49`
- **Primary tool:** Nmap

The scanner's own IP address was excluded from the target list. Subsequent scans therefore focused on the two lab target systems.

## 3. Scan Methodology

The assessment followed a staged reconnaissance workflow, progressing from host discovery to TCP enumeration, limited UDP reconnaissance, SMB checks, and targeted vulnerability-script testing.

### 3.1 Host Discovery

**Command**

```bash
sudo nmap -sn 172.16.8.0/24 -oA scans/01_discovery
```

**Purpose**

Identify active hosts on the lab subnet without performing a port scan. The `-sn` option disables port scanning, while `-oA` saves results in Nmap's normal, grepable, and XML formats.

**Result**

Three live IP addresses were identified:

- `172.16.8.1`: Ubuntu scanning machine
- `172.16.8.20`: Metasploitable 2
- `172.16.8.49`: Ubuntu Server lab stand-in

Host discovery results were used to define the subsequent scan scope.

### 3.2 Target List Compilation

The two lab targets were recorded in `live_hosts.txt`:

```text
172.16.8.20
172.16.8.49
```

**Purpose**

Using a target list allows multiple scans to reuse the same defined scope and reduces the risk of accidentally scanning the wrong systems.

### 3.3 Full TCP Port and Service Enumeration

**Command**

```bash
sudo nmap -sS -sV -sC -O -p- -T4 -iL live_hosts.txt -oA scans/02_full_tcp
```

**Purpose**

Enumerate the full TCP port range and gather service and operating-system information.

| Option | Function |
|---|---|
| `-sS` | Performs a TCP SYN scan. |
| `-sV` | Attempts to identify service versions. |
| `-sC` | Runs Nmap's default script set. |
| `-O` | Attempts operating-system detection. |
| `-p-` | Scans TCP ports 1–65535. |
| `-T4` | Uses a faster timing profile, suitable for many controlled lab networks. |
| `-iL` | Reads target IP addresses from a file. |
| `-oA` | Saves results in three standard output formats. |

**Result**

The scan identified a broad range of legacy services on `172.16.8.20` and only one open TCP port on `172.16.8.49`.

Service banners provide useful identification evidence, but they do not independently establish whether a particular vulnerability is exploitable.

### 3.4 UDP Reconnaissance

**Command**

```bash
sudo nmap -sU --top-ports 20 -iL live_hosts.txt -oA scans/03_udp
```

**Purpose**

Check the 20 UDP ports selected by Nmap's top-port ranking to identify potentially exposed connectionless services.

**Result**

UDP port `53` (DNS) was reported open on `172.16.8.20`. Several other ports were classified as `open|filtered`.

The scan covered only the selected top 20 UDP ports, not the entire UDP port range. Ports marked `open|filtered` were excluded from the confirmed-open service inventory because Nmap could not determine whether they were open or filtered.

### 3.5 SMB Protocol and Security Enumeration

**Command**

```bash
sudo nmap -p 445 --script smb-protocols,smb2-security-mode,smb-os-discovery -iL live_hosts.txt -oA scans/04_smb
```

**Purpose**

Inspect TCP port `445` using selected Nmap scripts to gather information about supported SMB protocols, SMB2 security settings where applicable, and available system information.

**Result**

The Metasploitable 2 target exposed Samba on port `445/tcp`. The scan reported SMB message signing as disabled and SMB2 negotiation as unsuccessful.

These results identify areas for further review. They do not independently prove that SMBv1 was negotiated or that a specific Samba CVE is exploitable.

### 3.6 Targeted Vulnerability Enumeration

**Command**

```bash
sudo nmap -sV -p 21,22,23,25,80,445 --script vuln -oA scans/04_vuln_targeted 172.16.8.20
```

**Purpose**

Run Nmap's vulnerability-category scripts against selected TCP ports on the Metasploitable 2 target.

**Result and limitation**

This scan provided additional checks against selected services. Its scope was limited to the six specified ports and the scripts available to Nmap. It should not be interpreted as a comprehensive vulnerability assessment of the host.

A lack of vulnerability-script findings would not prove that a service is secure. Likewise, a version match or script result must be interpreted in the context of the specific evidence returned.

## 4. Key Findings

### 4.1 Metasploitable 2: `172.16.8.20`

The target presented a broad legacy attack surface, including:

- **FTP (`21/tcp`):** vsftpd 2.3.4; anonymous FTP login was confirmed.
- **SSH (`22/tcp`):** OpenSSH 4.7p1, an old version requiring further assessment.
- **Telnet (`23/tcp`):** a legacy remote-access service that does not provide SSH-equivalent session encryption.
- **SMTP (`25/tcp`):** Postfix SMTP with SSLv2 support reported by the scan.
- **HTTP (`80/tcp`):** Apache httpd 2.2.8 with WebDAV reported as enabled.
- **Legacy remote-access services (`512–514/tcp`):** rexecd, rlogin, and rsh services were identified.
- **SMB (`445/tcp`):** Samba 3.0.20-Debian; message signing was reported disabled.
- **Bindshell (`1524/tcp`):** Nmap identified a service labelled `bindshell`, associated with the intentionally vulnerable lab image.

Additional services were identified, including DNS, RPC, NFS, database services, VNC, IRC, Java RMI, and Apache Tomcat. The complete service inventory is maintained in the accompanying CSV file.

**Assessment:** The combination of legacy services, potentially insecure protocols, and a reported bindshell warrants high-priority remediation within the lab. The risk ratings assigned in the inventory are qualitative analyst judgments, not automatically generated Nmap or CVSS scores.

### 4.2 Ubuntu Server Lab Stand-In: `172.16.8.49`

The TCP scan identified only one open TCP port:

- **SSH (`22/tcp`):** OpenSSH 10.2p1 Ubuntu 2ubuntu3.8, as reported by the scan.

This indicates a smaller *observed TCP service footprint* than the Metasploitable 2 target. It does not establish that the system is fully hardened or free from vulnerabilities. The UDP scan also did not confirm any open UDP ports on this host within the tested top-20 port set.

**Assessment:** Maintain SSH as an exposed management service, restrict access to trusted sources where practical, and validate patch status, authentication controls, and configuration independently.

## 5. Asset Triage Summary

| IP address | Port/protocol | Service | Observed version or evidence | Risk | Primary concern |
|---|---|---|---|---|---|
| `172.16.8.20` | `21/tcp` | FTP | vsftpd 2.3.4; anonymous login confirmed | High | Anonymous access; investigate the version-specific CVE candidate separately. |
| `172.16.8.20` | `22/tcp` | SSH | OpenSSH 4.7p1 | Medium | Legacy service version; verify package and patch status. |
| `172.16.8.20` | `23/tcp` | Telnet | Linux telnetd | High | Unencrypted remote-access protocol. |
| `172.16.8.20` | `25/tcp` | SMTP | Postfix; SSLv2 support reported | High | Obsolete SSL protocol support. |
| `172.16.8.20` | `80/tcp` | HTTP | Apache 2.2.8; WebDAV reported | High | Legacy web server and additional web functionality. |
| `172.16.8.20` | `445/tcp` | SMB/Samba | Samba 3.0.20-Debian; signing disabled | High | Legacy SMB service and a security-configuration concern. |
| `172.16.8.20` | `512–514/tcp` | Legacy r-services | rexecd, rlogin, rsh | Critical | High-risk legacy remote-access and trust mechanisms. |
| `172.16.8.20` | `1524/tcp` | Bindshell | Service identified as `bindshell` | Critical | Potentially severe remote-access exposure in the lab. |
| `172.16.8.49` | `22/tcp` | SSH | OpenSSH 10.2p1 Ubuntu | Low | Exposed management port; configuration was not fully audited. |

*This is a summary of selected findings, not the complete inventory. The accompanying CSV contains 32 service findings across the two target hosts.*

### Candidate CVE tracking

- **CVE-2011-2523, vsftpd:** The observed version string and confirmed anonymous login do not prove that the known backdoor is present. The affected backdoored distribution is associated with a specific download window in 2011. Record this CVE as an unverified candidate, not a confirmed vulnerability.
- **CVE-2007-2447, Samba:** The reported Samba version makes this worth investigating, but the banner and disabled message signing do not establish exploitability. The relevant Samba configuration and package build would need validation.

Do not assign a CVE solely because a service looks old. Record the evidence, distinguish candidates from confirmed findings, and avoid claiming exploitability without sufficient support.

## 6. Analyst Notes and Limitations

- **Scope:** The inventory covers confirmed-open services observed in the supplied TCP results, plus confirmed UDP port `53` on `172.16.8.20`.
- **UDP limitations:** The UDP scan covered only the top 20 ports. `open|filtered` results were excluded from the confirmed-open inventory.
- **CVE status:** CVE references are candidates pending validation of package builds, configurations, and relevant vulnerability conditions.
- **Service identification:** Nmap's version detection is based on observed responses and may not always identify the exact installed build.
- **Risk scoring:** Risk levels are qualitative analyst assessments for this lab. They are not Nmap-generated scores or formal CVSS ratings.
- **Host identity:** `172.16.8.49` is an Ubuntu Server lab stand-in, not a Windows workstation.
- **Finding count:** The CSV contains 32 service findings across two target hosts. TCP and UDP services are counted as separate findings; the total does not represent the number of hosts.
- **Assessment limitations:** The results reflect the ports, scripts, and scan conditions used. They do not constitute proof that every service or vulnerability on either host has been discovered.

## 7. Recommended Actions

1. **Prioritize severe exposure:** Investigate and remove or isolate the legacy r-services and bindshell on the Metasploitable 2 target where appropriate.
2. **Disable unnecessary services:** Reduce the exposed service footprint to only what the lab requires.
3. **Replace insecure protocols:** Prefer SSH over Telnet and review other legacy remote-access mechanisms.
4. **Review FTP access:** Disable anonymous access unless it is explicitly required for the exercise; verify the vsftpd package against trusted vulnerability information.
5. **Modernize web and mail services:** Review the Apache and SMTP configurations, especially WebDAV exposure and obsolete SSL/TLS protocol support.
6. **Review SMB configuration:** Validate the Samba package and configuration, restrict access, and enable appropriate signing protections where supported.
7. **Validate SSH configuration:** On the Ubuntu Server stand-in, review patch status, authentication controls, and permitted source networks.
8. **Preserve evidence:** Retain the raw Nmap output files and screenshots so another analyst can trace conclusions back to the original observations.

## 8. Conclusion

This exercise demonstrated a staged Nmap reconnaissance workflow, from subnet discovery to TCP service enumeration, limited UDP probing, SMB checks, and targeted vulnerability-script testing.

The primary outcome was an evidence-based inventory that separates confirmed observations from unverified vulnerability candidates. The Metasploitable 2 host showed a substantially broader legacy service footprint, while the Ubuntu Server stand-in exposed only SSH over TCP in the tested scan.

The resulting triage matrix provides a starting point for prioritizing remediation, validating vulnerability candidates, and communicating technical findings clearly. The next step is to ensure the report, CSV inventory, raw scan outputs, and screenshots use consistent filenames and remain traceable to the same evidence.

## 9. Practical Tips and Tricks

- **Use `-oA` for repeatable evidence collection.** It saves normal, grepable, and XML output, which helps with review and future analysis.
- **Keep discovery separate from enumeration.** Identify live hosts first, confirm the authorized target list, then perform deeper scans.
- **Understand what the options actually do.** `-p-` covers all TCP ports, but it does not mean all UDP ports were scanned. `--top-ports 20` is a limited UDP check.
- **Treat `open|filtered` carefully.** It is an ambiguous state, not confirmation that a service is listening.
- **Separate evidence from interpretation.** “Port 445 is open and signing is disabled” is an observation. “A particular CVE is exploitable” is a separate conclusion requiring more evidence.
- **Keep risk ratings explainable.** Tie each rating to exposure, likely impact, and the lab's threat context. Do not use severity labels as decoration.
- **Keep a consistent naming convention.** Use the same scan basename in commands, report references, and the folder containing the outputs.
- **Make the report reproducible.** A reviewer should be able to run the documented command against the authorized lab and understand which output supports each claim.
- **Avoid overclaiming from a clean result.** No finding from a script does not prove the absence of vulnerabilities.
- **Protect the scope.** Only scan systems you own or have explicit permission to assess.

