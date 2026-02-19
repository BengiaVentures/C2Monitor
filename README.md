# C2Monitor

Lightweight Command & Control beacon detection for Windows. Enterprise-grade C2 detection without the enterprise price tag.

## What It Does

C2Monitor detects malware that has already bypassed your antivirus and is "phoning home" to an attacker's server. It catches:

- **Beaconing** - processes calling back at regular intervals (the #1 C2 signature)
- **Known C2 servers** - cross-references connections against abuse.ch Feodo Tracker (updated every 6 hours)
- **DGA domains** - randomly generated domain names used by malware (Shannon entropy analysis)
- **DNS tunneling** - data exfiltration over DNS from non-system processes
- **Phishing chains** - Office apps spawning cmd/powershell (initial access detection)
- **Encoded PowerShell** - obfuscated commands used by attackers
- **Lateral movement** - outbound RDP connections from your workstation
- **Unsigned executables** making network connections from temp folders

## Quick Install

Open PowerShell **as Administrator** and run:

```powershell
irm https://raw.githubusercontent.com/BengiaVentures/C2Monitor/main/Install-C2Monitor.ps1 | iex
```

Or download and run manually:

```powershell
powershell -ExecutionPolicy Bypass -File Install-C2Monitor.ps1
```

## What Gets Installed

| Component | Purpose | Resource Usage |
|-----------|---------|---------------|
| **Sysmon** (Microsoft) | Kernel-level network/process logging | ~26 MB RAM, always running |
| **Deep Scan** | Beaconing analysis + threat intel | ~100 MB, runs 10 min every 30 min, then exits |
| **Quick Watch** | Connection spot-checks | ~50 MB, runs few seconds every 5 min, then exits |
| **Notifier** | Desktop toast alerts | ~75 MB RAM, always running in your session |

**Total persistent footprint: ~120 MB RAM**

## How Detection Works

### Beaconing Detection
The deep scanner samples all outbound TCP connections 20 times over 10 minutes. It calculates the **coefficient of variation** of connection intervals per process/destination pair. A low CV (< 0.30) with consistent timing indicates automated beaconing rather than human-driven traffic.

### Threat Intelligence
Every 6 hours, the scanner downloads the latest known C2 server IPs from [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) and cross-references all active connections and Sysmon network logs against this list.

### DGA Detection
DNS queries logged by Sysmon are analyzed for **Shannon entropy**. Domains with entropy > 3.5 and length > 15 characters are flagged as potential Domain Generation Algorithm output.

### Process Lineage
Sysmon process creation events are checked for suspicious parent-child relationships (e.g., `WINWORD.EXE` spawning `powershell.exe`), which is the classic phishing attack chain.

## Alerts

When something is detected, you get:
1. **Desktop toast notification** (immediate, on-screen)
2. **Log entry** at `C:\ProgramData\C2Monitor\alerts.log`
3. **Windows Event Log** entry (Application > Source: C2Monitor)

Each alert includes: severity, description, process name, PID, full file path, remote IP:port, and SHA256 hash of the suspicious file.

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File C:\ProgramData\C2Monitor\Uninstall-C2Monitor.ps1
```

Cleanly removes everything: Sysmon, scheduled tasks, registry entries, and optionally archives your alert logs.

## Requirements

- Windows 10 or 11
- PowerShell 5.1+ (included with Windows)
- Administrator privileges (for Sysmon and scheduled tasks)
- ~120 MB RAM

## License

MIT
