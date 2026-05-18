# Credential Dumping Detection (T1003)

Detect attempts to dump credentials from memory or system storage.

## 🎯 Objective

Identify when attackers use tools like Mimikatz to extract passwords from system memory (LSASS) or SAM database.

## 🔍 What We're Detecting

### Attack Flow

```
Attacker gains initial access
         ↓
    Runs Mimikatz
         ↓
   Accesses LSASS memory
         ↓
  Extracts password hashes
         ↓
  Uses hashes for lateral movement
```

## 🛠️ Tools Used in This Attack

| Tool | Method | Detection Point |
|------|--------|------------------|
| **Mimikatz** | Memory dump | Process creation, DLL injection |
| **ProcDump** | LSASS dump | Process access, file creation |
| **Hashdump** | SAM registry | Registry access |
| **Secretsdump** | SAM/NTDS dump | Registry access |
| **LaZagne** | Stored credentials | Process creation, file access |

## 📊 Event Mapping

### Sysmon Events

| Event ID | Event Name | What We See |
|----------|------------|-------------|
| 1 | Process Creation | Mimikatz.exe launched |
| 3 | Network Connection | Mimikatz connecting to C2 |
| 8 | CreateRemoteThread | Injecting into LSASS |
| 10 | ProcessAccess | Accessing LSASS memory |
| 13 | RegistryEvent | Accessing SAM registry |
| 23 | FileDelete | Cleanup of artifacts |

## 🚨 Detection Rules

### Rule 1: Mimikatz Process Execution

**What**: Detect when mimikatz.exe is executed  
**When**: Process creation event  
**How**: Check for mimikatz binary name or suspicious command lines  

#### Sigma Rule

```yaml
title: Mimikatz Execution
id: 29b8faf5-5f21-4f3e-b8c6-d1d6c52a1d8b
status: stable
description: Detects execution of Mimikatz tool
references:
  - https://attack.mitre.org/techniques/T1003/
author: Security Team
date: 2024/05/18
logsource:
  product: windows
  service: sysmon
detection:
  selection_image:
    Image|endswith:
      - 'mimikatz.exe'
      - 'mimi.exe'
      - 'meow.exe'
  selection_commandline:
    CommandLine|contains:
      - 'lsadump::sam'
      - 'lsadump::secrets'
      - 'sekurlsa::logonpasswords'
      - 'vault::cred'
      - 'lsadump::cache'
      - 'token::elevate'
  condition: selection_image OR selection_commandline
falseposives:
  - Legitimate penetration testing
  - Red team exercises
levels: high
tags:
  - attack.credential_access
  - attack.t1003
```

#### Splunk SPL

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
EventCode=1
| search Image="*mimikatz.exe" OR Image="*mimi.exe" 
   OR CommandLine="*lsadump*" OR CommandLine="*sekurlsa*"
| stats count by Image, CommandLine, user, Computer
```

#### Elastic KQL

```
process.name:(mimikatz.exe OR mimi.exe) OR 
  process.command_line:(*lsadump* OR *sekurlsa* OR *vault*)
```

### Rule 2: LSASS Process Access

**What**: Detect suspicious access to LSASS process  
**When**: Process access event (Sysmon 10)  
**Why**: Credential dumping requires reading LSASS memory  

#### Splunk SPL

```spl
index=windows EventCode=10
TargetImage="C:\\Windows\\System32\\lsass.exe"
SourceImage!="C:\\Windows\\*"
| stats count by SourceImage, SourceUser, Computer
```

#### Elastic KQL

```
event.code:10 AND process.target.name:lsass.exe AND 
  NOT process.executable:"C:\\Windows\\*"
```

### Rule 3: Suspicious Registry Access (SAM)

**What**: Detect access to SAM registry hive  
**When**: Registry modification event  
**Why**: SAM contains password hashes  

#### Splunk SPL

```spl
index=windows EventCode=4657
ObjectName="\\Registry\\Machine\\SAM"
| stats count by SubjectUserName, Computer, ObjectName
```

---

## 📈 Alert Tuning

### False Positives

**Common Sources**:
- Backup/restoration tools accessing SAM
- Windows Update processes
- Anti-virus scans
- System maintenance tools

**Tuning**:
```spl
# Exclude known legitimate processes
| search NOT (SourceImage="C:\\Program Files\\*" OR 
              SourceImage="C:\\Windows\\*")
```

### Sensitivity Levels

**High Sensitivity** (catch everything):
- Include any LSASS access
- Risk: Many false positives

**Medium Sensitivity** (balanced):
- LSASS access from non-system processes
- From user-writable directories
- Recommended for production

**Low Sensitivity** (only obvious attacks):
- Only Mimikatz binary execution
- High-confidence indicators only

---

## 🔍 Investigation Steps

### When Alert Triggers

1. **Identify Source Process**
   - What process attempted the access?
   - From what location?
   - Run by which user?

2. **Check Process Ancestry**
   - What started this process?
   - Was it manually launched?
   - Or launched by another process?

3. **Review Timeline**
   - When did it happen?
   - Correlate with other events
   - Check for related alerts

4. **Analyze Context**
   - Normal work for this user/system?
   - Expected based on role?
   - Known legitimate tool?

5. **Determine Severity**
   - Confirmed attack = P1 (High)
   - Suspicious but explainable = P2 (Medium)
   - Likely benign = P3 (Low)

### Sample Investigation

**Alert**: "Mimikatz Execution Detected"

**Query to Investigate**:
```spl
index=windows EventCode=1 Image="*mimikatz*"
| stats earliest(_time) as First, latest(_time) as Last, 
        count as Total by user, Computer, CommandLine
```

**Questions**:
1. ✓ Is user an admin? → Yes → More suspicious
2. ✓ Is computer a server? → No, desktop → More suspicious
3. ✓ What command line used? → sekurlsa::logonpasswords → Definite attack
4. ✓ Any lateral movement after? → Search for SMB activity afterward

---

## 💼 Real World Example

### Scenario: Mimikatz Execution Detected

**Alert**: 2026-05-18 14:30:00  
**Computer**: WORKSTATION-42  
**User**: jsmith  
**Process**: C:\\Users\\jsmith\\Downloads\\mimikatz.exe  
**Command Line**: mimikatz.exe sekurlsa::logonpasswords exit  

**Investigation**:
```spl
# Get details
index=windows Computer=WORKSTATION-42 EventCode=1 
  Image="*mimikatz*"
| table _time, user, CommandLine, ParentImage

# Check for lateral movement after
index=windows Computer=WORKSTATION-42 
  _time>=2026-05-18T14:30:00
| search EventCode=3 AND DestinationPort=445
| table _time, DestinationIp, DestinationPort

# Check for LSASS access
index=windows EventCode=10 TargetImage="*lsass*" 
  _time>=2026-05-18T14:30:00
| table _time, SourceImage, SourceUser
```

**Findings**:
- ✅ Mimikatz executed from user Downloads
- ✅ Accessed LSASS memory
- ✅ Connected to internal file server (SMB)
- ✅ Accessed admin share C$

**Conclusion**: CONFIRMED ATTACK

---

## 🛡️ Remediation

If credential dumping detected:

### Immediate (0-30 min)
1. Isolate affected computer from network
2. Kill suspicious process
3. Capture memory for forensics
4. Review user RDP sessions

### Short-term (1-4 hours)
1. Reset passwords for compromised accounts
2. Review security event logs for lateral movement
3. Check for persistence mechanisms
4. Scan for malware

### Long-term (1-7 days)
1. Hunt for similar activity on other systems
2. Review all logons from compromised account
3. Check for data access/exfiltration
4. Implement LSA protection

---

## 📚 References

- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Windows LSASS Process](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/windbg-kernel-debugging-primer)
- [Credential Dumping Detection](https://medium.com/)

---

**Status**: ✅ Production Ready  
**Version**: 1.0  
**Last Updated**: 2026-05-18  
**Severity**: HIGH