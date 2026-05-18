# SIEM Detection & Threat Hunting Lab

Practical detection engineering and threat hunting using real logs from the Home SOC Lab environment.

## 🎯 Overview

This project provides hands-on experience with:

- **Detection Rule Creation**: Build Sigma, Splunk SPL, and Elastic KQL rules
- **Threat Hunting**: Proactively hunt for indicators of compromise
- **SIEM Queries**: Master advanced query languages
- **Alert Tuning**: Reduce false positives, increase true positives
- **Threat Intelligence**: Apply IOC-based detection
- **Incident Investigation**: Analyze events to understand attacks

## 📚 What You'll Learn

✅ Write effective detection rules  
✅ Master Splunk SPL and Elastic KQL  
✅ Understand Sigma rule format  
✅ Perform threat hunting at scale  
✅ Correlate events across systems  
✅ Identify attack patterns  
✅ Reduce alert fatigue  
✅ Create hunting playbooks  
✅ Build SOC dashboards  
✅ Automate detection workflows  

## 🏗️ Project Structure

```
siem-detection-threat-hunting/
├── README.md
├── GETTING-STARTED.md
├── detections/
│   ├── credential-dumping/
│   │   ├── README.md
│   │   ├── sigma.yml
│   │   ├── splunk-spl.txt
│   │   ├── elastic-kql.txt
│   │   └── examples/
│   ├── lateral-movement/
│   ├── privilege-escalation/
│   ├── persistence/
│   ├── data-exfiltration/
│   └── ransomware/
├── threat-hunting/
│   ├── playbooks/
│   │   ├── hunting-for-encoded-powershell.md
│   │   ├── hunting-for-credential-dumping.md
│   │   ├── hunting-for-lateral-movement.md
│   │   ├── hunting-for-persistence.md
│   │   └── hunting-for-data-exfiltration.md
│   ├── queries/
│   │   ├── splunk/
│   │   ├── elastic/
│   │   └── README.md
│   └── dashboards/
│       ├── splunk-dashboards.xml
│       └── elastic-dashboards.json
├── resources/
│   ├── false-positive-analysis.md
│   ├── mitre-detection-mapping.md
│   ├── siem-query-reference.md
│   └── alert-tuning-guide.md
└── examples/
    ├── detected-attacks/
    └── case-studies/
```

## 🚀 Quick Start

### Prerequisites

- Home SOC Lab deployed and running
- Access to SIEM (Splunk or Elastic)
- Windows logs being collected
- Sysmon events available

### Step 1: Connect to Your SIEM

**Elastic Stack**:
```
URL: http://192.168.100.30:5601
Index Pattern: winlogbeat-*
```

**Splunk**:
```
URL: http://192.168.100.30:8000
Index: windows
```

### Step 2: Explore Available Events

**Elastic KQL**:
```
host.name:"Windows-Target"
```

**Splunk SPL**:
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
```

### Step 3: Use Detection Rules

Start with credential dumping detection:

**Directory**: `detections/credential-dumping/`

---

## 🔍 Detection Categories

### 1. Credential Dumping (T1003)

**What**: Attackers extract passwords from memory or SAM database  
**Why**: To move laterally and escalate privileges  
**How Detected**: Monitor process access to LSASS, registry access to SAM  
**Tools**: Mimikatz, ProcDump, Hashdump  
**Sigma Rule**: `detections/credential-dumping/sigma.yml`  
**Splunk Query**: `detections/credential-dumping/splunk-spl.txt`  
**Elastic Query**: `detections/credential-dumping/elastic-kql.txt`  

### 2. Lateral Movement (T1021)

**What**: Attackers move from one system to another  
**Why**: To find valuable data or escalate privileges  
**How Detected**: Monitor authentication events, SMB activity, RDP sessions  
**Techniques**: PsExec, WMI, RDP, SSH, SMB shares  
**Indicators**: Unusual service creation, admin shares accessed, logon event chains  

### 3. Privilege Escalation (T1548)

**What**: Attackers escalate from user to admin privileges  
**Why**: To access restricted files and execute privileged commands  
**How Detected**: Monitor UAC bypass attempts, service modification, token impersonation  
**Techniques**: UAC bypass, DLL injection, Token impersonation, Kernel exploit  

### 4. Persistence (T1547)

**What**: Attackers establish mechanisms to maintain access  
**Why**: To ensure long-term presence even if initial access is removed  
**How Detected**: Monitor registry modifications, scheduled task creation, service installation  
**Techniques**: Registry Run keys, scheduled tasks, WMI subscriptions, logon scripts  

### 5. Data Exfiltration (T1041)

**What**: Attackers move data outside the network  
**Why**: To steal sensitive information for profit or espionage  
**How Detected**: Monitor network traffic, DNS queries, file size transfers  
**Techniques**: DNS tunneling, HTTPS tunneling, SMB exfiltration, FTP transfers  

### 6. Ransomware (T1561)

**What**: Attackers encrypt files and demand payment  
**Why**: Extortion and disruption  
**How Detected**: Monitor file modifications, process execution patterns, shadow copy deletion  
**Indicators**: Rapid file changes, extension changes, suspicious file deletion, high disk I/O  

---

## 📊 MITRE ATT&CK Mapping

| Technique | ID | Detection Coverage |
|-----------|----|-----------|
| Credential Dumping | T1003 | ✅ High |
| Remote Services | T1021 | ✅ High |
| Privilege Escalation | T1548 | ✅ Medium |
| Boot/Logon Autostart | T1547 | ✅ High |
| Exfiltration Over C2 | T1041 | ✅ Medium |
| Disk Content Wipe | T1561 | ✅ High |
| PowerShell | T1086 | ✅ High |
| Windows Admin Shares | T1570 | ✅ High |
| Service Creation | T1543 | ✅ High |

---

## 🎓 Learning Path

### Phase 1: Fundamentals (4-6 hours)

1. Read GETTING-STARTED.md
2. Explore SIEM interfaces
3. Run basic queries
4. Understand Sysmon event IDs
5. Review Windows event log structure

### Phase 2: Detection Rules (6-8 hours)

1. Study Sigma rule format
2. Convert Sigma to Splunk SPL
3. Convert Sigma to Elastic KQL
4. Test rules against sample data
5. Analyze false positives

### Phase 3: Threat Hunting (6-8 hours)

1. Work through hunting playbooks
2. Execute hunting queries
3. Correlate events
4. Document findings
5. Create case studies

### Phase 4: Advanced Topics (6-8 hours)

1. Build custom dashboards
2. Create alert rules
3. Implement detection tuning
4. Correlate across systems
5. Build threat intelligence integrations

**Total**: 22-30 hours for complete mastery

---

## 🛠️ Using the Resources

### Detection Rules

Each detection rule includes:

- **Sigma Format** (universal, platform-agnostic)
- **Splunk SPL** (Splunk Query Language)
- **Elastic KQL** (Kibana Query Language)
- **Example Detections** (real attack screenshots)
- **False Positive Analysis** (tuning guidance)
- **MITRE Mapping** (technique reference)

### Threat Hunting Playbooks

Each playbook includes:

- **Objective**: What you're hunting for
- **Threat Model**: Why attackers do this
- **IOCs**: Indicators to look for
- **Queries**: Pre-built SIEM queries
- **Analysis Steps**: How to investigate findings
- **Case Study**: Real example with findings

---

## 🔗 Integration with Home SOC Lab

This project uses logs from **Home SOC Lab** attack scenarios:

```
Home SOC Lab Attack Scenario
         ↓
  Sysmon Event Logging
         ↓
  Winlogbeat Forwarding
         ↓
  Elasticsearch/Splunk
         ↓
  Detection Rules Applied
         ↓
Detection & Investigation (This Project)
```

**To use these rules**:

1. Deploy Home SOC Lab
2. Run attack scenarios from `attack-scenarios/`
3. Apply detection rules from this project
4. Verify detections trigger
5. Tune based on results

---

## 📈 Key Concepts

### False Positive (FP)

**Definition**: Alert triggered by legitimate activity  
**Problem**: Analysts waste time on non-threats  
**Solution**: Tune rules to exclude known legitimate patterns  

### True Positive (TP)

**Definition**: Alert triggered by actual malicious activity  
**Goal**: Maximize these  
**Method**: Write specific rules, ignore noise  

### Sensitivity vs Specificity

- **High Sensitivity**: Catch everything (but lots of false positives)
- **High Specificity**: Only alert on definite threats (but miss some)
- **Sweet Spot**: Balance both

---

## 💡 Best Practices

### Rule Development

1. **Start Specific**: Write very specific rules first
2. **Test Thoroughly**: Validate against real data
3. **Document Well**: Explain detection logic
4. **Monitor FPs**: Track and tune over time
5. **Use Baselines**: Understand normal activity first

### Threat Hunting

1. **Have Hypothesis**: Hunt for something specific
2. **Follow Data**: Let evidence guide you
3. **Document Steps**: Record your process
4. **Share Findings**: Communicate discoveries
5. **Iterate**: Refine based on learning

### Alert Tuning

1. **Establish Baseline**: What's normal?
2. **Identify Noise**: What causes false positives?
3. **Exclude Known Good**: Whitelist legitimate activity
4. **Adjust Thresholds**: Find the right sensitivity
5. **Monitor Trends**: Track FP rates over time

---

## 📖 How to Use This Repository

### For Learning Detections

1. Pick a detection: `detections/credential-dumping/`
2. Read README.md for context
3. Review Sigma rule: `sigma.yml`
4. Study Splunk version: `splunk-spl.txt`
5. Compare Elastic version: `elastic-kql.txt`
6. Look at examples: `examples/`

### For Threat Hunting

1. Pick a playbook: `threat-hunting/playbooks/`
2. Read objective and threat model
3. Review provided queries
4. Execute in your SIEM
5. Follow analysis steps
6. Document findings

### For Building Dashboards

1. Access dashboards: `threat-hunting/dashboards/`
2. Import into your SIEM
3. Customize visualizations
4. Add to hunting toolkit

---

## 🔗 Cross-Project Integration

This project connects with:

- **[Home SOC Lab](https://github.com/CyberSecAndy/Home-SOC-Lab)** ← Uses logs from here
- **[Detection Rule Engineering](https://github.com/CyberSecAndy/detection-rule-engineering)** → Deep dive into rule creation
- **[Incident Response Case Studies](https://github.com/CyberSecAndy/incident-response-case-studies)** → Documents investigations
- **[SOC Automation Scripts](https://github.com/CyberSecAndy/soc-automation-scripts)** → Automates detection tasks

---

## 📚 External Resources

### Detection Frameworks
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Splunk SPL](https://docs.splunk.com/Documentation/Splunk/9.0.0/Search/GetstartedwithSearch)
- [Elastic Query Language](https://www.elastic.co/guide/en/kibana/current/kuery.html)

### Detection Resources
- [Splunk Boss of the SOC](https://www.splunk.com/en_us/boss-of-the-soc.html)
- [Elastic Security Labs](https://www.elastic.co/security-labs)
- [Windows Event Log ID Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Sysmon Event ID Reference](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)

---

## ✅ Verification Checklist

Before starting:

- [ ] Home SOC Lab deployed and running
- [ ] Logs flowing to SIEM
- [ ] Can access SIEM UI
- [ ] Sample Windows events visible
- [ ] Sysmon events showing
- [ ] Can execute basic queries

---

## 📞 Support

For issues or questions:

1. Check [GETTING-STARTED.md](GETTING-STARTED.md)
2. Review resource guides
3. Create GitHub issue
4. Reference [Home SOC Lab troubleshooting](https://github.com/CyberSecAndy/Home-SOC-Lab/blob/main/SETUP-GUIDE.md#part-6-troubleshooting)

---

**Status**: 🟢 Production Ready  
**Version**: 1.0.0  
**Last Updated**: 2026-05-18  
**Difficulty**: Intermediate  
**Time to Master**: 22-30 hours  

**Let's Hunt! 🕵️**