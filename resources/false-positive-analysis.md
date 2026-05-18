# False Positive Analysis & Alert Tuning

## Understanding False Positives

### Definitions

**False Positive (FP)**: Alert triggered by legitimate activity  
**False Negative (FN)**: Malicious activity not detected  
**True Positive (TP)**: Alert triggered by actual attack  
**True Negative (TN)**: Legitimate activity not alerted  

```
                 Alerted    Not Alerted
Malicious         TP            FN
Legitimate        FP            TN
```

### The FP Problem

**Issue**: Too many false positives cause alert fatigue
- Analysts ignore alerts
- Real attacks missed
- Burnout and turnover
- SOC effectiveness decreases

**Solution**: Balance sensitivity and specificity

---

## Common Sources of False Positives

### 1. System Administration

**Activity**: Admins accessing LSASS for troubleshooting  
**Detection**: Triggers credential dumping alert  
**Solution**: Whitelist admin accounts and tools  

**Example Query**:
```spl
index=windows EventCode=10 TargetImage="*lsass*"
| search NOT (SourceImage="C:\\Windows\\System32\\svchost.exe" 
              OR SourceImage="C:\\Program Files\\*")
```

### 2. Antivirus/EDR Scans

**Activity**: AV scanning system processes  
**Detection**: Triggers process access alerts  
**Solution**: Whitelist AV processes  

**Example**:
```spl
index=windows EventCode=10
| search NOT (SourceImage="*McAfee*" OR SourceImage="*Symantec*" 
              OR SourceImage="*Kaspersky*")
```

### 3. Backup Software

**Activity**: Backup accessing SAM registry  
**Detection**: Triggers SAM access alert  
**Solution**: Whitelist backup service account  

### 4. Windows Update

**Activity**: Update service modifying files/registry  
**Detection**: Triggers persistence alerts  
**Solution**: Exclude Windows Update processes  

### 5. Legitimate Tools

**Activity**: Password managers, system utilities  
**Detection**: Triggers credential access alerts  
**Solution**: Whitelist approved tools  

---

## Tuning Strategy

### Phase 1: Baseline (Week 1)

1. Deploy rules with minimal tuning
2. Accept higher FP rate temporarily
3. Document all alerts
4. Categorize alert sources

### Phase 2: Analysis (Week 2-3)

1. Analyze FP patterns
2. Identify common legitimate sources
3. Note FP rate by rule
4. Prioritize rules needing tuning

### Phase 3: Tuning (Week 4+)

1. Add exclusions for known FP sources
2. Adjust thresholds
3. Refine rule logic
4. Monitor new FP rates

### Phase 4: Optimization (Ongoing)

1. Continue monitoring FP trends
2. Add new exclusions as discovered
3. Adjust based on business changes
4. Maintain documentation

---

## Tuning Examples

### Example 1: Credential Dumping Alert

**Original Rule**:
```spl
index=windows EventCode=10
TargetImage="*lsass*"
```

**Problem**: Alerts on legitimate AV/EDR access  
**FP Rate**: 50%  
**TP Rate**: 50%  

**Tuned Rule**:
```spl
index=windows EventCode=10
TargetImage="*lsass*"
| search NOT (
    SourceImage="C:\\Program Files\\*" OR
    SourceImage="C:\\Windows\\*" OR
    SourceImage in ("C:\\Program Files (x86)\\McAfee\\*",
                    "C:\\Program Files\\SentinelOne\\*")
  )
```

**Result**:  
**FP Rate**: 5%  
**TP Rate**: 95%  

### Example 2: Lateral Movement Alert

**Original Rule**:
```spl
index=windows EventCode=4688
CommandLine="*psexec*" OR CommandLine="*PsExec*"
```

**Problem**: Alerts on internal IT using PsExec  
**FP Rate**: 70%  

**Tuned Rule**:
```spl
index=windows EventCode=4688
(CommandLine="*psexec*" OR CommandLine="*PsExec*")
| search NOT (
    user IN ("DOMAIN\\IT_ADMIN", "DOMAIN\\SYS_ADMIN")
    OR Computer LIKE "ADMIN-%"
  )
```

**Result**:  
**FP Rate**: 20%  
**TP Rate**: 98%  

---

## Exclusion Strategies

### Whitelist by Source

```spl
# Exclude known legitimate processes
| search NOT SourceImage IN (
    "C:\\Program Files\\CommonFiles\\*",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\System32\\svchost.exe"
  )
```

### Whitelist by User

```spl
# Exclude admin accounts
| search NOT user IN (
    "DOMAIN\\Administrator",
    "DOMAIN\\IT_ADMIN",
    "SYSTEM",
    "LOCAL SERVICE"
  )
```

### Whitelist by Computer

```spl
# Exclude admin systems
| search NOT Computer IN (
    "ADMIN-WKS-01",
    "SERVER-ADMIN-01",
    "SIEM-SERVER"
  )
```

### Whitelist by Time

```spl
# Exclude maintenance windows
| where NOT (dow=0 AND hour>=22)
```

---

## Monitoring FP Rates

### Dashboard Query

```spl
index=main source="alerts"
| stats 
    sum(eval(if(alert_type="false_positive", 1, 0))) as FPs,
    sum(eval(if(alert_type="true_positive", 1, 0))) as TPs,
    sum(eval(if(alert_type="investigating", 1, 0))) as Unknown
  by rule_name
| eval FP_Rate=round(FPs/(FPs+TPs+Unknown)*100, 2)
| table rule_name, TPs, FPs, Unknown, FP_Rate
| sort - FP_Rate
```

### Target FP Rates by Rule Type

| Rule Type | Target FP Rate | Action If Higher |
|-----------|---------------|-----------------|
| Definite Attack (Mimikatz) | < 5% | Tune |
| High-Risk Pattern | 5-15% | Monitor |
| Medium-Risk Pattern | 15-30% | Review |
| Low-Risk Pattern | 30-50% | Consider disable |

---

## Best Practices

1. **Start Aggressive**: Better to have more alerts initially
2. **Tune Gradually**: Don't over-tune, miss attacks
3. **Document Changes**: Track tuning decisions
4. **Monitor Trends**: FP rates should decrease over time
5. **Involve Analysts**: Front-line analysts know FP sources
6. **Review Monthly**: Regular tuning sessions
7. **Communicate Changes**: Tell analysts about tuning

---

**Status**: Reference Guide  
**Version**: 1.0  
**Last Updated**: 2026-05-18