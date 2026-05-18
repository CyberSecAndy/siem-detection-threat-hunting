# Contributing to SIEM Detection & Threat Hunting

Contributions are welcome! Here's how you can help.

## Types of Contributions

### 1. New Detection Rules

**What**: Create detection rules for new attack techniques  
**Include**:
- Sigma rule (universal format)
- Splunk SPL version
- Elastic KQL version
- README with context
- Example detections
- False positive analysis

### 2. Threat Hunting Playbooks

**What**: Document hunting procedures  
**Include**:
- Clear objective
- Threat model explanation
- Hunting queries
- Investigation steps
- Real-world case study
- Remediation guidance

### 3. Improvements

**What**: Improve existing content  
**Examples**:
- Better query performance
- Clearer documentation
- Additional examples
- New query variations

## Submission Guidelines

### Detection Rules

```
detections/[technique-name]/
├── README.md              # Technical explanation
├── sigma.yml             # Sigma format rule
├── splunk-spl.txt        # Splunk SPL query
├── elastic-kql.txt       # Elastic KQL query
└── examples/             # Sample alert screenshots
```

### Hunting Playbooks

```
threat-hunting/playbooks/
└── hunting-for-[technique].md
```

## Quality Standards

- [ ] Rule tested against real logs
- [ ] All three formats included (Sigma, Splunk, Elastic)
- [ ] Documentation clear and complete
- [ ] MITRE ATT&CK technique mapped
- [ ] False positive analysis included
- [ ] Examples with real data
- [ ] Links to relevant resources

## Process

1. Fork repository
2. Create feature branch: `git checkout -b feature/new-detection`
3. Add your contribution
4. Create Pull Request
5. Address review feedback
6. Merge when approved

Thank you for contributing!