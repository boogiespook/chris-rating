# Common Hierarchical Risk Intelligence Score (CHRIS) Rating

## Workflow

1. KEV (Highest Priority)
If a vulnerability is in KEV, it's immediately critical. Assign a very high base score, then add modifiers. This ensures KEV always pushes it to the highest tier.

``` 
score = 85 # Base for actively exploited vulnerabilities 
```

Add a bonus based on EPSS and CVSS for actively exploited ones
```
score += int(epss_score * 10)  # Up to +10 for EPSS (e.g., 0.9 EPSS adds 9)
score += int(cvss_base_score * 0.5) # Up to +5 for CVSS (e.g., CVSS 10 adds 5)
```

2. EPSS Score (High Probability of Exploitation)
EPSS indicates how likely it is to be exploited in the wild. Higher EPSS score, higher immediate risk

3. CVSS Base Score (Technical Severity)
Adjust score based on CVSS, with diminishing returns as EPSS already sets a base

4. Asset Criticality (Business Impact)
This is crucial for internal prioritization. You'll need to get asset_criticality from an internal asset inventory.

### Example 1 (High CVE)
```
$ python3 ./chris_score.py CVE-2025-27363
Processing CVE: CVE-2025-27363

KEV Status: In KEV
EPSS Score: 0.6842
CVSS Base Score: 8.1
CVE Severity (Red Hat): Important

Assumed Asset Criticality (based on CVE Severity placeholder): High
-----------------------------------------------------------------

Common Hierarchical Risk Intelligence Score (CHRIS) for CVE-2025-27363: 95/100
```

### Example 2 (Low CVE)
```
$ python3 ./chris_score.py CVE-2025-23165
Processing CVE: CVE-2025-23165

KEV Status: Not in KEV
EPSS Score: 0.0006
CVSS Base Score: 3.7
CVE Severity (Red Hat): Low

Assumed Asset Criticality (based on CVE Severity placeholder): Low
-----------------------------------------------------------------

Common Hierarchical Risk Intelligence Score (CHRIS) for CVE-2025-23165: 10/100
```
