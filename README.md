# Detection and Mitigation of ICMP-DDoS Flood Attacks in SDN
 
A real-time DDoS detection and mitigation system built on a Software-Defined Networking (SDN) environment using a Ryu controller and Mininet topology.
 
---
 
## Overview
 
ICMP flood attacks are particularly damaging in SDN environments because they overwhelm both the victim host and the controller's processing queue simultaneously. Existing defenses rely on static thresholds and binary IP blocking — neither of which adapts well to changing traffic conditions or avoids collateral damage to legitimate users.
 
This project implements an adaptive, multi-feature detection system with graduated rate-limiting mitigation using OpenFlow 1.3 meters.
 
---
 
## Architecture
   <img width="350" height="257" alt="topology" src="https://github.com/user-attachments/assets/b95567db-a33a-490c-9039-4cd24ac38436" />

 
---
 
## How It Works

 <img width="450" height="1000" alt="flow" src="https://github.com/user-attachments/assets/f874ada1-4475-4489-abb2-68081aa22221" />

### 1. Baseline Characterization
Before detection begins, the system collects 60 seconds of clean traffic to derive a statistical baseline:
- Mean (μ) and standard deviation (σ) of destination IP entropy (F2)
- Warning threshold: `T_warn = μ + 2σ`
- Attack threshold: `T_attack = μ + 3σ`
 
This eliminates topology-dependent fixed thresholds used in prior work.
 
### 2. Feature Extraction (per 5s sliding window)
 
| Feature | Description |
|---------|-------------|
| F1 | Source IP entropy |
| F2 | Destination IP entropy (primary trigger) |
| F3 | ICMP Type-8 / Total ICMP ratio |
| F4 | Packet-In event rate at controller |
 
### 3. Two-Tier Detection Logic
 
A window is flagged as an attack only when **both** conditions hold:
- **Primary:** `F2 ≥ T_attack`
- **Secondary:** `F3 > 0.80` OR `F4 > 2 × baseline`
 
The secondary condition prevents flash-crowd false positives — legitimate users pinging the same server collapse entropy (triggering primary) but receive replies, keeping F3 near 0.50.
 
### 4. Adaptive Sliding Window
 
The step size S is dynamic based on detection state:
- **Normal State** → large steps (low CPU overhead)
- **Warning State** → step halved (increased resolution)
- **Attack State** → step reduced further (high precision)

  <img width="400" height="200" alt="adaptive" src="https://github.com/user-attachments/assets/299ff64a-b926-4f22-8049-af5ad378b2dc" />

 
### 5. Graduated Mitigation (OpenFlow 1.3 Meters)
 
Mitigation uses a quadratic rate formula:
 
    Rate = Base_Rate × (1 - Confidence)²
    where Confidence = K/3
 
| Level | Windows (K) | Confidence | Permitted Rate |
|-------|-------------|------------|----------------|
| 1 | 1 | 0.33 | 45 pps |
| 2 | 2 | 0.67 | 11 pps |
| 3 | 3 | 1.00 | 0 pps (Block) |
 
Mitigation targets ICMP Type-8 packets only — TCP and Echo Reply traffic are untouched.
At Level 3, a `hard_timeout` is installed on the blocking rule for automatic rule expiry without manual intervention.
 
---
 
## Results
 
| Metric | Value |
|--------|-------|
| Attack Suppression Rate (steady-state) | 98.3% |
| Detection Latency (Level 1) | 0.5s |
| Full Mitigation Latency (Level 3) | 0.75s |
| False Positive Rate (distributed traffic) | 0.0% |
| False Positive Rate (ICMP flash crowd) | 21.4% |
 
### Suppression Across Attack Scenarios
 
| Scenario | Total pps | ASR |
|----------|-----------|-----|
| Heavy flood | 45,000 | 98.3% |
| Moderate flood | 10,000 | 98.3% |
| Burst flood | 150,000 | 95.8% |
| Slow flood (15 pps) | 15 | 98.3% |
 
---
 
## Tech Stack
 
- **Controller:** Ryu SDN Framework
- **Network Emulation:** Mininet
- **Protocol:** OpenFlow 1.3
- **Language:** Python
 
---
 
## Known Limitations
 
- FPR spikes to 21.4% during ICMP-based flash crowds due to dual-triggering of F3 and F4
- Full self-healing recovery loop is not yet implemented; hard-timeout handles rule expiry but re-evaluation post-timeout is a planned extension
 
---
 
## References
 
Key prior work this builds on:
- Mousavi & St-Hilaire (2015) — entropy-based early DDoS detection in SDN
- Hemmati et al. (2021) — dynamic threshold framework (μ ± kσ)
- Dharma et al. (2015) — time-based observation windows
- Yan et al. (2016) — limitations of binary IP blocking in SDN
 
Full reference list in the project report- [Computer_Networks_final-report.pdf](https://github.com/user-attachments/files/27788425/Computer_Networks__Abstract_and_Background.12.pdf)

 
---
 
