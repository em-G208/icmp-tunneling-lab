# ICMP Tunneling: Data Exfiltration via Diagnostic Packets


## 1. Threat Context

ICMP (Internet Control Message Protocol) is a diagnostic protocol used for network health checks — most commonly via `ping`. It operates at Layer 3, uses no ports, and is allowlisted by default in most network environments.

Threat actors exploit this trust by embedding stolen data inside ICMP echo request payloads — a technique classified under **Living off the Land (LotL)**. No custom malware is deployed. The attack uses tools native to the
operating system, blending into normal administrative traffic.

**Why firewalls fail to catch this:**
- ICMP has no port number — port-based rules are irrelevant
- Deep Packet Inspection (DPI) on ICMP is rarely enforced due to CPU overhead
- The protocol is considered low-risk by default

**MITRE ATT&CK Mapping:**
- Tactic: Exfiltration
- Technique: T1048.003 — Exfiltration Over Alternative Protocol: Non-Application Layer Protocol

- The fact that this technique requires no custom malware, no elevated privileges beyond ping, and bypasses standard port-based inspection suggests it is likely underreported in SOC environments.
  Detection requires explicit ICMP payload monitoring — which is absent in most default SIEM configurations.


## 2. Lab Environment

All activity was conducted in an isolated local environment. No external network traffic was generated.

| Component        | Details                        |
|------------------|--------------------------------|
| Hypervisor       | VirtualBox                     |
| OS               | Ubuntu Linux                   |
| Network          | Loopback (127.0.0.1) — isolated|
| Packet Analyzer  | TShark                         |
| Attack Vector    | Native ping utility (LotL)     |

- Loopback interface was chosen intentionally. Using an external target — even for educational purposes — would generate real network traffic with a real payload. Ethical boundary: the technique is demonstrated, but contained.


## 3. Attack Execution

### Payload Preparation

Target string: `EXFILTRATED`  
Hex encoding: `4558464c4c545241544544`

The string is encoded in hexadecimal before injection. This is not obfuscation — ICMP simply accepts raw hex as padding input.

### Command

```bash
ping -c 1 -p 4558464c4c545241544544 127.0.0.1
```

**Flag breakdown:**
- `-c 1` — send one packet
- `-p 4558464c4c545241544544` — replace standard ICMP padding with this hex pattern
- `127.0.0.1` — loopback target (isolated lab)

### What happens at kernel level

The Linux kernel accepts the custom hex string and uses it to fill the 56-byte ICMP payload. The pattern repeats cyclically to fill the available space. The receiving host echoes the payload back — no inspection, no modification.

- During execution I noticed the captured payload did not begin with the expected hex sequence. The output started mid-pattern — TRATED instead of EXFILTRATED. This is because ping fills the 56-byte payload by repeating
  the 11-byte string cyclically, and TShark captures the raw bytes regardless of offset. Practical implication for detection: you cannot search for an exact string match. You need to search for anomalous entropy across
  the entire padding field.


## 4. Captured Evidence

### TShark Capture Command

```bash
sudo tshark -i lo -f "icmp" -w /tmp/icmp_tunnel_demo.pcap
```

### Analysis Command

```bash
sudo tshark -r /tmp/icmp_tunnel_demo.pcap -Y "icmp" -T fields -e ip.src -e ip.dst -e data
```

### Output

```
127.0.0.1   127.0.0.1   5452415445444558464c4c5452415445444558464c4c5452415445444558464c4c54524154454400
127.0.0.1   127.0.0.1   5452415445444558464c4c5452415445444558464c4c5452415445444558464c4c54524154454400
```

### What this output shows

- 2 packets: echo request + echo reply
- Both source and destination: `127.0.0.1` — traffic never left the lab
- `data` field contains the injected payload in hex
- Decoded: `TRATEDEXFILTRATED EXFILTRATED EXFILTRATED` — cyclic repetition of the 11-byte string filling the 56-byte payload
- The payload travels in **plaintext** — no encryption, no obfuscation. The only protection the attacker relies on is the absence of DPI.

- Two packets were captured: echo request and echo reply. The payload is identical in both, the receiving host echoed the data back without any modification or inspection. 
  This confirms the core vulnerability: the destination does not validate payload content. In a real exfiltration scenario, the attacker's C2 server would be the destination, silently logging every echo reply.


## 5. Detection Logic

### What to look for in a SOC environment

Standard ICMP echo request payload is 56 bytes of predictable padding:
`!"#$%&'()*+,-./0123456789...`

Any deviation from this pattern is anomalous.

### TShark — Live Detection Filter

```bash
sudo tshark -i eth0 -Y "icmp and data.len > 0" -T fields -e ip.src -e ip.dst -e data
```

### SIEM Correlation Rule Logic

| Signal | Threshold | Action |
|--------|-----------|--------|
| ICMP payload size > 64 bytes | Single occurrence | Investigate |
| ICMP payload entropy anomaly | Single occurrence | Investigate |
| ICMP request count from single source | > 10 per minute | Alert |
| ICMP traffic to external IP with non-standard payload | Single occurrence | Escalate |

### Limitations of size-based detection

Payload fragmentation bypasses size thresholds — an attacker can split data across multiple packets, each within normal size range. Reliable detection requires **frequency + entropy correlation**, not size alone.

- My initial assumption was that size-based filtering would be sufficient for detection. The lab showed otherwise, an attacker can fragment the payload across multiple packets, each within normal size range. 
  This shifted my detection logic from single-signal to correlation-based: size anomaly alone is a weak rule. Reliable detection requires combining payload size, packet frequency, and entropy analysis. 
  A SIEM rule triggering on any one of these individually will generate noise. The value is in the intersection.


## 6. References

### MITRE ATT&CK
- [T1048.003 — Exfiltration Over Alternative Protocol: Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1048/003/)
- [T1095 — Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/)

### Tools Used
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
- [ping (Linux man page)](https://linux.die.net/man/8/ping)

### Lab Environment
- All activity conducted on isolated loopback interface (127.0.0.1)
- No external network traffic generated
- pcap file included in repository: `icmp_tunnel_demo.pcap`

- This lab was built without prior hands-on experience in packet analysis. Primary references were MITRE ATT&CK documentation and TShark man pages. 
  The goal was not to replicate a known walkthrough but to understand the mechanism well enough to explain detection logic from first principles.
