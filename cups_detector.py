import time
import json
import logging
import ipaddress
import argparse
from collections import defaultdict
from cups_logging import setup_logging
from scapy.all import sniff, IP, UDP, TCP, Raw

ALLOWLIST = []
alerts = []
seen = defaultdict(list)
WINDOW = 10
THRESHOLD = 5

def is_public_ip(ip):
    return not ipaddress.ip_address(ip).is_private

def export_json(out=None):
    if out:
        filename = out
    else:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"evidence/alerts_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(alerts, f, indent=2)
    return filename

def raise_alert(alert_type, src, detail):
    alert = {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
             "type": alert_type,
             "source": src,
             "detail": detail}
    alerts.append(alert)
    logging.warning(f"ALERT: {alert_type} from {src}: {detail}")

def parse_browse_string(payload):
    """Parse a CUPS Browse string."""
    text = payload.decode(errors='ignore').strip()
    parts = text.split(' ', 2)
    if len(parts) != 3:
        return None
    return {"ptype": parts[0], "pstate": parts[1], "uri": parts[2]}

def add_detector_arguments(parser):
    parser.add_argument("-i", "--iface", help="Interface for live monitoring")
    parser.add_argument("-r", "--pcap", help="Read packets from a pcap file (offline)")
    parser.add_argument("--allowlist", nargs="+", default=["172.18.0.3"],
                        help="Allowed printer source IPs")
    parser.add_argument("-o", "--out", help="Output filename for alerts (default: timestamped)")
    parser.add_argument("--log", help="Filename for logs")
    parser.add_argument("--window", type=int, default=10,
                        help="Seconds for repeated-discovery window")
    parser.add_argument("--threshold", type=int, default=5,
                        help="Max packets per window before REPEATED")

def handle_packet(pkt):
    """Called for each sniffed packet."""
    if pkt.haslayer(UDP) and pkt[UDP].dport == 631 and pkt.haslayer(Raw):
        src = pkt[IP].src
        payload = pkt[Raw].load
        fields = parse_browse_string(payload)

        if fields is None:
            raise_alert("MALFORMED", src, f"could not parse packet: {payload!r}")
            return

        uri = fields["uri"]
        if src not in ALLOWLIST:
            raise_alert("UNAUTHORIZED", src, f"advertised printer: {uri}")

        now = time.time()
        seen[src].append(now)
        seen[src] = [t for t in seen[src] if now - t <= WINDOW]
        if len(seen[src]) > THRESHOLD:
            raise_alert("REPEATED", src, f"{len(seen[src])} packets in {WINDOW} seconds")

    elif pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
        dst = pkt[IP].dst
        dport = pkt[TCP].dport
        if is_public_ip(dst):
            raise_alert("IPP CONNECTION", pkt[IP].src, 
                        f"connection attempt to PUBLIC address {dst}:{dport}")

def run_detector(args):
    setup_logging(args.log)

    global ALLOWLIST, WINDOW, THRESHOLD
    ALLOWLIST = args.allowlist
    WINDOW = args.window
    THRESHOLD = args.threshold

    try:
        if args.pcap:
            print(f"Offline mode: reading packets from {args.pcap}")
            sniff(offline=args.pcap, filter="udp port 631 or tcp",
                  prn=handle_packet, store=False)
        else:
            print(f"Live mode: sniffing on interface {args.iface}")
            sniff(iface=args.iface, filter="udp port 631 or tcp", 
                  prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        filename = export_json(args.out)
        print(f"Exported {len(alerts)} alerts to {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="CUPS Detection Tool - monitors for suspicious cups-browsed activity",
        epilog="Example (live):   sudo python3 cups_detector.py -i br-954f941dcf7f\n"
               "Example (offline): python3 cups_detector.py -r pcap_files/attack.pcap",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_detector_arguments(parser)
    args = parser.parse_args()

    if not args.iface and not args.pcap:
        parser.error("provide either --iface (live) or --pcap (offline)")

    run_detector(args)

if __name__ == "__main__":
    main()
