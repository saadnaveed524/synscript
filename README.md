# synscript
#SYN python script

#!/usr/bin/env python3
# syn_ping.py — Send only TCP SYN packets (probe or nowait)
# Usage:
#   sudo python3 syn_ping.py 192.168.1.10        # probe mode (default)
#   sudo python3 syn_ping.py 192.168.1.10 --nowait
#   sudo python3 syn_ping.py -f targets.txt -p 443 -r 2

import argparse, time
from scapy.all import IP, TCP, send, sr1, conf

conf.verb = 0

def syn_probe(target, port=80, timeout=2.0, sport=40000):
    pkt = IP(dst=target) / TCP(dport=port, sport=sport, flags="S", seq=1000)
    try:
        resp = sr1(pkt, timeout=timeout)
        if resp is None:
            return "no-response"
        if resp.haslayer(TCP):
            r = int(resp[TCP].flags)
            if r == 0x12:  # SYN-ACK
                # polite RST to close half-open connection
                rst = IP(dst=target) / TCP(dport=port, sport=sport, flags="R", seq=0, ack=resp[TCP].seq+1)
                send(rst, verbose=0)
                return "syn-ack"
            if r & 0x04:  # RST
                return "rst"
            return f"tcp-other(0x{r:x})"
        return "non-tcp-response"
    except Exception as e:
        return f"error:{e}"

def syn_nowait(target, port=80, sport=40000):
    pkt = IP(dst=target) / TCP(dport=port, sport=sport, flags="S", seq=1000)
    send(pkt, verbose=0)
    return "sent"

def main():
    p = argparse.ArgumentParser(description="SYN-only ping")
    p.add_argument("target", nargs="?", help="Target IP/host")
    p.add_argument("-f","--file", help="File with targets (one per line)")
    p.add_argument("-p","--port", type=int, default=80, help="Destination port (default 80)")
    p.add_argument("-t","--timeout", type=float, default=2.0, help="Probe timeout (s)")
    p.add_argument("-r","--rate", type=float, default=1.0, help="Packets per second")
    p.add_argument("--nowait", action="store_true", help="Fire-and-forget (send SYN only)")
    args = p.parse_args()

    targets=[]
    if args.file:
        with open(args.file) as fh:
            for ln in fh:
                ln=ln.strip()
                if ln and not ln.startswith("#"):
                    targets.append(ln)
    elif args.target:
        targets=[args.target]
    else:
        p.error("Provide target or -f file")

    print(f"SYN ping -> targets={len(targets)}, port={args.port}, mode={'nowait' if args.nowait else 'probe'}")
    idx=0
    for t in targets:
        idx+=1
        sport = 40000 + (idx % 20000)
        if args.nowait:
            res = syn_nowait(t, port=args.port, sport=sport)
        else:
            res = syn_probe(t, port=args.port, timeout=args.timeout, sport=sport)
        print(f"{t}:{args.port} -> {res}")
        if args.rate>0:
            time.sleep(1.0/args.rate)

if __name__=="__main__":
    main()
