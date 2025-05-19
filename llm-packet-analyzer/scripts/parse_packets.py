from scapy.all import rdpcap
from datetime import datetime

def parse_pcap(file_path='capture.pcap', output_log='packet_log.txt'):
    packets = rdpcap(file_path)
    logs = []

    for pkt in packets:
        if not pkt.haslayer('IP'):
            continue  # Ignore non-IP packets

        src = pkt['IP'].src
        dst = pkt['IP'].dst
        proto = pkt['IP'].proto
        timestamp = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S')
        length = len(pkt)

        # Get TCP flags if it’s a TCP packet
        flags = ''
        if pkt.haslayer('TCP'):
            flags = pkt['TCP'].flags

        log = f"[{timestamp}] Protocol: {proto} | Src: {src} | Dst: {dst} | Len: {length} | Flags: {flags}"
        logs.append(log)

    with open(output_log, 'w') as f:
        for line in logs:
            f.write(line + '\n')

    print(f"[*] Parsed {len(logs)} packets. Output saved to {output_log}")

if __name__ == "__main__":
    parse_pcap()
