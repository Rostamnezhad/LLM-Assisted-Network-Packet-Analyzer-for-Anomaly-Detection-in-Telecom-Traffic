from scapy.all import sniff, wrpcap

def capture_packets(output_file='capture.pcap', packet_count=100):
    print(f"[*] Capturing {packet_count} packets...")
    packets = sniff(count=packet_count)
    print(f"[*] Saving to {output_file}")
    wrpcap(output_file, packets)
    print("[*] Capture complete.")

if __name__ == "__main__":
    capture_packets()