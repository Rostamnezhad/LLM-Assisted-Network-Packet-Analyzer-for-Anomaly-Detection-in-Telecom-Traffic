def rule_based_analysis(log_line):
    log_line = log_line.lower()

    if "flags: s" in log_line and "->" in log_line:
        return "TCP SYN packet — part of connection setup. Normal unless repeated excessively."

    elif "flags: fa" in log_line or "flags: f" in log_line:
        return "TCP FIN or FIN-ACK — indicates session termination. Likely normal."

    elif "flags: r" in log_line:
        return "TCP RST (reset) — may indicate an abrupt termination. Could be normal or suspicious."

    elif "flags: p" in log_line:
        return "TCP PSH flag — data being pushed immediately. Normal in real-time apps."

    elif "8.8.8.8" in log_line or "1.1.1.1" in log_line:
        return "DNS lookup to a public resolver (Google or Cloudflare). Normal in browsing."

    elif "len: 0" in log_line:
        return "Zero-length packet — could be a keep-alive or something abnormal."

    elif "protocol: 17" in log_line:
        return "UDP packet — common for DNS, VoIP, and gaming. Monitor for frequency."

    elif "icmp" in log_line:
        return "ICMP packet — used for ping or diagnostics. Frequent use may be scanning."

    else:
        return "No specific pattern found — further inspection may be needed."


def main():
    input_file = 'C:\\Users\\soroush\\llm-packet-analyzer\\results\\packet_log.txt'
    output_file = 'C:\\Users\\soroush\\llm-packet-analyzer\\results\\analysis_output.txt'

    with open(input_file, 'r', encoding='utf-8') as infile, open(output_file, 'w', encoding='utf-8') as outfile:
        lines = infile.readlines()

        for line in lines:
            line = line.strip()
            if not line:
                continue
            print(f"[*] Analyzing: {line}")
            result = rule_based_analysis(line)
            outfile.write(f"{line}\n→ {result}\n\n")

    print(f"\n[*] Done. Output saved to {output_file}")

if __name__ == "__main__":
    main()
