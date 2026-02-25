from scapy.all import sniff, IP, TCP, UDP, Raw

def analyze_packet(packet):
    # Check if packet has IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print("\n==============================")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")

        # Protocol identification
        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        else:
            print(f"Protocol       : {protocol}")

        # Payload (raw data)
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"Payload        : {payload[:50]}")  # show first 50 bytes
        else:
            print("Payload        : None")

        print("==============================")

# Capture packets (Ctrl+C to stop)
print("Starting packet capture...")
sniff(prn=analyze_packet, store=False)
