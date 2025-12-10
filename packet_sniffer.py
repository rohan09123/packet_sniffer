import socket
import struct
import textwrap

# --------------------- DISPLAY FORMAT SETTINGS --------------------- #
# These tabs make the printed output visually clean and structured.
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


# ---------------------------- MAIN LOOP ----------------------------- #
def main():
    """
    This function sets up a raw socket and continuously listens
    for packets on the network interface. Each packet is decoded
    layer by layer: Ethernet → IPv4 → ICMP/TCP/UDP/Other
    """

    # AF_PACKET + SOCK_RAW allows full packet capture (Linux only)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    while True:
        raw_data, addr = conn.recvfrom(65536)

        # Unpack the Ethernet frame
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        print("\nEthernet Frame:")
        print(TAB_1 + f"Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}")

        # Handle only IPv4 packets
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

            print(TAB_1 + "IPv4 Packet:")
            print(TAB_2 + f"Version: {version}, Header Length: {header_length}, TTL: {ttl}")
            print(TAB_2 + f"Protocol: {proto}, Source: {src}, Target: {target}")

            # ------------------- ICMP ------------------- #
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)

                print(TAB_1 + "ICMP Packet:")
                print(TAB_2 + f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))

            # ------------------- TCP -------------------- #
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data = tcp_segment(data)

                print(TAB_1 + "TCP Segment:")
                print(TAB_2 + f"Source Port: {src_port}, Destination Port: {dest_port}")
                print(TAB_2 + f"Sequence: {sequence}, Acknowledgment: {acknowledgement}")
                print(TAB_2 + "Flags:")
                print(TAB_3 + f"URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}")

                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))

            # ------------------- UDP -------------------- #
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)

                print(TAB_1 + "UDP Segment:")
                print(TAB_2 + f"Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
                print(TAB_2 + "Data:")
                print(format_multi_line(DATA_TAB_3, data))

            # -------------- Other IPv4 Protocols --------- #
            else:
                print(TAB_1 + f"Other IPv4 Protocol: {proto}")
                print(format_multi_line(DATA_TAB_2, data))

        else:
            print(TAB_1 + "Non-IPv4 Ethernet Data:")
            print(format_multi_line(DATA_TAB_1, data))


# ---------------------- ETHERNET LAYER ---------------------- #
def ethernet_frame(data):
    """
    Unpacks Ethernet frame: [Destination MAC | Source MAC | Protocol]
    First 14 bytes = Ethernet header
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]


def get_mac_address(bytes_addr):
    """Converts bytes into a readable AA:BB:CC:DD:EE:FF MAC address."""
    bytes_addr = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_addr).upper()


# ----------------------- IPv4 LAYER ------------------------- #
def ipv4_packet(data):
    """
    Unpacks IPv4 packet: extracts version, header length, TTL,
    protocol number, source IP, destination IP, and payload.
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    """Converts raw IPv4 bytes to dotted-decimal format."""
    return '.'.join(map(str, addr))


# ----------------------- ICMP LAYER ------------------------- #
def icmp_packet(data):
    """Unpacks an ICMP packet (type, code, checksum)."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# ------------------------ TCP LAYER -------------------------- #
def tcp_segment(data):
    """
    Unpacks a TCP segment:
    Extracts ports, sequence number, acknowledgment, and flags.
    """
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack(
        '! H H L L H', data[:14])

    # Extract header size
    offset = (offset_reserved_flags >> 12) * 4

    # Extract flags from bitwise operations
    urg = (offset_reserved_flags & 32) >> 5
    ack = (offset_reserved_flags & 16) >> 4
    psh = (offset_reserved_flags & 8) >> 3
    rst = (offset_reserved_flags & 4) >> 2
    syn = (offset_reserved_flags & 2) >> 1
    fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgement, urg, ack, psh, rst, syn, fin, data[offset:]


# ------------------------ UDP LAYER -------------------------- #
def udp_segment(data):
    """Unpacks a UDP segment (source port, dest port, length)."""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# --------------------- FORMATTER FUNCTION -------------------- #
def format_multi_line(prefix, string, size=80):
    """
    Formats binary data into readable wrapped hex output.
    Very useful for inspecting raw packet payloads.
    """
    size -= len(prefix)

    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


# --------------------------- START --------------------------- #
main()
