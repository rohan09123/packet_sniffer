# 📡 Packet Sniffer (Python)

A lightweight, customizable packet sniffer built using raw sockets in Python.
Captures and parses Ethernet, IPv4, ICMP, TCP, and UDP packets in real time.

1. 🚀 Features
2. 🧪 Capture raw packets directly from the network interface
3. 🔍 Decode Ethernet frames
4. 🌐 Parse IPv4 packets
5. 💬 Inspect ICMP, TCP, and UDP traffic
6. 🧱 View packet payloads in formatted hex
7. 📦 Fully commented and beginner-friendly
8. ⚙️ Works on **Linux** (Kali, Ubuntu, Debian, etc.)

## 📷 Demo Output
Ethernet Frame:<br>
     - Destination: AA:BB:CC:DD:EE:FF, Source: 11:22:33:44:55:66, Protocol: 8<br>
     - IPv4 Packet:<br>
     &nbsp; &nbsp; &nbsp; &nbsp;- Version: 4, Header Length: 20, TTL: 64<br>
     &nbsp; &nbsp; &nbsp; &nbsp;- Protocol: 6 (TCP), Source: 192.168.1.5, Target: 142.250.72.14<br>
     - TCP Segment:<br>
     &nbsp; &nbsp; &nbsp; &nbsp;- Source Port: 54321, Destination Port: 80<br>
     &nbsp; &nbsp; &nbsp; &nbsp;- Flags: SYN<br>
     &nbsp; &nbsp; &nbsp; &nbsp;- Data:<br>
     &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; \x45\x00...

## 📁 Project Structure
packet-sniffer/<br>
│── sniffer.py<br>
│── LICENSE<br>
│── README.md<br>
└── .gitignore

## 🛠 Requirements

1. Python 3.8+
2. Linux system (raw sockets require root privileges)
3. Install dependencies (none external required):

## ▶️ How to Run

Run with root permissions:

sudo python3 sniffer.py


Live packet capture will begin immediately.

## ✨ Customization

You can easily add support for more protocols:

- DNS
- HTTP
- ARP
- IPv6
- SSL/TLS
- DHCP

## 🔒 Permissions & Limitations

Raw sockets require sudo on Linux:

sudo python3 sniffer.py

VirtualBox or VM networking settings may affect captured traffic.

## 📜 License

This project is licensed under the MIT License.
Feel free to modify and use it in personal or commercial projects.

## 🤝 Contributing

Pull requests are welcome!
If you’d like to improve parsing logic, add features, or fix bugs, feel free to open an issue.

## ⭐ Support

If this project helped you, please consider giving it a star ⭐ on GitHub.
