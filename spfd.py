# Import modules
import sys
import argparse
import logging
from scapy.all import *

# Define the command-line arguments
parser = argparse.ArgumentParser(description="Firewall detection tool using Scapy in Python")
parser.add_argument("-t", "--target", type=str, required=True, help="The target website or IP address")
parser.add_argument("-p", "--port", type=int, default=80, help="The port number to probe (default: 80)")
parser.add_argument("-w", "--timeout", type=int, default=2, help="The timeout in seconds for each packet (default: 2)")
parser.add_argument("-v", "--verbose", action="store_true", help="Increase the verbosity level")
args = parser.parse_args()

# Parse the command-line arguments
target = args.target
port = args.port
timeout = args.timeout
verbose = args.verbose

# Check the validity of the arguments
try:
    target_ip = socket.gethostbyname(target) # Resolve the target IP address
except socket.gaierror:
    print("Invalid target website or IP address")
    sys.exit(1)

if port < 1 or port > 65535:
    print("Invalid port number")
    sys.exit(1)

# Configure the logging level
if verbose:
    logging.basicConfig(level=logging.DEBUG, format="%(message)s")
else:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

# Define a custom function to print messages with colors and formats
def print_message(message, level, color):
    # Define the color codes
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }
    # Print the message with the color and the level
    print(colors[color] + "[" + level + "] " + message + colors["reset"])

# Create the TCP packets
packets = []
# TCP SYN packet with converted sport
tcp_syn = IP(dst=target_ip)/TCP(sport=int(RandShort()), dport=port, flags="S")
packets.append(tcp_syn)

# TCP ACK packets with converted sport
tcp_ack = IP(dst=target_ip)/TCP(sport=int(RandShort()), dport=port, flags="A")
packets.append(tcp_ack)

# TCP FIN packets with converted sport
tcp_fin = IP(dst=target_ip)/TCP(sport=int(RandShort()), dport=port, flags="F")
packets.append(tcp_fin)

udp = IP(dst=target_ip)/UDP(sport=RandShort(), dport=port)
packets.append(udp)
# ICMP packet
icmp = IP(dst=target_ip)/ICMP()
packets.append(icmp)

# Send the packets and receive the responses
ans, unans = sr(packets, timeout=timeout, retry=0, verbose=0)

# Analyze the results
firewall = False # Flag to indicate the presence of a firewall
firewall_type = "" # String to store the type of the firewall
# Loop through the answered packets
for packet, response in ans:
    if packet.haslayer(TCP):
        # TCP SYN packet
        if packet[TCP].flags == "S":
            # TCP SYN/ACK response
            if response[TCP].flags == "SA":
                print_message("Port " + str(port) + " is open", "INFO", "green")
                print_message("No firewall filtering on port " + str(port), "INFO", "green")
            # TCP RST/ACK response
            elif response[TCP].flags == "RA":
                print_message("Port " + str(port) + " is closed", "INFO", "yellow")
                print_message("No firewall filtering on port " + str(port), "INFO", "green")
        # TCP ACK packet
        elif packet[TCP].flags == "A":
            # TCP RST response
            if response.haslayer(TCP) and response[TCP].flags == "R":
                print_message("Firewall is stateless", "WARNING", "yellow")
                firewall = True
                firewall_type += "stateless, "
            # No response
            else:
                print_message("Firewall is stateful", "WARNING", "yellow")
                firewall = True
                firewall_type += "stateful, "
        # TCP FIN packet
        elif packet[TCP].flags == "F":
            # TCP RST response
            if response.haslayer(TCP) and response[TCP].flags == "R":
                print_message("Firewall is filtering based on flags", "WARNING", "yellow")
                firewall = True
                firewall_type += "flag-based, "
            # No response
            else:
                print_message("Firewall is not filtering based on flags", "INFO", "green")
    # UDP packet
    elif packet.haslayer(UDP):
        # ICMP port unreachable response
        if response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code == 3:
            print_message("Port " + str(port) + " is closed", "INFO", "yellow")
            print_message("No firewall filtering on port " + str(port), "INFO", "green")
        # No response
        else:
            print_message("Port " + str(port) + " is open or filtered", "INFO", "yellow")
            print_message("Firewall may be filtering on port " + str(port), "WARNING", "yellow")
            firewall = True
            firewall_type += "port-based, "
    # ICMP packet
    elif packet.haslayer(ICMP):
        # ICMP echo reply response
        if response.haslayer(ICMP) and response[ICMP].type == 0:
            print_message("No firewall filtering on ICMP", "INFO", "green")
        # No response
        else:
            print_message("Firewall is filtering on ICMP", "WARNING", "yellow")
            firewall = True
            firewall_type += "ICMP-based, "

# Loop through the unanswered packets
for packet in unans:
    if packet.haslayer(TCP):
        if packet[TCP].flags == "S":
            print_message("Port " + str(port) + " is filtered", "INFO", "yellow")
            print_message("Firewall is blocking on port " + str(port), "WARNING", "yellow")
            firewall = True
            firewall_type += "block-based, "

# Display the final result
if firewall:
    print_message("Firewall detected on target " + target, "ERROR", "red")
    print_message("Firewall type: " + firewall_type[:-2], "ERROR", "red")
else:
    print_message("No firewall detected on target " + target, "INFO", "green")

# End the program
print_message("Firewall detection completed", "INFO", "white")
sys.exit(0)
