Functionalities
Automatic Subnet or Targeted IP Scanning:
Auto-detects your local IP and scans the entire /24 subnet or, with -p, scans a specific IP address.

Full or Fast Scan Modes:
Scan all 65,535 ports, or use -f for a fast mode scanning only common/important ports (including port 554 for RTSP).

Banner Grabbing:
For each open port found, the program attempts to grab and display basic service banners.

OS Fingerprinting:
Attempts to identify the likely operating system of targets using TTL signatures when possible.

Ollama LLM Analysis:
When -m is specified, leverages a local Ollama model to give detailed explanations and risk summaries for found open ports and banners.

Verbose Mode:
Add -v for detailed scanning output, including more network and error information.

Thread Control:
Number of scanning threads is tunable with --threads, defaulting to 100 for fast parallel scanning.

Efficient and Clean Output:
Only machines with open ports are reported; if no ports are open, the host is omitted from output.

Graceful Interrupt:
Press Ctrl+C at any time to immediately and cleanly stop the scan.

Usage Examples
Scan your local network (all ports):


python port_scanner.py => Fast scan (known/common ports including 554):

python port_scanner.py -f => Scan a single IP (fast):

python port_scanner.py -p 192.168.1.20 -f -m ollama_model => Scan fast and get Ollama model interpretation:

python port_scanner.py -p 192.168.1.20 -m ollama_model

python port_scanner.py -h => See help

