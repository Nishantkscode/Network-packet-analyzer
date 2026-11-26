# Network Packet Analyzer (Java)

A Java-based network packet analyzer that reads network capture (`.pcap`) files, inspects packet contents, tracks network connections, identifies applications and websites, and filters network traffic using IP-based, application-based, and domain-based rules.

Built using **Java 17+** and the standard Java library, with no external dependencies.

---

## Features

| Feature | Description |
|---|---|
| **PCAP File Parsing** | Reads PCAP files with little-endian and big-endian formats |
| **Protocol Analysis** | Parses Ethernet, IPv4, TCP, and UDP protocols |
| **Packet Inspection** | Displays MAC addresses, IP addresses, ports, TTL, TCP flags, sequence numbers, and payload information |
| **Connection Tracking** | Groups packets into flows using a five-tuple |
| **Deep Packet Inspection (DPI)** | Extracts application-related information from supported packet contents |
| **Application Detection** | Identifies applications using TLS SNI, HTTP Host, and DNS information |
| **Traffic Filtering** | Filters traffic using source IP, application name, or domain |
| **Filtered PCAP Output** | Saves allowed packets into a new PCAP file that can be opened in Wireshark |
| **Multithreaded Processing** | Uses reader, load balancer, fast-path workers, and writer components connected through thread-safe queues |

## Requirements

- Java Development Kit (JDK) 17 or newer
- Windows, Linux, or macOS
- Wireshark (optional, for viewing PCAP files)

Check your Java installation:

```bash
java -version
javac -version
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Nishantkscode/Network-packet-analyzer.git
cd Network-packet-analyzer
```

### 2. Build the Project

**Windows:**

```bat
build.bat
```

**Linux / macOS:**

```bash
./build.sh
```

### 3. Run Tests

**Windows:**

```bat
run-tests.bat
```

**Linux / macOS:**

```bash
./run-tests.sh
```

The project includes 56 automated checks and does not require an external testing library.

### 4. Run the Application

**Windows:**

```bat
run.bat generate sample\my.pcap
```

**Linux / macOS:**

```bash
./run.sh generate sample/my.pcap
```

The run scripts automatically build the JAR when required.

You can also execute the generated JAR directly:

```bash
java -jar out/packet-analyzer.jar <command> ...
```

---

## Available Commands

| Command | Description |
|---|---|
| `analyze <pcap> [max]` | Displays packet information layer by layer |
| `scan <pcap>` | Displays one line per packet, including available website information |
| `dpi <in.pcap> <out.pcap> ...` | Performs packet inspection and filtering using a single thread |
| `dpi-mt <in.pcap> <out.pcap> ...` | Performs packet inspection and filtering using multiple threads |
| `generate [file.pcap]` | Generates a sample PCAP file for testing |

## Traffic Filtering Options

The `dpi` and `dpi-mt` commands support the following options:

| Option | Description |
|---|---|
| `--block-ip <ip>` | Drops traffic matching the specified source IP address |
| `--block-app <name>` | Blocks an application by name |
| `--block-domain <domain>` | Blocks traffic matching a specified domain |
| `--rules <file>` | Loads filtering rules from a file |
| `--show-flows` | Displays tracked network connections |
| `--lbs <n>` | Sets the number of load-balancer threads (multithreaded mode) |
| `--fps <n>` | Sets the number of fast-path workers per load balancer (multithreaded mode) |

Supported application names include Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, and Cloudflare.

### Domain Filtering

Examples:

- `facebook` matches domain names containing that text.
- `*.tiktok.com` matches the domain and its subdomains.

### Example

Block YouTube traffic, a specific source IP, and Facebook-related domains:

```bash
./run.sh dpi sample/test_dpi.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook
```

On Windows, use `run.bat` instead of `./run.sh`.

---

## Example Processing Report

The application generates a processing report containing packet statistics, forwarded and dropped packets, tracked connections, and application breakdown.

```text
+====================================================================+
|                         PROCESSING REPORT                          |
+====================================================================+
| Packets read:                       77                             |
| Analyzed (IPv4 TCP/UDP):            77                             |
| Skipped (other):                     0                             |
| Total bytes:                      5738                             |
| TCP packets:                        73                             |
| UDP packets:                         4                             |
+--------------------------------------------------------------------+
| Forwarded:                          70                             |
| Dropped:                             7                             |
| Connections (flows):                43                             |
+--------------------------------------------------------------------+
|                       APPLICATION BREAKDOWN                        |
+--------------------------------------------------------------------+
| HTTPS              37  48.1% #########                             |
| Unknown            16  20.8% ####                                  |
| DNS                 4   5.2% #                                     |
| HTTP                4   5.2% #                                     |
| YouTube             1   1.3%                      (BLOCKED)        |
+====================================================================+
```

*The output above is shortened for demonstration.*

Open `filtered.pcap` in Wireshark to inspect the resulting packets.

**Using your own capture?** Save it from Wireshark in the classic PCAP format. The newer PCAPNG format is detected and rejected with an error message.

---

## How It Works

### Multithreaded Architecture

```text
                    +--> LB0 --+--> FP0 --+
 Reader --(hash)----+          +--> FP1 --+--> output queue --> Writer --> out.pcap
 (parse packets)    +--> LB1 --+--> FP2 --+
                               +--> FP3 --+
```

### Processing Pipeline

1. **Reader:** Reads packets from the PCAP file and parses Ethernet, IPv4, TCP, and UDP headers.
2. **Load Balancer:** Uses the packet's five-tuple hash to distribute packets across load-balancer workers.
3. **Fast Path:** Processes packets, tracks flows, identifies applications, checks filtering rules, and decides whether to forward or drop traffic.
4. **Output Queue:** Transfers allowed packets safely to the writer.
5. **Writer:** Writes forwarded packets into the output PCAP file.

The five-tuple consists of:

- Source IP address
- Destination IP address
- Source port
- Destination port
- Protocol

Packets belonging to the same direction of a connection are routed to the same fast-path worker, allowing each worker to maintain its own flow table.

The single-threaded and multithreaded modes share the same packet-processing logic.

### Deep Packet Inspection

The analyzer uses available packet information to identify websites and applications.

- **TLS SNI:** Extracts the server name from a supported TLS Client Hello.
- **HTTP Host:** Extracts the hostname from an HTTP request header.
- **DNS:** Inspects DNS information to identify domain-related traffic.
- **Application Classification:** Uses extracted information and protocol details to classify supported applications.

HTTPS payloads are encrypted. The analyzer does not decrypt HTTPS traffic; it uses information available in the handshake when accessible.

---

## Project Structure

```text
Network-packet-analyzer/
│
├── src/
│   ├── main/
│   │   └── java/com/nishant/packetanalyzer/
│   │       ├── Main.java
│   │       ├── pcap/
│   │       ├── parser/
│   │       ├── dpi/
│   │       ├── engine/
│   │       ├── tools/
│   │       └── util/
│   │
│   └── test/
│       └── java/
│           └── SelfTest.java
│
├── sample/
│   ├── test_dpi.pcap
│   └── blocking_rules.txt
│
├── .gitignore
├── README.md
├── build.bat
├── build.sh
├── run.bat
├── run.sh
├── run-tests.bat
└── run-tests.sh
```

### Main Components

| Package | Responsibility |
|---|---|
| `pcap` | Reading and writing PCAP files |
| `parser` | Parsing Ethernet, IPv4, TCP, and UDP packets |
| `dpi` | Extracting domain and application information |
| `engine` | Packet processing, flow tracking, filtering, and multithreading |
| `tools` | Generating sample PCAP files |
| `util` | Byte conversion and IP address utilities |

---

## Technical Implementation

1. **Five-Tuple Flow Tracking:** Groups packets using network and transport-layer information.
2. **Thread-Safe Communication:** Uses locks, conditions, and queues to coordinate processing workers.
3. **Domain Matching:** Supports domain text matching and wildcard subdomain rules.
4. **Application Classification:** Distinguishes HTTP, HTTPS, DNS, QUIC, and supported applications.
5. **Graceful Thread Shutdown:** Uses staged queue closure and worker coordination.
6. **Packet Validation:** Handles unsupported packet formats and invalid input with clear errors.
7. **PCAP Compatibility Checks:** Detects unsupported PCAPNG files.

---

## Known Limitations

- **IPv4 Only:** IPv6 packets are not supported.
- **Ethernet Only:** Other link-layer formats are not supported.
- **Connection Direction:** Forward and reverse traffic are tracked as separate flows.
- **TLS SNI Extraction:** The complete Client Hello must be available in a single TCP packet. Client Hello messages split across TCP segments are not recognised.
- **QUIC Identification:** QUIC payloads are encrypted, so application identification is limited.
- **Multithreaded Performance:** The reader and parsing stages can become bottlenecks. Multithreaded processing does not guarantee faster execution.

---

## Future Improvements

- Support for IPv6 packet parsing.
- Bidirectional flow tracking.
- TCP stream reassembly for improved TLS SNI extraction.
- Improved QUIC and HTTP/3 application identification.
- Performance optimization of the packet-reading pipeline.
- Additional protocol support.

---

## Technologies Used

- Java 17+
- PCAP File Format
- Ethernet, IPv4, TCP, and UDP
- Deep Packet Inspection (DPI)
- Multithreading
- Thread-Safe Queues
- Wireshark

---

## Author

**Nishant Kumar Sharma**

GitHub: [@Nishantkscode](https://github.com/Nishantkscode)

---

If you find this project useful, feel free to explore the repository, test the application, and share feedback.
