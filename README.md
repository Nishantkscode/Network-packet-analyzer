# Network Packet Analyzer (Java)

A Java application that reads network captures (`.pcap` files from Wireshark), shows what is inside each packet, keeps track of the connections between devices, finds out which websites / apps the traffic belongs to, and filters traffic with **IP-based and domain-based rules**.

This is a **Java port** of a C++ Deep Packet Inspection (DPI) project. It uses only the standard library: no external dependencies.

---

## What it does

| Feature | How |
|---|---|
| **Read PCAP files** | Parses the 24-byte global header and every packet record (little- and big-endian captures) |
| **Decode protocols** | Ethernet, then IPv4, then TCP / UDP: MAC addresses, IP addresses, ports, TTL, TCP flags, sequence numbers, payload |
| **Track connections** | Groups packets into flows using the *five-tuple* (source IP, destination IP, source port, destination port, protocol) |
| **Identify websites / apps** | Reads the website name from the TLS *Client Hello* (SNI) for HTTPS, the `Host:` header for HTTP, and the port for DNS |
| **Filter traffic** | Block by source IP, application (YouTube, TikTok, ...) or domain (text match or `*.example.com`) |
| **Write filtered PCAP** | Allowed packets are saved to a new `.pcap` you can open in Wireshark |
| **Multi-threaded mode** | Reader, load balancers, fast-path workers and a writer thread connected by thread-safe queues |

## Requirements

* **JDK 17 or newer** (check with `java -version` and `javac -version`)
* Works on Windows, Linux and macOS

## Quick start

```bash
# Linux / macOS                         # Windows
./build.sh                              build.bat
./run-tests.sh                          run-tests.bat
./run.sh generate sample/my.pcap        run.bat generate sample\my.pcap
./run.sh dpi sample/test_dpi.pcap out.pcap --block-app YouTube     (run.bat on Windows)
```

`run.sh` / `run.bat` build the jar automatically the first time. You can also use the jar directly:
`java -jar out/packet-analyzer.jar <command> ...`

### Commands

```
analyze  <pcap> [max]             Show every packet layer by layer
scan     <pcap>                   One line per packet, with HTTPS website names
dpi      <in.pcap> <out.pcap> ... Inspect + filter, single thread
dpi-mt   <in.pcap> <out.pcap> ... Inspect + filter, multi-threaded
generate [file.pcap]              Create a sample capture to experiment with
```

### Options for `dpi` / `dpi-mt`

| Option | Meaning |
|---|---|
| `--block-ip <ip>` | Drop traffic whose **source** is this IP |
| `--block-app <name>` | Drop an application: Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon, Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare (case-insensitive) |
| `--block-domain <d>` | Drop a domain. `facebook` matches any name containing the text; `*.tiktok.com` matches the domain and all subdomains |
| `--rules <file>` | Load rules from a file, see `sample/blocking_rules.txt` |
| `--show-flows` | Also print the table of tracked connections |
| `--lbs <n>`, `--fps <n>` | (`dpi-mt` only) load-balancer threads (default 2) and fast-path threads per balancer (default 2) |

### Example

```bash
./run.sh dpi sample/test_dpi.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook
```

Output (shortened):

```
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
| Amazon              1   1.3%                                       |
| Apple               1   1.3%                                       |
| Cloudflare          1   1.3%                                       |
| Discord             1   1.3%                                       |
| Facebook            1   1.3%                                       |
| GitHub              1   1.3%                                       |
| Google              1   1.3%                                       |
| Instagram           1   1.3%                                       |
| Microsoft           1   1.3%                                       |
| Netflix             1   1.3%                                       |
| Spotify             1   1.3%                                       |
| Telegram            1   1.3%                                       |
  ...
| TikTok              1   1.3%                                       |
| Twitter/X           1   1.3%                                       |
| YouTube             1   1.3%                      (BLOCKED)        |
| Zoom                1   1.3%                                       |
+====================================================================+

```

Open `filtered.pcap` in Wireshark to see that the blocked traffic is gone.

> **Using your own capture?** In Wireshark use *File -> Save As* and choose the **pcap** format. The newer *pcapng* format is detected and rejected with a clear message.

---

## How it works

```
                    +--> LB0 --+--> FP0 --+
 Reader --(hash)----+          +--> FP1 --+--> output queue --> Writer --> out.pcap
 (parse packets)    +--> LB1 --+--> FP2 --+
                               +--> FP3 --+
```

1. **Reader** reads each packet from the PCAP file and decodes Ethernet, IP and TCP/UDP headers.
2. The packet's **five-tuple** is hashed to pick a **load balancer (LB)**, which hashes again to pick a **fast path (FP)**. The same connection always lands on the same FP, so each FP keeps its own private flow table and needs no locks.
3. The **FP** looks up the flow, tries to learn the website name (SNI / Host / DNS), classifies the application, checks the blocking rules and decides *forward* or *drop*. Once a flow is blocked, all its later packets are dropped.
4. The **Writer** saves forwarded packets to the output file.

The single-threaded `dpi` command runs the same `PacketProcessor` in one loop, so both modes give identical results.

**Why SNI?** HTTPS is encrypted, but the very first handshake message (*Client Hello*) is not, and it contains the website name in plain text. That is how the analyzer can tell YouTube from Facebook without decrypting anything.

## Project structure

```
src/main/java/com/nishant/packetanalyzer/
  Main.java                 command-line entry point
  pcap/    PcapReader, PcapWriter, PcapGlobalHeader, RawPacket
  parser/  PacketParser, ParsedPacket, NetConstants        (Ethernet / IPv4 / TCP / UDP)
  dpi/     FiveTuple, AppType, SniExtractor, HttpHostExtractor, DnsExtractor, QuicSniExtractor
  engine/  PacketProcessor, FlowEntry, RuleManager, ThreadSafeQueue,
           LoadBalancer, FastPath, SingleThreadEngine, MultiThreadEngine, Report
  tools/   PacketBuilder, GenerateTestPcap                  (build sample packets)
  util/    Bytes, IpUtils
src/test/java/.../SelfTest.java      56 automated checks (no libraries needed)
sample/                              test_dpi.pcap, blocking_rules.txt
```

## C++ to Java mapping

| C++ original | Java version |
|---|---|
| `pcap_reader.h/.cpp` | `pcap/PcapReader`, `PcapWriter`, `PcapGlobalHeader`, `RawPacket` |
| `packet_parser.h/.cpp`, `platform.h` | `parser/PacketParser`, `ParsedPacket`, `NetConstants`, `util/Bytes` (replaces `ntohs`/`ntohl`) |
| `types.h/.cpp` (`FiveTuple`, `AppType`, `sniToAppType`) | `dpi/FiveTuple` (a record), `dpi/AppType` |
| `sni_extractor.h/.cpp` | `dpi/SniExtractor`, `HttpHostExtractor`, `DnsExtractor`, `QuicSniExtractor` |
| `TSQueue<T>` in `dpi_mt.cpp` (mutex + condition variables) | `engine/ThreadSafeQueue` (`ReentrantLock` + `Condition`) |
| `Rules` / `rule_manager.cpp` | `engine/RuleManager` (+ wildcard domains and rules file from the unfinished v2 code) |
| `FastPath`, `LoadBalancer`, `DPIEngine` in `dpi_mt.cpp` | `engine/FastPath`, `LoadBalancer`, `MultiThreadEngine` |
| `main_working.cpp` | `engine/SingleThreadEngine` (shares `PacketProcessor` with the multi-threaded engine) |
| `main.cpp`, `main_simple.cpp` | `Main` commands `analyze` and `scan` |
| `generate_test_pcap.py` | `tools/GenerateTestPcap` + `PacketBuilder` |

## Verified against the C++ original

I built the C++ version and compared both programs on the same capture:

* `dpi` output file is **byte-for-byte identical** to the C++ output file.
* `analyze` and `scan` print **identical text** (1,709 lines for the sample).
* The multi-threaded engine produces the **same set of packets** as the single-threaded one on a 539,000-packet / 266,005-flow capture, for thread layouts from 1x1 up to 8x2, and 40 repeated runs had no failures.

## Deliberate improvements over the C++ code

1. **Domain matching bug fixed.** The C++ matched `t.co` and `x.com` as plain substrings, so `www.microsoft.com` ("microsof**t.co**m") and `www.netflix.com` ("netfli**x.com**") were labelled *Twitter/X*. Short domains now match only as a whole domain or subdomain.
2. **All worker threads are used.** The C++ reused the same hash remainder at both balancing levels, so half the fast-path threads never received work. Java uses the next part of the hash for the second level.
3. **Safe shutdown.** The C++ slept 500 ms and hoped the queues were empty. Java closes the queues stage by stage and waits for each to drain, so no packet can be lost, and a failing worker shuts the pipeline down instead of hanging.
4. **Plain HTTP is labelled HTTP**, not HTTPS, even for unknown sites.
5. UDP port 443 is labelled QUIC; IP fragments and Ethernet padding no longer confuse the parser; `Host:` is only read at the start of a header line; app and domain names are case-insensitive; invalid IPs and options give clear errors; `pcapng` files are detected.

## Known limitations

* **Replies are tracked separately.** A connection and its replies (server to client) have different five-tuples, so replies are listed as their own "Unknown" flows and are not dropped when the request flow is blocked. This is the same behaviour as the original. Merging both directions into one flow is a natural next step.
* **IPv4 only.** IPv6 packets are skipped. Ethernet links only.
* **SNI needs the whole Client Hello in one packet.** A hello split across TCP segments is not recognised. QUIC/HTTP3 payloads are encrypted, so QUIC flows are labelled only by port.
* **The multi-threaded mode is not faster on this workload** (about 4 s for 539,000 packets in both modes): reading and parsing happens on one thread, so it is the bottleneck. The mode is there to show the pipeline architecture.

## Running the tests

```bash
./run-tests.sh      # Windows: run-tests.bat
```
