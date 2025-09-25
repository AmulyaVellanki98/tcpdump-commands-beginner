Sample commands and their explanation

sudo tcpdump -D
you’re asking tcpdump: “List all the doors you can eavesdrop on.”
use eth0, which means: capture packets coming in and out of the main wired Ethernet interface.

---

sudo tcpdump -i eth0 -v -c5
  sudo → run as admin (needed to sniff network traffic).

  tcpdump → the packet sniffer itself.

  -i eth0 → “listen at the door called eth0,” i.e. the first Ethernet interface.

  -v → verbose mode, show extra details about each packet.

  -c5 → capture exactly 5 packets, then stop.

  Sniff network traffic on the Ethernet card, show me detailed info, and stop after 5 packets.
  ### Understanding tcpdump output

When tcpdump captures a packet, the output shows several important fields:

- **Timestamp** – The exact time the packet was observed.  
- **Protocol info** – Whether it’s IP, TCP, UDP, etc., along with header details like TTL (time-to-live), total length, and flags (e.g. “don’t fragment”).  
- **Source → Destination** – The sending host and port number, then an arrow (`>`) pointing to the receiving host and port number.  
- **TCP flags** – Indicators such as SYN (connection start), ACK (acknowledge), PSH (push data), FIN (finish), etc.  
- **Sequence and acknowledgment numbers** – Show which bytes are being sent and what the receiver is expecting next.  
- **Window size** – How much data the receiver can handle before acknowledging.  
- **Options and payload length** – Extra TCP options (like timestamps) and how many bytes of data are carried.


**Quick translation of output(human-readable format):**  
“At a given time, one machine sent a certain `number of bytes` of data from a `source port` to another machine at a `destination port`. It included TCP flags (like push and ack), carried sequence numbers to track the data stream, and told the receiver how much more data it could accept before pausing.”

--------------
### Capturing HTTP Traffic with tcpdump and curl

#### Step 1: Start tcpdump
```bash
sudo tcpdump -i eth0 -nn -c9 port 80 -w capture.pcap &
```
- **`-i eth0`** → capture on the Ethernet interface `eth0`.  
- **`-nn`** → disable hostname and port name resolution (show raw numbers).  
- **`-c9`** → stop after exactly 9 packets.  
- **`port 80`** → filter only HTTP traffic.  
- **`-w capture.pcap`** → write packets to `capture.pcap` instead of printing them.  
- **`&`** → run in the background so the terminal is free for other commands.

The shell responded with:
```bash
[1] 13760
tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```
- `[1]` = job number in the shell.  
- `13760` = process ID (PID) of tcpdump.  
- tcpdump confirms it’s listening on `eth0` and will capture Ethernet packets with a snapshot length of 262,144 bytes.

---

#### Step 2: Generate traffic with curl
```bash
curl opensource.google.com
```
- This sends an HTTP request to `opensource.google.com` on port 80.  
- The server replies with a `301 Moved` redirect, pointing to `https://opensource.google/`.  
- That back-and-forth traffic is captured by tcpdump.

Output of curl:
```html
<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">
<TITLE>301 Moved</TITLE></HEAD><BODY>
<H1>301 Moved</H1>
The document has moved
<A HREF="https://opensource.google/">here</A>.
</BODY></HTML>
```

---

#### Step 3: tcpdump capture completes
```bash
9 packets captured
10 packets received by filter
0 packets dropped by kernel
```
- **9 packets captured** → exactly as specified by `-c9`.  
- **10 packets received by filter** → tcpdump saw 10 matching packets but wrote 9 (normal behavior).  
- **0 dropped by kernel** → no packet loss; the capture is complete and reliable.

---

### Summary (Human-readable)
You ran tcpdump in the background to listen for HTTP traffic on `eth0`. Then you used curl to request a webpage over port 80, which triggered a `301 Moved` redirect. Tcpdump captured exactly 9 packets from this exchange and wrote them into `capture.pcap`. The process ended cleanly with no packet loss.
------------

### Reading and Filtering Saved Packet Captures with tcpdump

#### Command 1: Verbose packet headers
```bash
sudo tcpdump -nn -r capture.pcap -v
```
- **`-nn`** → disables name lookups for IPs and ports (keeps raw numbers).  
- **`-r capture.pcap`** → read packets from the saved file instead of live capture.  
- **`-v`** → verbose mode; show more details from the headers.

**What the output shows:**
```
reading from file capture.pcap, link-type EN10MB (Ethernet)
20:53:27.669101 IP (tos 0x0, ttl 64, id 50874, offset 0, flags [DF], proto TCP (6), length 60)
    172.17.0.2:46498 > 146.75.38.132:80: Flags [S], cksum 0x5445 (incorrect), seq 4197622953, win 65320, options [mss 1420,sackOK,TS val 610940466 ecr 0, nop,wscale 7], length 0
20:53:27.669422 IP (tos 0x0, ttl 62, id 0, offset 0, flags [DF], proto TCP (6), length 60)
    146.75.38.132:80 > 172.17.0.2:46498: Flags [S.], cksum 0xc272 (correct), seq 2026312556, ack 4197622953, win 65535, options [mss 1420,sackOK,TS val 155704241 ecr 610940466, nop,wscale 9], length 0
```

- **Timestamp** → when the packet was seen.  
- **Source → Destination** → client IP/port to server IP/port.  
- **Flags [S] / [S.]** → SYN (connection request) and SYN+ACK (server reply).  
- **seq/ack numbers** → track data ordering and reliability.  
- **options** → TCP extras like max segment size and timestamps.  
This is showing the TCP handshake: your client asked to connect, and the server replied.

---

#### Command 2: Hex and ASCII packet contents
```bash
sudo tcpdump -nn -r capture.pcap -X
```
- **`-nn`** → no name lookups.  
- **`-r capture.pcap`** → read from saved capture.  
- **`-X`** → display the raw packet data in both hexadecimal and ASCII.

**What the output shows:**
- **Left side** → hexadecimal representation of the bytes in the packet.  
- **Right side** → ASCII translation (if the byte maps to a printable character).  
- Useful for security analysis: you can literally see strings like HTTP headers (`GET /`, `Host: ...`) or even HTML payload (`<H1>301 Moved</H1>`).

---

### Summary (Human-readable)
- The `-v` option lets you study the **envelope** of each packet (who sent it, flags, sequence numbers).  
- The `-X` option lets you open the **letter itself** and look at the raw contents in both hex and text.  
Together, they let you confirm both the network-level behavior (handshakes, flags, ports) and the application-level data (HTTP requests, responses, or suspicious patterns).
