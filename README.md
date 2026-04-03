# simple-ids 🛡️

A **lightweight Network Intrusion Detection System** written in pure C using raw sockets — no libpcap, no external dependencies.

## What it detects

| Threat              | Trigger                                                  |
| ------------------- | -------------------------------------------------------- |
| **Port Scan**       | One IP hits ≥10 unique ports within 3 s                  |
| **SYN Flood**       | One IP sends ≥100 SYN-only packets within 3 s            |
| **ICMP Sweep**      | One IP pings ≥10 unique hosts within 3 s                 |
| **Suspicious Port** | Any traffic to known malware ports (4444, 1337, 31337 …) |

All thresholds are tunable in `rules/rules.conf`.

## Directory structure

```
simple-ids/
├── include/
│   └── ids.h          ← all types, constants, prototypes
├── src/
│   ├── main.c         ← argument parsing, entry point
│   └── ids.c          ← packet capture + all detection logic
├── rules/
│   └── rules.conf     ← tunable thresholds
├── logs/              ← alert log written here at runtime
├── Makefile
└── README.md
```

## Build

```bash
make
```

Requires `gcc` and Linux headers (standard on any Linux distro).

## Run

```bash
sudo ./ids                              # defaults (eth0, rules/rules.conf)
sudo ./ids -i wlan0                     # different interface
sudo ./ids -i eth0 -r rules/rules.conf -l logs/ids.log -v
```

> **Root required** — raw AF_PACKET sockets need `CAP_NET_RAW`.

## Sample output

```
[ALERT #1]  [2025-04-04 14:32:11] PORT SCAN        | SRC: 192.168.1.105  | Ports hit: 10 (threshold: 10)
[ALERT #2]  [2025-04-04 14:32:14] SYN FLOOD        | SRC: 10.0.0.44      | SYN count: 100 in 3s (threshold: 100)
[ALERT #3]  [2025-04-04 14:32:18] ICMP SWEEP       | SRC: 192.168.1.200  | Hosts pinged: 10 in 3s (threshold: 10)
[ALERT #4]  [2025-04-04 14:32:21] SUSPICIOUS PORT  | SRC: 172.16.0.9     | Port 4444 (common malware/C2 port)
```

## Test it

```bash
# Port scan (from another terminal / machine)
nmap -p 1-100 <your-ip>

# SYN flood (hping3)
sudo hping3 -S --flood -p 80 <your-ip>

# ICMP sweep
nmap -sn 192.168.1.0/24
```

## Tuning `rules/rules.conf`

```ini
port_scan_threshold  = 10    # unique ports to trigger scan alert
syn_flood_threshold  = 100   # SYN packets to trigger flood alert
icmp_sweep_threshold = 10    # hosts pinged to trigger sweep alert
time_window          = 3     # sliding window in seconds
log_file             = logs/ids.log
```

## Key C concepts used

- `socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)` — capture full Ethernet frames
- Manual header parsing (`struct iphdr`, `struct tcphdr`, `struct icmphdr`)
- Bitset for O(1) port-seen tracking
- djb2 hash table for per-IP state
- Time-windowed sliding counters
- Signal handling for graceful shutdown
