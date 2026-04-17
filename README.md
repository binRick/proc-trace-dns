# proc-trace-dns

Watch every DNS query your processes make, in real time — with per-process
attribution, query types, resolved IPs, NXDOMAIN errors, and latency.

```
$ sudo proc-trace-dns
12341  curl       A      api.github.com           → 140.82.121.6       1.4ms
12342  python3    A      api.openai.com           → 104.18.7.192       2.1ms
12342  python3    AAAA   api.openai.com           → 2606:4700::6812    2.1ms
12343  node       A      registry.npmjs.org       → 104.16.0.35        1.7ms
12344  apt        A      deb.debian.org           → NXDOMAIN           0.5ms
```

## How it works

proc-trace-dns opens a raw `AF_PACKET` socket and captures all UDP port-53
traffic system-wide. For each outgoing DNS query it resolves the source port
→ socket inode → PID via `/proc/net/udp` and `/proc/<pid>/fd/`. When the
matching response arrives (matched by DNS transaction ID), it emits the
fully-attributed record.

No eBPF. No libpcap. No external dependencies. One static Go binary.

## Requirements

- Linux (kernel 2.6+)
- `root` or `CAP_NET_RAW` capability

```sh
# Grant capability so normal users can run it (optional)
sudo setcap cap_net_raw+eip /usr/local/bin/proc-trace-dns
```

## Install

**Pre-built binary (Linux amd64):**
```sh
curl -fsSL https://github.com/binRick/proc-trace-dns/releases/latest/download/proc-trace-dns-linux-amd64 \
  -o proc-trace-dns
chmod +x proc-trace-dns
sudo mv proc-trace-dns /usr/local/bin/
```

**Build from source (Go 1.22+):**
```sh
git clone https://github.com/binRick/proc-trace-dns
cd proc-trace-dns
go build -trimpath -ldflags="-s -w" -o proc-trace-dns .
sudo mv proc-trace-dns /usr/local/bin/
```

**Docker cross-compile (no local Go required):**
```sh
chmod +x build.sh
./build.sh
# Outputs dist/proc-trace-dns-linux-amd64 and dist/proc-trace-dns-linux-arm64
```

## Usage

```
Usage: proc-trace-dns [flags] [-- CMD [args...]]

  -c          force ANSI color output
  -d PATTERN  only show queries matching this domain substring
  -f          flat output (no column alignment)
  -j          JSON output (one object per line / ndjson)
  -n NAME,…   only show queries from these process names
  -o FILE     append output to FILE instead of stdout
  -p PID,…    only show queries from these PIDs
  -q          quiet — print only queried hostnames, one per line
  -Q          suppress error messages
  -t          show RFC3339 timestamp for each query
  -T TYPE,…   only show these record types (A, AAAA, MX, TXT, …)
```

### Examples

```sh
# System-wide — watch everything
sudo proc-trace-dns

# Filter by process name
sudo proc-trace-dns -n curl,wget

# Filter by domain
sudo proc-trace-dns -d amazonaws.com

# Only NXDOMAIN failures
sudo proc-trace-dns -Qf | grep NXDOMAIN

# JSON output
sudo proc-trace-dns -j | jq .

# Audit what an install script resolves
sudo proc-trace-dns -q -- bash install.sh | sort -u

# Trace a single command
sudo proc-trace-dns -- curl -s https://example.com

# Log to file in background
sudo proc-trace-dns -Qt -o /var/log/dns-queries.log &
```

### JSON output format

```json
{
  "pid": 12341,
  "name": "curl",
  "type": "A",
  "query": "api.github.com",
  "answers": ["140.82.121.6"],
  "rcode": "NOERROR",
  "latency_ms": 1.4
}
```

## License

MIT
