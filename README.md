# Portscan and Pingscan BOFs

A portscanner BOF (COFF) that replicates [Cobalt Strikes Port Scanning](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_port-scanning.htm) functionality including the wide variety of input parameters and provides the same amount of information as it's output.

A pingscanner BOF that perform an ICMP ping scan on target input.

For more information about design considerations and OPSEC notes, see the following [blog](https://fyx.me/articles/replicating-cobalt-strikes-port-scanner-as-a-bof-for-open-source-c2-frameworks/).

## Usage

To run the BOFs use the following commands:
```
portscan [targets] [ports]
pingscan [targets]
```

The following options are supported:
- `[targets]`: a comma separated list of hosts to scan (hostnames and IPs supported). Additionally, you can specify any IPv4 ranges and CIDR (eg. `192.168.1.128-192.168.2.240`, `192.168.1.0/24` )
- `[ports]`: a comma separated list of ports to scan (eg. "53,80,443,8000-8050")

### Cobalt Strike

CS already has a builtin portscan command so the BOF's command have been set to the following:
```
portscan_alt [targets] [ports]
pingscan [targets]
```

### Usage Examples

#### Portscan example in Havoc

```
10/01/2025 03:05:49 [danielward] Demon » portscan "10.10.121.100-10.10.121.120,10.10.123.100-10.10.123.120,10.10.120.0-10.10.120.20" "22,139,445"
[*] [7DBE165A] Running port scan
[+] Send Task to Agent [31 bytes]
[+] Received Output [118 bytes]:
[.] portscanner: Scanning 10.10.121.100-10.10.121.120,10.10.123.100-10.10.123.120,10.10.120.0-10.10.120.20 22,139,445

[+] Received Output [948 bytes]:
10.10.121.107:139
10.10.121.107:445 (platform: 500 version: 10.0 name: WS02 domain: RLAB)
10.10.121.108:139
10.10.121.108:445 (platform: 500 version: 10.0 name: WS06 domain: RLAB)
10.10.121.112:139
10.10.121.112:445 (platform: 500 version: 10.0 name: WS01 domain: RLAB)
10.10.123.100:139
10.10.123.100:445 (platform: 500 version: 10.0 name: WS03 domain: RLAB)
10.10.123.101:139
10.10.123.101:445 (platform: 500 version: 10.0 name: WS04 domain: RLAB)
10.10.123.110:139
10.10.123.110:445 (platform: 500 version: 10.0 name: WS05 domain: RLAB)
10.10.120.1:139
10.10.120.1:445 (platform: 500 version: 10.0 name: DC01 domain: RLAB)
10.10.120.5:139
10.10.120.5:445 (platform: 500 version: 10.0 name: FS01 domain: RLAB)
10.10.120.10:139
10.10.120.10:445 (platform: 500 version: 10.0 name: MX01 domain: RLAB)
10.10.120.15:139
10.10.120.15:445 (platform: 500 version: 10.0 name: SRV01 domain: RLAB)
10.10.120.20:22 (SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11)

[*] BOF execution completed
```

#### Pingscan example in Havoc

```
10/01/2025 03:02:42 [danielward] Demon » pingscan 10.10.121.100-10.10.121.120
[*] [51273B8E] Running ping scan
[+] Send Task to Agent [31 bytes]
[+] Received Output [60 bytes]:
[.] Attempting to ping targets: 10.10.121.100-10.10.121.120

[+] Received Output [157 bytes]:
Reply from 10.10.121.107: bytes=32 time=16ms TTL=128
Reply from 10.10.121.108: bytes=32 time=0ms TTL=128
Reply from 10.10.121.112: bytes=32 time=2ms TTL=128

[*] BOF execution completed
```

## Supported C2s

- Havoc: `havoc-portscan.py`
- Cobalt strike: `portscan.cna`
- _Any C2 that can run a BOF (COFF)_

## Build

```
make
```

## OPSEC

The timeouts have been `#defined` in the portscanner bof. Additionally, the number of concurrent sockets is also defined in `portscanner.c`

Some OPSEC considerations have been incorporated into the tool. Nevertheless, needs further improvements, test in a Lab environment before using in PROD.

