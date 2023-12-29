## Overview

**net-proc-watch** is a real-time network bandwidth monitor for the command-line.  It breaks down traffic *per process* akin to [nethogs](https://github.com/raboof/nethogs), but does it using [Linux eBPF](https://ebpf.io/) kernel probes (specifically a [bpftrace](https://github.com/iovisor/bpftrace) script).

Example output (refreshes every second):

```
PID, COMMAND, CONNS, TX_SEC, RX_SEC
30408, curl, 1, 0 bytes/sec, 96.86 K/sec
2863, Mendo Server, 1, 373 bytes/sec, 100 bytes/sec
2421, Performa Server, 2, 141.97 K/sec, 3.35 K/sec
30466, node, 1, 333 bytes/sec, 697 bytes/sec
18430, PoolNoodle Serv, 1, 8.89 K/sec, 83 bytes/sec
```

It can also output in JSON format, for machine-readability.

## Installation

**net-proc-watch** ships as a standalone Perl script (with all the BPF bits inline), so all you need to do is download the file and run it as root.  But first, you'll need to install a few dependencies:

| OS | Command |
|----|---------|
| CentOS / Fedora / RedHat | `yum install bpftrace perl-JSON` |
| Ubuntu / Debian | `apt-get install bpftrace build-essential libjson-perl` |

If your package manager cannot find `bpftrace`, please see [bpftrace Package Install](https://github.com/iovisor/bpftrace/blob/master/INSTALL.md#package-install).

Here is an easy way to download the latest version of the `net-proc-watch` script and install it in `/usr/local/bin/`:

```sh
curl -o /usr/local/bin/net-proc-watch "https://github.com/pixlcore/net-proc-watch/blob/main/net-proc-watch.pl"
chmod 775 /usr/local/bin/net-proc-watch
```

## Usage

Assuming you installed the script to `/usr/local/bin/net-proc-watch` and you have `/usr/local/bin` in your PATH, all you need to do is run it (as root):

```sh
net-proc-watch
```

For machine-readable JSON output mode, add `--format json` like this:

```sh
net-proc-watch --format json
```

The script will run continually until killed (Ctrl-C or SIGTERM).  It refreshes the process list every second.  Note that processes are only listed if they have at least one open TCP connection.

## Caveats

- **Memory Usage**
	- Currently, as of this writing, [bpftrace](https://github.com/iovisor/bpftrace) scripts require about 130MB of memory to run.
	- Compare this to [nethogs](https://github.com/raboof/nethogs) which only uses around 10MB or so.
	- This will be improved in the future once bpftrace scripts can be compiled using [AOT compilation](https://dxuuu.xyz/aot-bpftrace.html).
- **Compiler Toolchain**
	- Currently, [bpftrace](https://github.com/iovisor/bpftrace) scripts require that the entire LLVM toolchain be installed on the machines where it runs.
	- This is obviously a difficult sell for production servers.
	- This will be fixed in the future once bpftrace scripts can be compiled using [AOT compilation](https://dxuuu.xyz/aot-bpftrace.html) and shipped as binaries.
- **Modern Kernels**
	- Linux eBPF requires a modern kernel (see [Tested Using](#tested-using) below).
- **TCP Only**
	- Currently, only TCP connections are tracked.  
	- UDP may be added in the future.

## Tested Using

| OS | Kernel | Arch | Hardware |
|----|--------|------|----------|
| **Amazon Linux 2** | `Linux 4.14.330-250.540.amzn2.x86_64` | x86 | AWS |
| **Amazon Linux 3** | `Linux 6.1.66-91.160.amzn2023.x86_64` | x86 | AWS |
| **Ubuntu 22** | `Linux 5.15.0-1019-aws` | x86 | AWS |
| **Ubuntu 23** | `Linux 6.5.0-1011-aws` | x86 | AWS |
| **Ubuntu 23** | `Linux 6.5.13-orbstack-00121-ge428743e4e98` | ARM | VM |
| **CentOS 9** | `Linux 6.5.13-orbstack-00121-ge428743e4e98` | ARM | VM |
| **Fedora 39** | `Linux 6.5.13-orbstack-00121-ge428743e4e98` | ARM | VM |

## License

MIT and Apache 2.0 -- see [LICENSE.md](https://github.com/pixlcore/net-proc-watch/blob/main/LICENSE.md)
