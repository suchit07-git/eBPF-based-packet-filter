## Description

This project leverages **eBPF** (extended Berkeley Packet Filter) to implement a high-performance packet filter that operates at the **kernel level**. By utilizing **XDP** (eXpress Data Path), the program efficiently processes **IPv4** and **IPv6** network traffic. 

## Features

- **Packet Counting**: Keeps track of incoming packets from unique IP addresses and prints the count in real time.
- **Protocol-based Filtering**: Filter packets by their protocol number. For instance, you can filter packets based on whether they're TCP (6), UDP (17), or ICMP (1), etc.
- **Drop or Pass Traffic**: Choose to block specific protocols while allowing all others.
- **IPv4 and IPv6 Support**: Works with both IPv4 and IPv6 packets

## Prerequisites

- **Linux Kernel** version >= 4.8 (eBPF and XDP support required)
- **Go compiler** (Don't forget to change the go version in go.mod file to your installed version)
- **clang** (for compiling the eBPF program)
- **ebpf-go library**  (to interact with eBPF programs from Go)

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/suchit07-git/eBPF-based-packet-filter.git
   cd eBPF-based-packet-filter
   ```

2. **Install dependencies:**
    Run the following command to install the ebpf-go library.
    ```bash
    go get github.com/cilium/ebpf
3. **Build the Go application:** 
    After installing the dependencies, compile the Go program:<br>
    ```bash
    go build
    ```    
    This will create an executable named `ebpf-packet-filter` in the current directory.

## How to run the program?

Once the application is built, you can run it with the following options:

1. Specify the Interface:<br>
Use the `-iface` option to specify the network interface on which the XDP program will be attached. By default, it uses ***eth0***.<br>
```bash
sudo ./ebpf-packet-filter -iface wlan0
```

2.  Drop Specific Packets:<br>
Use the `-block` option to drop packets for specific protocols. This option accepts a comma-separated list of protocol numbers.
For example, to drop ICMP (1) and UDP (17) packets:<br>
```bash
sudo ./ebpf-packet-filter -block 1,17
```

3. Filter Specific Packets:<br>
Use the `-filter` option to only pass packets of the specified protocols. This option also accepts a comma-separated list of protocol numbers.
For example, to filter only IGMP (2), TCP (6), and IPv6 (41) packets:<br>
```bash
sudo ./ebpf-packet_filter -filter 2,6,41
```
