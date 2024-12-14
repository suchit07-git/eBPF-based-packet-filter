package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func loadProtocolMap() map[uint8]string {
	protocolMap := make(map[uint8]string)
	file, err := os.Open("/etc/protocols")
	if err != nil {
		fmt.Println("Could not open /etc/protocols:", err)
		return protocolMap
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			name := fields[0]
			protoNum, err := strconv.Atoi(fields[1])
			if err == nil && protoNum >= 0 && protoNum <= 255 {
				protocolMap[uint8(protoNum)] = name
			}
		}
	}
	return protocolMap
}

const bpfProgramPath = "packet_filter.o"

func ip4ToString(ip uint32) net.IP {
	address := make(net.IP, 4)
	binary.LittleEndian.PutUint32(address, ip)
	return address
}

func ip6ToString(ip [16]byte) string {
	return net.IP(ip[:]).String()
}

func printIPv4Map(m *ebpf.Map) {
	iter := m.Iterate()
	var ip uint32
	var count uint64
	for iter.Next(&ip, &count) {
		fmt.Printf("  %s: %d packets\n", ip4ToString(ip), count)
	}
	if err := iter.Err(); err != nil {
		fmt.Printf("Error iterating map: %v\n", err)
	}
}

func printIPv6Map(m *ebpf.Map) {
	iter := m.Iterate()
	var ip [16]byte
	var count uint64
	for iter.Next(&ip, &count) {
		fmt.Printf("  %s: %d packets\n", ip6ToString(ip), count)
	}
	if err := iter.Err(); err != nil {
		fmt.Printf("Error iterating map: %v\n", err)
	}
}

func main() {
	ifname := flag.String("iface", "eth0", "Network interface to attach the XDP program")
	blockProtocols := flag.String("block", "", "Specify comma-separated list of protocols to block")
	filterProtocols := flag.String("filter", "", "Specify comma-separated list of protocols to filter")
	flag.Parse()
	protocolsMap := loadProtocolMap()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Error while removing memlock:", err)
	}
	spec, err := ebpf.LoadCollectionSpec(bpfProgramPath)
	if err != nil {
		log.Fatal("Failed to load the BPF program:", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal("Failed to create BPF collection:", err)
	}
	defer collection.Close()
	ip4Map := collection.Maps["ipv4_counter_map"]
	ip6Map := collection.Maps["ipv6_counter_map"]
	blockedProtocolsMap := collection.Maps["blocked_protocols"]
	filterMap := collection.Maps["filtered_protocols"]
	if ip4Map == nil || ip6Map == nil || blockedProtocolsMap == nil {
		log.Fatal("Failed to find required map in the BPF program")
	}
	iface, err := net.InterfaceByName(*ifname)
	if err != nil {
		log.Fatalf("Error while getting interface %s: %s", *ifname, err)
	}
	prog := collection.Programs["xdp_protocol_filter"]
	if prog == nil {
		log.Fatal("Failed to find xdp_protocol_filter in the BPF program")
	}
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Failed to attach XDP program:", err)
	}
	defer link.Close()
	fmt.Printf("eBPF program attached to %s\n", iface.Name)
	if *blockProtocols != "" {
		protocols := make([]string, 0)
		for _, protoStr := range strings.Split(*blockProtocols, ",") {
			protoNum, err := strconv.ParseUint(protoStr, 10, 8)
			if err != nil {
				fmt.Printf("Invalid protocol number %s: %v\n", protoStr, err)
				continue
			}
			protocol := uint8(protoNum)
			if err := blockedProtocolsMap.Put(&protocol, &protocol); err != nil {
				fmt.Printf("Failed to block protocol %d: %v\n", protocol, err)
			} else {
				protocols = append(protocols, protocolsMap[protocol])
			}
		}
		fmt.Print("Dropping packets of protocols: ")
		for i := 0; i < len(protocols); i++ {
			fmt.Print(protocols[i], " ")
		}
		fmt.Println()
	}
	if *filterProtocols != "" {
		protocols := make([]string, 0)
		for _, protoStr := range strings.Split(*filterProtocols, ",") {
			protoNum, err := strconv.ParseUint(protoStr, 10, 8)
			if err != nil {
				fmt.Printf("Invalid protocol number %s: %v\n", protoStr, err)
				continue
			}
			protocol := uint8(protoNum)
			if err := filterMap.Put(&protocol, &protocol); err != nil {
				fmt.Printf("Failed to filter protocol %d: %v\n", protocol, err)
			} else {
				protocols = append(protocols, protocolsMap[protocol])
			}
		}
		fmt.Print("Filtering packets of protocols: ")
		for i := 0; i < len(protocols); i++ {
			fmt.Print(protocols[i], " ")
		}
		fmt.Println()
	} else {
		for i := 0; i < 256; i++ {
			protocol := uint8(i)
			if err := filterMap.Put(&protocol, &protocol); err != nil {
				fmt.Printf("Failed to filter protocol %d: %v\n", i, err)
			}
		}
	}
	tick := time.Tick(2 * time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	fmt.Println("Counting packets by IP address.")
	for {
		select {
		case <-tick:
			fmt.Println("IPv4 Packets count:")
			printIPv4Map(ip4Map)
			fmt.Println("IPv6 Packets count:")
			printIPv6Map(ip6Map)
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}
}
