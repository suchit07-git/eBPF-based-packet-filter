package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const bpfProgramPath = "counter.o"

func ip4ToString(ip uint32) net.IP {
	address := make(net.IP, 4)
	binary.LittleEndian.PutUint32(address, ip)
	return address
}

func ip6ToString(ip [16]byte) string {
	return net.IP(ip[:]).String()
}

func printMap(m *ebpf.Map, ipToString func(interface{}) string) {
	iter := m.Iterate()
	var ip interface{}
	var count uint64
	for iter.Next(&ip, &count) {
		fmt.Printf("%s: %d packets\n", ipToString(ip), count)
	}
	if err := iter.Err(); err != nil {
		fmt.Printf("Error iterating map: %v\n", err)
	}
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
	if len(os.Args) < 3 || os.Args[1] != "-count" {
		fmt.Println("Usage: ./ebpf-packet-filter -count <interface_name>")
		os.Exit(0)
	}
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
	if ip4Map == nil || ip6Map == nil {
		log.Fatal("Failed to find required map in the BPF program")
	}
	ifname := os.Args[2]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Error while getting interface %s: %s", ifname, err)
	}
	prog := collection.Programs["xdp_ip_packet_counter"]
	if prog == nil {
		log.Fatal("Failed to find xdp_ip_packet_counter in the BPF program")
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
	tick := time.Tick(time.Second)
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
