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

func ipToString(ip uint32) net.IP {
	address := make(net.IP, 4)
	binary.LittleEndian.PutUint32(address, ip)
	return address
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
	ipMap := collection.Maps["pkt_count"]
	if ipMap == nil {
		log.Fatal("Failed to find pkt_count map in the BPF program")
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
			iter := ipMap.Iterate()
			var ip uint32
			var count uint64
			for iter.Next(&ip, &count) {
				log.Printf("%s: %d packets\n", ipToString(ip), count)
			}
			if err := iter.Err(); err != nil {
				log.Fatal("Error iterating map:", err)
			}
		case <-stop:
			log.Println("Received signal, exiting...")
			return
		}
	}
}
