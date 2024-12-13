package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

func main() {
	if len(os.Args) < 3 || os.Args[1] != "-count" {
		fmt.Println("Usage: ./ebpf-packet-filter -count <interface_name>")
		os.Exit(0)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Error while removing memlock:", err)
	}
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Error while loading eBPF objects:", err)
	}
	defer objs.Close()
	ifname := os.Args[2]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Error while getting interface %s: %s", ifname, err)
	}
	link, err := link.AttachXDP(link.XDPOptions{
		Program: objs.CountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Error while attaching function:", err)
	}
	defer link.Close()
	log.Printf("Counting incoming packets on %s...", ifname)
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Print("Received signal, exiting...")
			return
		}
	}
}
