package main

import (
	"flag"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func main(){
	var filePath = flag.String("f", "./bpf.o", "bpf programe file")
	var ifName = flag.String("i", "lo", "network interface name")
	flag.Parse()


	collection, err := ebpf.LoadCollection(*filePath)
	if err != nil {
		return
	}

	nl, err := netlink.LinkByName(*ifName)
	if err != nil {
		return
	}

	for _, tmpProg := range collection.Programs {
		err = netlink.LinkSetXdpFd(nl, tmpProg.FD())
		if err != nil {
			return
		}
	}
}
