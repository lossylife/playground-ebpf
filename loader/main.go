package main

import (
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func main(){
	var filePath = flag.String("f", "./bpf.o", "bpf programe file")
	var ifName = flag.String("i", "lo", "network interface name")
	flag.Parse()


	collection, err := ebpf.LoadCollection(*filePath)
	if err != nil {
		fmt.Printf("load bpf collection failed, %s", err)
		return
	}

	nl, err := netlink.LinkByName(*ifName)
	if err != nil {
		fmt.Printf("get link failed, %s", err)
		return
	}

	for _, tmpProg := range collection.Programs {
		err = netlink.LinkSetXdpFd(nl, tmpProg.FD())
		if err != nil {
			fmt.Printf("link bpf program to network interface failed, %s", err)
			return
		}
	}

	fmt.Printf("load bpf program success\n")
}
