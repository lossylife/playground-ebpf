package main

import(
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"time"
)

func main(){
	var mapPath = flag.String("p", "/sys/fs/bpf/eth0/test", "help message for flag n")
	flag.Parse()

	m,err := ebpf.LoadPinnedMap(*mapPath)
	if err != nil {
		fmt.Printf("load pinned map failed, ", err)
		return
	}


	for {
		var key string
		var value uint32
		entries := m.Iterate()
		for entries.Next(&key, &value) {
			fmt.Printf("key: %s, value: %d\n", key, value)
		}

		time.Sleep(time.Second)
	}
}
