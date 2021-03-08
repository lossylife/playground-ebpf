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

	info,err := m.Info()
	if err != nil {
		fmt.Printf("get map info failed, ", err)
		return
	}
	fmt.Println("load pinned map success: ", *mapPath, "\n", info)

	for {
		fmt.Println("try to fetch key/value:")
		var key uint32
		value := make([]byte, 16)
		entries := m.Iterate()
		for entries.Next(&key, &value) {
			fmt.Printf("key: %v, value: %v\n", key, value)
		}

		time.Sleep(time.Second)
	}
}
