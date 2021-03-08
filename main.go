package main

import(
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/cilium/ebpf"
	"time"
)

type PktStatRec struct {
	RxPackets uint64
	RxBytes   uint64
}

func NewPktStatRecFromBin(b []byte) (*PktStatRec, error) {
	var rec PktStatRec
	buf := bytes.NewReader(b)
	err := binary.Read(buf, binary.LittleEndian, &rec)
	return &rec, err
}

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
		for entries.Next(&key, value) {
			rec,err := NewPktStatRecFromBin(value)
			if err == nil {
				fmt.Printf("key: %v, value: %d pkts, %d bytes\n", key, rec.RxPackets, rec.RxBytes)
			}
		}

		time.Sleep(time.Second)
	}
}
