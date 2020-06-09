package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source = `
#include <uapi/linux/ptrace.h>

#define OFFSET(ptr, offset) (void*)ptr + offset * 8

struct event {
	u64  method_len;
	u64  path_len;
	char method[10];
	char path[128];
};
BPF_PERF_OUTPUT(events);

int handler(struct pt_regs *ctx)
{
	struct event e = {};

	u64 req;
	bpf_probe_read(&req, sizeof(req), OFFSET(PT_REGS_SP(ctx), 3));

	u64 data;

	// method
	bpf_probe_read(&data, sizeof(data), OFFSET(req, 0));
	bpf_probe_read(&e.method_len, sizeof(e.method_len), OFFSET(req, 1));

	bpf_probe_read(&e.method,
		e.method_len > sizeof(e.method) ? sizeof(e.method) : e.method_len,
		(void*)data);

	// path
	u64 url;
	bpf_probe_read(&url, sizeof(url), OFFSET(req, 2));
	bpf_probe_read(&data, sizeof(data), OFFSET(url, 7));
	bpf_probe_read(&e.path_len, sizeof(e.path_len), OFFSET(url, 8));

	bpf_probe_read(&e.path,
		e.path_len > sizeof(e.path) ? sizeof(e.path) : e.path_len,
		(void*)data);

	// emit event
	events.perf_submit(ctx, &e, sizeof(e));

	return 0;
}
`

type event struct {
	MethodLen uint64
	PathLen   uint64
	Method    [10]byte
	Path      [128]byte
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	uprobe, err := m.LoadKprobe("handler")
	if err != nil {
		log.Fatalf("Failed to load kprobe: %s\n", err)
	}

	err = m.AttachUprobe(os.Args[1], os.Args[2], uprobe, -1)
	if err != nil {
		log.Fatalf("could not attach uprobe to symbol: %s: %s", os.Args[2], err.Error())
	}

	table := bpf.NewTable(m.TableId("events"), m)
	channel := make(chan []byte, 100)

	perfMap, err := bpf.InitPerfMap(table, channel, nil)
	if err != nil {
		log.Fatalf("Failed to init perf map: %s\n", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var e event
		for {
			data := <-channel
			if err := binary.Read(bytes.NewBuffer(data), bpf.GetHostByteOrder(), &e); err != nil {
				fmt.Printf("failed to decode packet: %s\n", err)
				continue
			}
			method, path := string(e.Method[:e.MethodLen]), string(e.Path[:e.PathLen])
			fmt.Printf("%-10s %s\n", method, path)
		}
	}()
	fmt.Printf("%-10s %s\n", "Method", "Path")

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
