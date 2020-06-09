package main

import (
	"fmt"
	"net/http"
	"time"
	"unsafe"
)

func ping(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "pong\n")
	wb := (*[16]byte)(unsafe.Pointer(&w))
	fmt.Printf("w: %x %x\n", wb[:8], wb[8:])
	fmt.Printf("req: %p\n", unsafe.Pointer(req))
}

func main() {
	http.HandleFunc("/ping", ping)
	go http.ListenAndServe(":8090", nil)
	time.Sleep(time.Second)
	http.Get("http://localhost:8090/ping")
}
