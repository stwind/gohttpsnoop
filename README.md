# gohttpsnoop

An experiment on tracing Go function with complex struct arguments.

## What it does

This program will trace HTTP server handlers by attaching uprobe to a handler function with eBPF, and print the method and path whenever the the function called, i.e. an request accepted.

To seen it in action

```sh
$ go build -o server server/main.go # build the server
$ go run main.go ./server/main main.ping # start the snooper
Method     Path
```

Now by running `./server/main`, a server will be started and sent a request, the snooper will capture it and print out

```
GET        /ping
```

## How it works

### Problem

Let's say we want to trace an Golang HTTP/HTTPS server for every incoming request. For plain HTTP it would be easy with tcpdump, but not so much with HTTPS. It could easier with eBPF. 

For example for this simple server program

```go
package main

import (
	"fmt"
	"net/http"
)

func ping(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "pong\n")
}

func main() {
	http.HandleFunc("/ping", ping)
	http.ListenAndServe(":8090", nil)
}
```

We want to print a message every time the `main.ping` function was called

```
GET /ping
```

This could be done by attaching an uprobe to `main.ping` and reading the necessary information (method and path) from the `http.Request` argument.

For Go, the slightly difficult part is reading these information from functions arguments inside an eBPF program.

In [Golang bcc/BPF Function Tracing](http://www.brendangregg.com/blog/2017-01-31/golang-bcc-bpf-function-tracing.html), Brendan Gregg demonstrated how to read function arguments from the stack. And in [Tracing Go Functions with eBPF Part 2](https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-2/), Grant Seltzer Richman also showed how to extract function arguments by calculating stack offset or using  [weaver](https://github.com/grantseltzer/weaver). 

But these are only for primitive type arguments, our tasks here is to go deeper into the [`http.Request`](https://golang.org/pkg/net/http/#Request) to find `http.Request.Method` and `http.Request.URL.Path`.

### Solution

#### Locating the arguments

The first step was to get the value of `req` in the above program, which is a pointer to `http.Request`. We already knew that arguments are passed by stack, so let's take a look at the stack using gdb.

Before that we have to figure out the size of `http.ResponseWriter` and `*http.Request`

```go
package main

import (
	"fmt"
	"net/http"
	"unsafe"
)

func ping(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "pong\n")
	fmt.Printf("w size: %d\n", unsafe.Sizeof(w))
	fmt.Printf("req size: %d\n", unsafe.Sizeof(req))
}

func main() {
	http.HandleFunc("/ping", ping)
	go http.ListenAndServe(":8090", nil)
	http.Get("http://localhost:8090/ping")
}
```

```sh
$ go run main.go
w size: 16
req size: 8
```

So it is 16 bytes and 8 bytes. Now let's confirm the actual values on the stack with gdb. 

We change the `ping` function to print out the bytes and pointer value.

```go
func ping(w http.ResponseWriter, req *http.Request) {
	fmt.Fprint(w, "pong\n")
	wb := (*[16]byte)(unsafe.Pointer(&w))
	fmt.Printf("w: %x %x\n", wb[:8], wb[8:])
	fmt.Printf("req: %p\n", unsafe.Pointer(req))
}
```

And compare with the stack with gdb

```sh
$ go build main.go
$ gdb -q main
Reading symbols from main...
...
(gdb) set print thread-events off
(gdb) b main.ping
Breakpoint 1 at 0x6692e0: file /vagrant/main.go, line 9.
(gdb) r
Starting program: /vagrant/main
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Switching to Thread 0x7fffd0916700 (LWP 1840454)]

Thread 3 "main" hit Breakpoint 1, main.ping (w=..., req=0xc00009e300) at /vagrant/main.go:9
9	func ping(w http.ResponseWriter, req *http.Request) {
(gdb) x/4xg $rsp
0xc000043b58:	0x000000000063d544	0x0000000000766a60
0xc000043b68:	0x000000c0000a6000	0x000000c00009e300
(gdb) c
Continuing.
w: 606a760000000000 00600a00c0000000
req: 0xc00009e300
[Inferior 1 (process 1840447) exited normally]
```

We can see that the bytes value of `w http.ResponseWriter` is `606a760000000000 00600a00c0000000`, corresponding to the stack offset from 8 to 24 (2nd and 3rd 64-bit word), i.e. `0x0000000000766a60` and `0x000000c0000a6000` (little-endian). And the bytes value of `req *http.Request` is `0xc00009e300`, which corresponds to the stack offset from 24 to 32 (4th 64-bit word), i.e. `0x000000c00009e300`.

#### Digging into struct

Next we want to get the method and path from the `http.Request` struct, i.e. `http.Request.Method` and `http.Request.URL.Path`. Let's first figure out the offsets of these fields.

```go
package main

import (
	"fmt"
	"net/http"
	"unsafe"
)

func main() {
	req := &http.Request{}
	fmt.Printf("req.Method offset: %d\n", unsafe.Offsetof(req.Method))
	fmt.Printf("req.URL offset: %d\n", unsafe.Offsetof(req.URL))
	fmt.Printf("req.URL.PATH offset: %d\n", unsafe.Offsetof(req.URL.Path))
}
```

```sh
$ go run main.go
req.Method offset: 0
req.URL offset: 16
req.URL.PATH offset: 56
```

With these offset we could try to read the values from the pointer to `req`. Since the values we want are `string`, there is one more important thing, in Go `string` are represented as 16 bytes values, with the first 8 bytes as the pointer to the heap and the second 8 bytes as the lengths. This can be inspected by converting a `string` to `reflect.StringHeader`.

```go
package main

import (
	"fmt"
	"reflect"
	"unsafe"
)

func main() {
	s := "hello"
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	fmt.Printf("data: %p\n", unsafe.Pointer(sh.Data))
	fmt.Printf("len: %d\n", sh.Len)
}
```

```sh
$ go run main.go
data: 0x10ce63b
len: 5
```

We can now try to get the `http.Request.Method` and `http.Request.URL.Path`  values in gdb. Start the server again:

```sh
$ gdb -q main
Reading symbols from main...
...
(gdb) set print thread-events off
(gdb) b main.ping
Breakpoint 1 at 0x6692e0: file /vagrant/main.go, line 9.
(gdb) r
Starting program: /vagrant/main
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Switching to Thread 0x7fffcbfff700 (LWP 1872431)]

Thread 4 "main" hit Breakpoint 1, main.ping (w=..., req=0xc0000e6400) at /vagrant/main.go:9
warning: Source file is more recent than executable.
9	func ping(w http.ResponseWriter, req *http.Request) {
(gdb) x/4xg $rsp
0xc00003eb58:	0x000000000063d544	0x0000000000766a60
0xc00003eb68:	0x000000c000182000	0x000000c0000e6400
```

The `req` is at `0x000000c0000e6400`, `req.Method` is at offset `0`, so the address of `req.Method` is also `0x000000c0000e6400`

```sh
(gdb) x/2xg 0x000000c0000e6400
0xc0000e6400:	0x000000c0000b6160	0x0000000000000003
(gdb) x/3cb 0x000000c0000b6160
0xc0000b6160:	71 'G'	69 'E'	84 'T'
```

Nice, we get the method value of `GET`. Now for the `req.URL.Path`, start with `req.URL` at offset `16` from `req`

```sh
(gdb) x/1xg 0x000000c0000e6400+16
0xc0000e6410:	0x000000c0000e4300
```

So `0x000000c0000e4300` is the address of `req.URL`, now for the `req.URL.Path` at offset `56`

```sh
(gdb) x/2xg 0x000000c0000e4300+56
0xc0000e4338:	0x000000c0000b6164	0x0000000000000005
(gdb) x/5cb 0x000000c0000b6164
0xc0000b6164:	47 '/'	112 'p'	105 'i'	110 'n'	103 'g'
```

We've successfully found the `req.URL.Path` to be `/ping` !

#### Transform into eBPF program

```c
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
```

## References

* [Golang bcc/BPF Function Tracing](http://www.brendangregg.com/blog/2017-01-31/golang-bcc-bpf-function-tracing.html)
* [Tracing Go Functions with eBPF Part 2](https://www.grant.pizza/blog/tracing-go-functions-with-ebpf-part-2/)
* [grantseltzer/weaver: Trace Go program execution with uprobes and eBPF](https://github.com/grantseltzer/weaver)