// File: golang/server_test.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	ucall "github.com/unum-cloud/ucall/golang"
)

// serving starts a loopback server with routes registered by setup, polls it on its own goroutine,
// and answers its URL prefix; the cleanup stops and closes it.
func serving(t *testing.T, network ucall.Interface, setup func(server *ucall.Server)) string {
	t.Helper()
	server, err := ucall.NewServer([]ucall.Interface{network}, nil)
	if err != nil {
		t.Fatal(err)
	}
	setup(server)
	address, ok := server.Address(0)
	if !ok {
		t.Fatal("the server has no address")
	}
	polled := make(chan error)
	go func() { polled <- server.TakeCalls(0) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-polled; err != nil {
			t.Error(err)
		}
		_ = server.Close()
	})
	return "http://" + address
}

// bodyOf reads a buffered response's body, which every test here expects readable.
func bodyOf(t *testing.T, response *ucall.Response) string {
	t.Helper()
	body, err := response.Body()
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func client(t *testing.T, connections uint) *ucall.Client {
	t.Helper()
	client, err := ucall.NewClient(&ucall.ClientOptions{Connections: connections})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestGreetingRoundTrip(t *testing.T) {
	url := serving(t, ucall.NewInterface("127.0.0.1:0"), func(server *ucall.Server) {
		err := server.Get("/hello/{name}", func(request *ucall.Request) {
			name, err := request.PathParameter("name")
			if err != nil {
				_ = request.ReplyError(ucall.HTTPStatusBadRequest, err.Error())
				return
			}
			_ = request.Reply(ucall.HTTPStatusOK, []string{"content-type: text/plain"}, append([]byte("Hello, "), name...))
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	response, err := client(t, 1).Get(url + "/hello/world")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	if body := bodyOf(t, response); response.StatusCode() != ucall.HTTPStatusOK || body != "Hello, world" {
		t.Fatalf("answered %d %q", response.StatusCode(), body)
	}
	if kind, err := response.Header("Content-Type"); err != nil || string(kind) != "text/plain" {
		t.Fatalf("content type %q: %v", kind, err)
	}
	if _, err := response.Header("X-Absent"); !errors.Is(err, ucall.StatusNotFound) {
		t.Fatalf("an absent header answered %v", err)
	}
}

func TestUnrepliedRequestsAnswer500(t *testing.T) {
	url := serving(t, ucall.NewInterface("127.0.0.1:0"), func(server *ucall.Server) {
		if err := server.Get("/silent", func(request *ucall.Request) {}); err != nil {
			t.Fatal(err)
		}
	})
	response, err := client(t, 1).Get(url + "/silent")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	if response.StatusCode() != ucall.HTTPStatusInternalError {
		t.Fatalf("answered %d", response.StatusCode())
	}
}

func TestRegisteringTwiceFails(t *testing.T) {
	server, err := ucall.NewServer([]ucall.Interface{ucall.NewInterface("127.0.0.1:0")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	handler := func(request *ucall.Request) {}
	if err := server.Get("/twice", handler); err != nil {
		t.Fatal(err)
	}
	if err := server.Get("/twice", handler); !errors.Is(err, ucall.StatusAlreadyExists) {
		t.Fatalf("a second registration answered %v", err)
	}
	if err := server.Get("/none", nil); !errors.Is(err, ucall.StatusInvalidArgument) {
		t.Fatalf("a route without a handler answered %v", err)
	}
}

// A detached request's file reply finishes on the polling goroutine, so a worker waits on it while
// the route's handler stays registered: the wait claims nocallback, and a handler run inside it
// would crash the process.
func TestDetachedFileReply(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "clip"), []byte("frame"), 0o644); err != nil {
		t.Fatal(err)
	}
	network := ucall.NewInterface("127.0.0.1:0")
	network.ReplyDirectories = []string{directory}
	handed := make(chan *ucall.DetachedRequest, 1)
	url := serving(t, network, func(server *ucall.Server) {
		if err := server.Get("/clip", func(request *ucall.Request) { handed <- request.Detach() }); err != nil {
			t.Fatal(err)
		}
	})
	sent := make(chan error, 1)
	go func() {
		detached := <-handed
		deferred, err := detached.ReplyParts(ucall.HTTPStatusOK, nil, []ucall.ReplyPart{ucall.BytesPart([]byte("key")), ucall.PathPart(ucall.PathRange{Path: "clip"})})
		if err != nil {
			sent <- err
			return
		}
		t.Logf("the file reply polls %v before the wait", deferred.Status())
		_, err = deferred.Wait()
		sent <- err
	}()
	response, err := client(t, 1).Get(url + "/clip")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	if body := bodyOf(t, response); body != "keyframe" {
		t.Fatalf("answered %q", body)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
}

// A blocking read allocates its frame alone, a refusal its Error alone, and a deferred pull adds
// only its Deferred's cleanup.
func TestCallsAllocateOnlyTheirFrames(t *testing.T) {
	measured := make(chan [2]float64, 1)
	url := serving(t, ucall.NewInterface("127.0.0.1:0"), func(server *ucall.Server) {
		err := server.Post("/measure", func(request *ucall.Request) {
			path := testing.AllocsPerRun(100, func() { _, _ = request.Path() })
			detached := request.Detach()
			pull := testing.AllocsPerRun(100, func() {
				chunk, err := detached.BodyChunk()
				if err == nil {
					_, _ = chunk.Wait()
				}
			})
			measured <- [2]float64{path, pull}
			_ = detached.Reply(ucall.HTTPStatusNoContent, nil, nil)
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	response, err := client(t, 1).Post(url+"/measure", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Close()
	allocations := <-measured
	closed := client(t, 1)
	_ = closed.Close()
	refused := testing.AllocsPerRun(100, func() { _ = closed.Submit(ucall.ClientCall{Verb: ucall.VerbGet, URL: url}, 0) })
	// The holder stands for the Deferred, whose cleanup the runtime registers the same way.
	cleanup := testing.AllocsPerRun(100, func() { runtime.AddCleanup(new([2]uintptr), func(uint) {}, 0) })
	t.Logf("allocations: %v per blocking read, %v per refusal, %v per deferred pull and wait", allocations[0], refused, allocations[1])
	if allocations[0] != 1 {
		t.Errorf("a blocking read allocated %v times", allocations[0])
	}
	if refused != 1 {
		t.Errorf("a refused submit allocated %v times", refused)
	}
	if allocations[1] != 1+cleanup {
		t.Errorf("a deferred pull allocated %v times, %v of them registering its cleanup", allocations[1], cleanup)
	}
}
