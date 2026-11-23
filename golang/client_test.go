// File: golang/client_test.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall_test

import (
	"errors"
	"testing"
	"time"

	ucall "github.com/unum-cloud/ucall/golang"
)

func echoing(t *testing.T) string {
	t.Helper()
	return serving(t, ucall.NewInterface("127.0.0.1:0"), func(server *ucall.Server) {
		err := server.Get("/echo", func(request *ucall.Request) {
			query, err := request.QueryString()
			if err != nil {
				_ = request.ReplyError(ucall.HTTPStatusBadRequest, err.Error())
				return
			}
			_ = request.Reply(ucall.HTTPStatusOK, []string{"x-echo: yes"}, query)
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestBlockingCallsKeepOtherCompletions(t *testing.T) {
	url := echoing(t)
	client := client(t, 2)
	if err := client.Submit(ucall.ClientCall{Verb: ucall.VerbGet, URL: url + "/echo?first"}, 7); err != nil {
		t.Fatal(err)
	}
	second, err := client.Get(url + "/echo?second")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if body := bodyOf(t, second); body != "second" {
		t.Fatalf("answered %q", body)
	}
	completed := make([]ucall.Completed, 2)
	var taken []ucall.Completed
	for len(taken) == 0 {
		if taken, err = client.TakeCompleted(completed, 100*time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	first := taken[0]
	if len(taken) != 1 || first.Context != 7 || first.Err != nil {
		t.Fatalf("took %d, the first with context %d and error %v", len(taken), first.Context, first.Err)
	}
	defer first.Response.Close()
	if body := bodyOf(t, first.Response); body != "first" {
		t.Fatalf("answered %q", body)
	}
	fields := 0
	for name, value := range first.Response.Fields() {
		if string(name) == "x-echo" && string(value) == "yes" {
			fields++
		}
	}
	if fields != 1 {
		t.Fatal("the echoed header is missing from the fields")
	}
}

func TestFullClientsRefuse(t *testing.T) {
	client := client(t, 1)
	if err := client.Submit(ucall.ClientCall{Verb: ucall.VerbGet, URL: "http://127.0.0.1:1/"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := client.Submit(ucall.ClientCall{Verb: ucall.VerbGet, URL: "http://127.0.0.1:1/"}, 2); !errors.Is(err, ucall.StatusContended) {
		t.Fatalf("a full client answered %v", err)
	}
	_ = client.Close()
	if _, err := client.TakeCompleted(make([]ucall.Completed, 1), 0); !errors.Is(err, ucall.StatusUninitialized) {
		t.Fatalf("a closed client answered %v", err)
	}
}

func TestUnreachableServersFail(t *testing.T) {
	_, err := client(t, 1).Get("http://127.0.0.1:1/")
	if !errors.Is(err, ucall.StatusConnectionFailed) {
		t.Fatalf("an unreachable server answered %v", err)
	}
}
