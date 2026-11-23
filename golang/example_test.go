// File: golang/example_test.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall_test

import (
	"fmt"
	"log"

	ucall "github.com/unum-cloud/ucall/golang"
)

// The README Quickstart: a server answers on loopback, and a client calls it.
func Example() {
	server, err := ucall.NewServer([]ucall.Interface{ucall.NewInterface("127.0.0.1:0")}, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	err = server.Get("/hello/{name}", func(request *ucall.Request) {
		name, _ := request.PathParameter("name")
		greeting := append([]byte("Hello, "), name...)
		_ = request.Reply(ucall.HTTPStatusOK, []string{"content-type: text/plain"}, greeting)
	})
	if err != nil {
		log.Fatal(err)
	}
	address, _ := server.Address(0)
	polled := make(chan error)
	go func() { polled <- server.TakeCalls(0) }()

	client, err := ucall.NewClient(&ucall.ClientOptions{Connections: 1})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	response, err := client.Get("http://" + address + "/hello/world")
	server.Stop()
	if err := <-polled; err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer response.Close()
	body, err := response.Body()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
	// Output: Hello, world
}
