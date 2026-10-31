package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"time"
	"bytes"
  	"flag"
)

var(
    limitSeconds int
    limitTransmits int
    port int
    batch int
    html bool
    req string
)

func main() {

  flag.IntVar(&port,           "p", 8545,      "port")
  flag.IntVar(&limitSeconds,   "s", 2,         "Stop after n seconds")
  flag.IntVar(&limitTransmits, "n", 1_000_000, "Stop after n requests")
  flag.IntVar(&batch,          "b", 0,         "Batch n requests together")
  flag.BoolVar(&html,          "html", false,  "Send an html request instead of jsonrpc")
  flag.Parse()

	servAddr := fmt.Sprintf(`localhost:%d`,port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		println("ResolveTCPAddr failed:", err.Error())
		os.Exit(1)
	}

	start := time.Now()
	reply := make([]byte, 4096)
	restarts := 0
	transmits := 0

  var buffer bytes.Buffer

  if batch > 0 {
      for i := 0; i < batch; i++ {
          a := rand.Intn(1000)
          b := rand.Intn(1000)
          buffer.WriteString(fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":%d,"session_id":%d},"id":0}`, a, b))
      }
  }

  a := rand.Intn(1000)
  b := rand.Intn(1000)

  if html {
      jRPC := fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":%d,"session_id":%d},"id":0}`, a, b)
      req := fmt.Sprintf(`POST / HTTP/1.1\r\nHost: localhost:8558\r\nUser-Agent: python-requests/2.31.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s`, len(jRPC), jRPC) 
      _ = req
  } else {
      req := fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":%d,"session_id":%d},"id":0}`, a, b)
      _ = req
  }

	for {
		conn, err := net.DialTCP("tcp", nil, tcpAddr)
		if err != nil {
			println("Dial failed:", err.Error())
			os.Exit(1)
		}

		for {

      if batch > 0 {
			    _, err = conn.Write(buffer.Bytes())
      } else {
			    _, err = conn.Write([]byte(req))
      }
			if err != nil {
				break
			}

			_, err = conn.Read(reply)
			if err != nil && !errors.Is(err, io.EOF) {
				break
			}
			if transmits >= limitTransmits || time.Since(start).Seconds() >= float64(limitSeconds) {
				break
			}
			transmits++
		}
		conn.Close()
		if transmits >= limitTransmits || time.Since(start).Seconds() >= float64(limitSeconds) {
			break
		}
		restarts++
	}

	elapsed := time.Since(start)
	latency := float64(elapsed.Microseconds()) / float64(transmits)
	speed := float64(transmits) / float64(elapsed.Seconds())
  if batch > 0 { 
      speed *= float64(batch) 
	    fmt.Printf("Took %s to perform %d queries with %d cmds per query\n", elapsed, transmits, batch)
  } else {
	    fmt.Printf("Took %s to perform %d queries\n", elapsed, transmits)
  }
	fmt.Printf("Mean latency is %.1f microsecond\n", latency)
	fmt.Printf("Resulting in %.1f commands/second\n", speed)
	fmt.Printf("Recreating %d TCP connections\n", restarts)

}
