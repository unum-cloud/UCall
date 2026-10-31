package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"
	"bytes"
    "flag"
    "strings"
)

var(
    limitSeconds int
    numConnections int
    hostname string
    port int
    batch int
    html bool
    req string
    buffer bytes.Buffer
)

func load_buffer() {
    a := 46
    b := 23
    jRPC := fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":%d,"session_id":%d},"id":0}`, a, b)
    buffer.WriteString(fmt.Sprintf("POST / HTTP/1.1\r\nHost: localhost:8545\r\nUser-Agent: python-requests/2.31.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(jRPC), jRPC))
    //fmt.Printf("%s\n",buffer.String())
}


func test_http(tcpAddr *net.TCPAddr ) {
    print("  Test http ... ")    
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
        println("connection failed:", err.Error())
        return
    }
    reply := make([]byte, 4096)

    jrpc := fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":46,"session_id":0},"id":0}`)
    req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: localhost:8558\r\nUser-Agent: python-requests/2.31.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(jrpc), jrpc)

    _, err = conn.Write([]byte(req))
    if err != nil {
        println("write error: %v\n", err)
        return
    }
    n, err := conn.Read(reply)
    if err != nil && !errors.Is(err, io.EOF) {
        println("read error: %v\n", err)
        return
    }
    rep := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: 38       \r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":true}")

    if rep != string(reply[:n]) {
        println("unexpected reply")
        println("    exp: ", rep)
        println("    act: ", string(reply[:n]))
        return
    }

    println("successful")
}
func test_big(tcpAddr *net.TCPAddr ) {
    print("  Test 4097 byte json ... ")    
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
        println("connection failed:", err.Error())
        return
    }
    reply := make([]byte, 4096)
    pad := bytes.Repeat([]byte("a"), 3992)
    req = fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":46,"session_id":0},"id":0, "padding":"%s"}`,pad)
    _, err = conn.Write([]byte(req))
    if err != nil {
        println("write error: %v\n", err)
        return
    }
    n, err := conn.Read(reply)
    if err != nil && !errors.Is(err, io.EOF) {
        println("read error: %v\n", err)
        return
    }
    rep := `{"jsonrpc":"2.0","id":0,"result":true}`
    if strings.Compare( rep, string(reply[:n]) ) != 0 {
        println("unexpected reply")
        println("    exp: ", rep)
        println("    act: ", string(reply[:n]))
        return
    }

    println("successful")
}
func test_partial(tcpAddr *net.TCPAddr ) {
    print("  Test partial ... ")    
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
        println("connection failed:", err.Error())
        return
    }
    reply := make([]byte, 4096)

    req = fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":46,"session_id"`)
    _, err = conn.Write([]byte(req))
    if err != nil {
        println("write error: %v\n", err)
        return
    }
    time.Sleep(1000 * time.Millisecond)
    req = fmt.Sprintf(`:0},"id":0}`)
    _, err = conn.Write([]byte(req))
    if err != nil {
        println("write second part error: %v\n", err)
        return
    }
    n, err := conn.Read(reply)
    if err != nil && !errors.Is(err, io.EOF) {
        println("read error: %v\n", err)
        return
    }
    rep := fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"result":true}`)
    if strings.Compare( rep, string(reply[:n]) ) != 0 {
        println("unexpected reply")
        println("    exp: ", rep)
        println("    act: ", string(reply[:n]))
        return
    }

    println("successful")
}

func test_close(tcpAddr *net.TCPAddr ) {
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
        println("connection failed:", err.Error())
        return
    }
    _, err = conn.Write(buffer.Bytes())
    if err != nil {
        fmt.Printf("Write Error: %v\n", err)
    }
    conn.Close()
}



func client(c chan int, tcpAddr *net.TCPAddr, tid int ) {
	  reply := make([]byte, 4096)

    start := time.Now()
    transmits := 0
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
	      println("Dial failed:", err.Error())
	      os.Exit(1)
    }

    for {
        _, err = conn.Write(buffer.Bytes())
        if err != nil {
            fmt.Printf("Write Error: %v\n", err)
            break
        }

        //conn.SetReadDeadline(time.Now().Add(time.Second*5))
        _, err := conn.Read(reply)
        //fmt.Printf("Reply\n%s",reply[:l])
        if err != nil && !errors.Is(err, io.EOF) {
            break
        }
        if time.Since(start).Seconds() >= float64(limitSeconds) {
            break
        }
        transmits++
    }
    conn.Close()
    c <- transmits
}

func test_generic(name string, tcpAddr *net.TCPAddr, req []byte, rep []byte ) {
    print("  Test ",name," ... ")    
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    if err != nil {
        println("connection failed:", err.Error())
        return
    }
    rbuf := make([]byte, 4096)
    request := fmt.Sprintf("POST / HTTP/1.1\r\nHost: localhost:8558\r\nUser-Agent: python-requests/2.31.0\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(req), req)

    _, err = conn.Write([]byte(request))
    if err != nil {
        println("write error: %v\n", err)
        return
    }
    n, err := conn.Read(rbuf)
    if err != nil && !errors.Is(err, io.EOF) {
        println("read error: %v\n", err)
        return
    }
    //reply := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n%s", len(rep), rep)
    if string(rep) != string(rbuf[78:n]) {
        println("unexpected reply")
        println("    exp: ", string(rep))
        println("    act: ", string(rbuf[78:n]))
        return
    }

    println("successful")
}


func main() {

    flag.StringVar(&hostname,    "h", "localhost", "hostname")
    flag.IntVar(&port,           "p", 8545,        "port")
    flag.IntVar(&numConnections, "c", 16,          "Number of connections")
    flag.IntVar(&limitSeconds,   "s", 2,           "Stop after n seconds")
    flag.IntVar(&batch,          "b", 1,           "Batch n requests together")
    flag.BoolVar(&html,          "html", false,    "Send an html request instead of jsonrpc")
    flag.Parse()
    
    servAddr := fmt.Sprintf(`%s:%d`,hostname,port)
	tcpAddr, err := net.ResolveTCPAddr("tcp", servAddr)
	if err != nil {
		  println("ResolveTCPAddr failed:", err.Error())
		  os.Exit(1)
	}

    //test_rpc(tcpAddr)
    //test_http(tcpAddr)
    //test_big(tcpAddr)
    //test_partial(tcpAddr)

    
    req := fmt.Sprintf(`{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":46,"session_id":0},"id":0}`)
    rep := fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"result":true}`)
    test_generic("validate_session", tcpAddr, []byte(req), []byte(rep) )

    req = fmt.Sprintf(`{"jsonrpc":"2.0","method":"echo","params":{"data":"session_id"},"id":0}`)
    rep = fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"result":"session_id"}`)
    test_generic("echo", tcpAddr, []byte(req), []byte(rep) )

    req = fmt.Sprintf(`{"jsonrpc":"2.0","method":"create_user","params":{"age":46,"name":"My Name","bio":"My bio","avatar":"fdasfsadbfasdfasdwefdsahfsds"},"id":0}`)
    rep = fmt.Sprintf(`{"jsonrpc":"2.0","method":"create_user","params":{"age":46,"name":"My Name","bio":"My bio","avatar":"fdasfsadbfasdfasdwefdsahfsds"},"id":0}`)
    test_generic("create_user", tcpAddr, []byte(req), []byte(rep) )

    req = fmt.Sprintf(`{"jsonrpc":"2.0","method":"set","params":{"key":"test","value":"val"},"id":0}`)
    rep = fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"result":"OK"}`)
    test_generic("set", tcpAddr, []byte(req), []byte(rep) )
    req = fmt.Sprintf(`{"jsonrpc":"2.0","method":"get","params":{"key":"test","value":"val"},"id":0}`)
    rep = fmt.Sprintf(`{"jsonrpc":"2.0","id":0,"result":"val"}`)
    test_generic("get", tcpAddr, []byte(req), []byte(rep) )


    print("  Test closing connections ... ")    
    n := 1
    for n < 2000 {
        test_close(tcpAddr)
        n += 1
    }
    println("successful")

    test_http(tcpAddr)

    load_buffer()

    print("  Test many connections ... ")    
    num := 1024
    c := make(chan int)
    for i := 0; i < num; i++ {
        go client( c, tcpAddr, i )
    }

    // Wait for all connections to finish
    transmits := 0
    for i := 0; i < num; i++ {
        transmits += <-c
    }

}
