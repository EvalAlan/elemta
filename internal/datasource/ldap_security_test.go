package datasource

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestLDAPRefusesBindWhenStartTLSFails(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	seen := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			seen <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		packet := make([]byte, 1024)
		n, _ := conn.Read(packet)
		seen <- packet[:n]
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	l := NewLDAP(Config{Host: host, Port: port, Username: "service", Password: "private"})
	if err := l.Connect(); err == nil {
		t.Fatal("bound after StartTLS was refused")
	}
	packet := <-seen
	if !bytes.Contains(packet, []byte("1.3.6.1.4.1.1466.20037")) || bytes.Contains(packet, []byte("private")) {
		t.Fatalf("first LDAP packet was not a credential-free StartTLS request: %x", packet)
	}
}
