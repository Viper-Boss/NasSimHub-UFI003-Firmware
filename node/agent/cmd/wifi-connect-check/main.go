package main

import (
	"context"
	"fmt"
	"github.com/human-agent65535/nassimhub-node/agent/netbackend/networkmanager"
	"github.com/human-agent65535/nassimhub-node/proto"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: wifi-connect-check SSID; password on standard input")
	}
	p, err := io.ReadAll(io.LimitReader(os.Stdin, 1024))
	if err != nil {
		return err
	}
	password := strings.TrimSuffix(strings.TrimSuffix(string(p), "\n"), "\r")
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	b := networkmanager.New(networkmanager.Options{})
	scan, err := b.Scan(ctx)
	if err != nil {
		return err
	}
	security := proto.WiFiSecurityUnknown
	for _, n := range scan.Networks {
		if n.SSID == os.Args[1] {
			security = n.Security
			break
		}
	}
	if security == proto.WiFiSecurityUnknown {
		return fmt.Errorf("requested SSID was not found")
	}
	fmt.Println("Detected security:", security)
	if _, err = b.Connect(ctx, proto.WiFiConnectRequest{SSID: os.Args[1], Security: security, PSK: password}); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		s, err := b.Status(ctx)
		if err != nil {
			return err
		}
		if s.State == proto.WiFiFailed {
			return fmt.Errorf("connection failed: %s", s.FailureReason)
		}
		if s.State == proto.WiFiConnected && s.SSID == os.Args[1] {
			fmt.Printf("PASS connected SSID=%s IP=%s saved=%s\n", s.SSID, s.IPv4, s.SavedSSID)
			return nil
		}
	}
}
