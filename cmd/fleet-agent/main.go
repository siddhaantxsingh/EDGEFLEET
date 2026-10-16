// fleet-agent: the on-device update agent.
//
//	fleet-agent -server http://cp:8080 -id dev-1 -state /var/lib/fleet -token <enroll token> \
//	            -release-pubkey <base64> -initial-version 1.0 -exec
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"edgefleet/internal/agent"
	"edgefleet/internal/proto"
)

type labels map[string]string

func (l labels) String() string { return "" }
func (l labels) Set(v string) error {
	k, val, _ := strings.Cut(v, "=")
	l[k] = val
	return nil
}

func main() {
	lb := labels{}
	server := flag.String("server", "http://127.0.0.1:8080", "control plane URL")
	id := flag.String("id", "", "device id")
	state := flag.String("state", "fleet-agent", "state directory")
	token := flag.String("token", "", "enrollment token (first start only)")
	pubkey := flag.String("release-pubkey", "", "base64 Ed25519 release key")
	rootPub := flag.String("root-pubkey", "", "key-rotation mode: pinned base64 Ed25519 root key (replaces -release-pubkey)")
	initial := flag.String("initial-version", "1.0", "version installed in slot a")
	execApp := flag.Bool("exec", false, "run the application from the active slot")
	hw := flag.Duration("health-window", 2*time.Second, "time a new version must stay up")
	hb := flag.Duration("heartbeat", 0, "override the server's heartbeat interval")
	flag.Var(lb, "label", "k=v device label (repeatable)")
	flag.Parse()
	cfg := agent.Config{Server: *server, DeviceID: *id, StateDir: *state, EnrollToken: *token, Labels: lb,
		InitialVersion: *initial, Exec: *execApp, HealthWindow: *hw, Heartbeat: *hb}
	if *rootPub != "" {
		root, err := proto.DecodePublicKey(*rootPub)
		if err != nil {
			log.Fatal("-root-pubkey: ", err)
		}
		cfg.RootKey = root
	} else {
		key, err := proto.DecodePublicKey(*pubkey)
		if err != nil {
			log.Fatal("-release-pubkey: ", err)
		}
		cfg.ReleaseKey = key
	}
	a, err := agent.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := a.Start(); err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		cancel()
	}()
	log.Printf("agent %s running version %s", *id, a.BootState().ActiveVersion)
	a.Run(ctx)
	a.Stop()
}
