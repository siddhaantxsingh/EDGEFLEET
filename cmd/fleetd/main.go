// fleetd: the fleet control plane.
//
//	FLEET_ADMIN_TOKEN=... fleetd -data ./fleet -listen 127.0.0.1:8080 -release-pubkey <base64>
//	FLEET_ADMIN_TOKEN=... fleetd -data ./fleet -root-pubkey <base64> -keyset keyset.json   # key-rotation mode
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"encoding/json"

	"edgefleet/internal/proto"
	"edgefleet/internal/server"
)

func main() {
	data := flag.String("data", "fleet-data", "state directory")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	pubkey := flag.String("release-pubkey", "", "base64 Ed25519 public key that signs releases")
	hb := flag.Int("heartbeat-sec", 30, "device heartbeat interval")
	rootPub := flag.String("root-pubkey", "", "key-rotation mode: base64 Ed25519 root key that signs key sets")
	ksPath := flag.String("keyset", "", "key-rotation mode: initial signed key set (JSON from fleetctl keyset)")
	tick := flag.Duration("tick", time.Second, "rollout controller interval")
	flag.Parse()
	cfg := server.Config{DataDir: *data, AdminToken: os.Getenv("FLEET_ADMIN_TOKEN"), HeartbeatSec: *hb, TickInterval: *tick}
	if *rootPub != "" {
		root, err := proto.DecodePublicKey(*rootPub)
		if err != nil {
			log.Fatal("-root-pubkey: ", err)
		}
		cfg.RootKey = root
		if *ksPath != "" {
			b, err := os.ReadFile(*ksPath)
			if err != nil {
				log.Fatal(err)
			}
			var ks proto.SignedKeySet
			if err := json.Unmarshal(b, &ks); err != nil {
				log.Fatal("-keyset: ", err)
			}
			cfg.KeySet = &ks
		}
	} else {
		key, err := proto.DecodePublicKey(*pubkey)
		if err != nil {
			log.Fatal("-release-pubkey: ", err)
		}
		cfg.ReleaseKey = key
	}
	s, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	log.Printf("fleetd listening on %s", *listen)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	srv.Shutdown(ctx)
	cancel()
	s.Close()
}
