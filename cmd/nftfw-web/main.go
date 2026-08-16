package main

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
)

var page = template.Must(template.New("index").Parse(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NFT Firewall V2</title><style>body{font:16px system-ui;background:#111;color:#eee;max-width:900px;margin:2rem auto;padding:0 1rem}pre{background:#1d1d1d;padding:1rem;overflow:auto}h1{font-size:1.5rem}button{padding:.5rem}</style></head><body><h1>NFT Firewall V2</h1><p id="status">Loading...</p><pre id="data"></pre><script>async function refresh(){const r=await fetch('/api/status',{cache:'no-store'});const d=await r.json();document.getElementById('status').textContent=d.status||'UNKNOWN';document.getElementById('data').textContent=JSON.stringify(d,null,2)}refresh();setInterval(refresh,5000)</script></body></html>`))

func main() {
	bind := os.Getenv("NFTFW_WEB_BIND")
	if bind == "" {
		bind = "127.0.0.1:8787"
	}
	sock := os.Getenv("NFTFW_STATUS_SOCKET")
	if sock == "" {
		sock = "/run/nftfw/status.sock"
	}
	client := &http.Client{Timeout: 5 * time.Second}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		headers(w, "text/html; charset=utf-8")
		_ = page.Execute(w, nil)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		resp, err := api.Call(r.Context(), sock, api.Request{Op: "status"})
		if err != nil {
			http.Error(w, "status unavailable", http.StatusServiceUnavailable)
			return
		}
		b, _ := json.Marshal(resp.Data)
		headers(w, "application/json; charset=utf-8")
		w.Write(b)
	})
	srv := &http.Server{Addr: bind, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	_ = client
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
}
func headers(w http.ResponseWriter, ct string) {
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
}
