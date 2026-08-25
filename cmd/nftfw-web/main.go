package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/unknown0152/nft-firewall-v2/internal/api"
	"github.com/unknown0152/nft-firewall-v2/internal/version"
)

const pageHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NFT Firewall V2</title>
  <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
  <header class="topbar">
    <div class="brand"><span class="brand-mark" aria-hidden="true"></span><h1>NFT Firewall V2</h1></div>
    <div class="toolbar"><span id="updated">Waiting for status</span><button id="refresh" type="button">Refresh</button></div>
  </header>
  <main>
    <section class="overview" aria-label="Firewall overview">
      <div class="metric"><span>Overall health</span><strong id="overall"><i class="status-dot"></i>Loading</strong></div>
      <div class="metric"><span>Active generation</span><strong id="generation">-</strong></div>
      <div class="metric"><span>Kill switch</span><strong id="killswitch">-</strong></div>
      <div class="metric"><span>Blocked addresses</span><strong id="blocked">-</strong></div>
    </section>

    <section class="details">
      <div class="detail-group">
        <div class="section-heading"><h2>Policy state</h2><span id="drift" class="tag">Checking</span></div>
        <dl>
          <div><dt>IPv6 mode</dt><dd id="ipv6">-</dd></div>
          <div><dt>Policy checksum</dt><dd id="checksum" class="mono">-</dd></div>
          <div><dt>Zones / policies</dt><dd id="policy-count">-</dd></div>
          <div><dt>Database</dt><dd id="database">-</dd></div>
          <div><dt>Pending generation</dt><dd id="pending">None</dd></div>
        </dl>
      </div>
      <div class="detail-group">
        <div class="section-heading"><h2>WireGuard</h2><span id="wg-health" class="tag">Checking</span></div>
        <dl>
          <div><dt>Interface</dt><dd id="wg-interface">Configured</dd></div>
          <div><dt>Peers</dt><dd id="wg-peers">-</dd></div>
          <div><dt>Endpoints</dt><dd id="wg-endpoints">-</dd></div>
          <div><dt>Last handshake</dt><dd id="wg-handshake">-</dd></div>
          <div><dt>Reason</dt><dd id="reason">None</dd></div>
        </dl>
      </div>
    </section>

    <section class="table-section">
      <div class="section-heading"><h2>Dynamic claims</h2><span id="claim-total">0 active claims</span></div>
      <div class="table-wrap"><table><thead><tr><th>Source</th><th>Claims</th></tr></thead><tbody id="claims"></tbody></table></div>
    </section>
    <section class="table-section">
      <div class="section-heading"><h2>Integrations</h2></div>
      <div class="table-wrap"><table><thead><tr><th>Name</th><th>Status</th><th>Entries</th><th>Last success</th></tr></thead><tbody id="integrations"></tbody></table></div>
    </section>
    <section class="table-section">
      <div class="section-heading"><h2>Recent security events</h2></div>
      <div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Actor</th><th>Detail</th></tr></thead><tbody id="audit"></tbody></table></div>
    </section>
  </main>
  <script src="/assets/app.js" defer></script>
</body>
</html>`

const appCSS = `:root{color-scheme:light;--ink:#17201d;--muted:#66716d;--line:#d8dfdc;--surface:#fff;--canvas:#f3f6f4;--green:#16754a;--red:#b42318;--amber:#9a6700;--focus:#1769aa}*{box-sizing:border-box}body{margin:0;background:var(--canvas);color:var(--ink);font:14px/1.45 system-ui,sans-serif;letter-spacing:0}.topbar{height:64px;padding:0 max(20px,calc((100% - 1180px)/2));display:flex;align-items:center;justify-content:space-between;background:#202a27;color:#fff;border-bottom:3px solid #43a66f}.brand,.toolbar,.section-heading{display:flex;align-items:center}.brand{gap:11px}.brand-mark{width:12px;height:20px;background:#43a66f;border-radius:2px}.brand h1{font-size:17px;margin:0;font-weight:650}.toolbar{gap:14px;color:#c9d2cf;font-size:12px}.toolbar button{border:1px solid #65716d;background:transparent;color:#fff;padding:7px 12px;border-radius:4px;cursor:pointer}.toolbar button:hover{background:#33403c}.toolbar button:focus-visible{outline:3px solid #79bde8;outline-offset:2px}main{max-width:1180px;margin:0 auto;padding:24px 20px 48px}.overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metric{min-height:92px;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:15px 16px;display:flex;flex-direction:column;justify-content:space-between}.metric span{color:var(--muted);font-size:12px}.metric strong{font-size:20px;font-weight:650;overflow-wrap:anywhere}.status-dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--amber);margin-right:8px}.status-dot.ok{background:var(--green)}.status-dot.bad{background:var(--red)}.details{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:34px}.detail-group,.table-section{border-top:2px solid var(--ink);padding-top:12px}.section-heading{min-height:32px;justify-content:space-between;gap:16px}.section-heading h2{font-size:15px;margin:0;font-weight:700}.section-heading>span{color:var(--muted);font-size:12px}.tag{border:1px solid var(--line);border-radius:3px;padding:2px 7px;text-transform:uppercase;font-size:10px!important;font-weight:700}.tag.ok{color:var(--green);border-color:#95ceb1;background:#edf8f2}.tag.bad{color:var(--red);border-color:#e5a8a3;background:#fff3f2}dl{margin:8px 0 0}dl div{display:grid;grid-template-columns:minmax(130px,1fr) minmax(0,1.4fr);gap:16px;padding:9px 0;border-bottom:1px solid var(--line)}dt{color:var(--muted)}dd{margin:0;text-align:right;overflow-wrap:anywhere}.mono{font:12px ui-monospace,monospace}.table-section{margin-top:36px}.table-wrap{overflow-x:auto;margin-top:8px}table{width:100%;border-collapse:collapse;background:var(--surface)}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:11px;text-transform:uppercase;font-weight:650;background:#e9eeeb}td{font-size:13px;overflow-wrap:anywhere}.empty{color:var(--muted);font-style:italic}.status-text-ok{color:var(--green);font-weight:650}.status-text-bad{color:var(--red);font-weight:650}@media(max-width:760px){.topbar{height:auto;min-height:64px;padding:12px 16px;align-items:flex-start}.toolbar{flex-direction:column;align-items:flex-end;gap:6px}.overview{grid-template-columns:1fr 1fr}.details{grid-template-columns:1fr;gap:28px}.metric{min-height:84px}.metric strong{font-size:17px}main{padding:18px 14px 36px}}@media(max-width:430px){.overview{grid-template-columns:1fr}.toolbar span{display:none}dl div{grid-template-columns:1fr;gap:3px}dd{text-align:left}}`

const appJS = `const el=id=>document.getElementById(id);const set=(id,value,fallback='-')=>{el(id).textContent=value===undefined||value===null||value===''?fallback:String(value)};const when=value=>{if(!value)return 'Never';const d=new Date(value);return Number.isNaN(d.valueOf())?'Unknown':d.toLocaleString()};function row(values,empty=false){const tr=document.createElement('tr');values.forEach(value=>{const td=document.createElement('td');td.textContent=String(value);if(empty)td.className='empty';tr.appendChild(td)});return tr}function fill(id,rows,columns,label){const body=el(id);body.replaceChildren();if(!rows.length){const tr=row([label],true);tr.firstChild.colSpan=columns;body.appendChild(tr);return}rows.forEach(values=>body.appendChild(row(values)))}function badge(id,ok,good,bad){const node=el(id);node.textContent=ok?good:bad;node.className='tag '+(ok?'ok':'bad')}function render(data){const hasPrimary=Object.prototype.hasOwnProperty.call(data,'policy_hash');const hasChecksum=Object.prototype.hasOwnProperty.call(data,'policy_checksum');const primaryHash=data.policy_hash;const checksum=data.policy_checksum;const primaryValid=hasPrimary&&typeof primaryHash==='string'&&/^[0-9a-f]{64}$/.test(primaryHash);const checksumValid=hasChecksum&&typeof checksum==='string'&&/^[0-9a-f]{64}$/.test(checksum);const hashValid=primaryValid&&checksumValid&&primaryHash===checksum;const policyHash=primaryHash;const contract=data.schema==='nftfw.status.v2'&&data.active===true&&data.policy_match===true&&data.kill_switch_enforced===true&&hashValid&&data.protected===true;const healthy=data.status==='HEALTHY'&&contract;const overall=el('overall');overall.lastChild.textContent=healthy?'Healthy':'Degraded';overall.querySelector('.status-dot').className='status-dot '+(healthy?'ok':'bad');set('generation',data.active_generation||'None');set('killswitch',data.kill_switch_enforced===true?'Enforced':'Degraded');set('blocked',data.blocked_addresses,0);set('ipv6',data.ipv6_mode);set('checksum',hashValid?policyHash.slice(0,16)+'...':'Invalid');set('policy-count',String(data.zone_count||0)+' / '+String(data.policy_count||0));set('database',data.database);set('pending',data.pending_generation?String(data.pending_generation)+(data.pending_deadline?' until '+when(data.pending_deadline):''):'None');badge('drift',data.policy_match===true,'In sync','Drift');const wg=data.wireguard||{};badge('wg-health',wg.healthy===true,'Healthy','Degraded');set('wg-interface',wg.interface);set('wg-peers',wg.peer_count,0);set('wg-endpoints',wg.endpoint_count,0);set('wg-handshake',wg.latest_handshake?when(wg.latest_handshake)+' ('+String(wg.age_seconds||0)+'s ago)':'Never');set('reason',data.reason||wg.reason||'None');const claims=Object.entries(data.claims_by_source||{}).sort((a,b)=>a[0].localeCompare(b[0])).map(item=>[item[0],item[1]]);set('claim-total',String(data.block_claims||0)+' active block claims');fill('claims',claims,2,'No active claims');const integrations=(data.integrations||[]).map(item=>[item.name,item.status,item.entry_count,when(item.last_success)]);fill('integrations',integrations,4,'No integrations enabled');const audit=(data.recent_audit||[]).map(item=>[when(item.created_at),item.event,item.actor,item.detail]);fill('audit',audit,4,'No audit events');set('updated','Updated '+new Date().toLocaleTimeString())}async function refresh(){const button=el('refresh');button.disabled=true;try{const response=await fetch('/api/status',{cache:'no-store',headers:{Accept:'application/json'}});if(!response.ok)throw new Error('status unavailable');render(await response.json())}catch(error){const overall=el('overall');overall.lastChild.textContent='Unavailable';overall.querySelector('.status-dot').className='status-dot bad';set('reason','Status service unavailable')}finally{button.disabled=false}}el('refresh').addEventListener('click',refresh);refresh();setInterval(refresh,5000);`

func main() {
	if err := candidateStartupGuard(); err != nil {
		fmt.Fprintln(os.Stderr, "nftfw-web:", err)
		os.Exit(1)
	}
	bind := os.Getenv("NFTFW_WEB_BIND")
	if bind == "" {
		bind = "127.0.0.1:8787"
	}
	sock := os.Getenv("NFTFW_STATUS_SOCKET")
	if sock == "" {
		sock = "/run/nftfw/status.sock"
	}
	srv := &http.Server{
		Addr: bind, Handler: newHandler(sock), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "nftfw-web:", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintln(os.Stderr, "nftfw-web shutdown:", err)
		}
	}
}

func candidateStartupGuard() error {
	info := version.Current()
	if info.Version == "" || info.Commit == "" || info.Date == "" || info.BuildDisposition == "" {
		return errors.New("build identity is incomplete; refusing startup")
	}
	if version.IsStageRCandidateOnly() {
		return errors.New("stage R candidate-only build is quarantined and cannot start")
	}
	return nil
}

func newHandler(statusSocket string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			writeHTTPError(w, http.StatusNotFound, "not found")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeHTTPError(w, http.StatusMethodNotAllowed, "read-only")
			return
		}
		secureHeaders(w, "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(pageHTML))
		}
	})
	mux.HandleFunc("/assets/app.css", staticAsset("text/css; charset=utf-8", appCSS))
	mux.HandleFunc("/assets/app.js", staticAsset("text/javascript; charset=utf-8", appJS))
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeHTTPError(w, http.StatusMethodNotAllowed, "read-only")
			return
		}
		response, err := api.Call(r.Context(), statusSocket, api.Request{Op: "status"})
		if err != nil {
			writeHTTPError(w, http.StatusServiceUnavailable, "status unavailable")
			return
		}
		fields, ok := response.Data.(map[string]any)
		if !ok {
			writeHTTPError(w, http.StatusServiceUnavailable, "status unavailable")
			return
		}
		payload := make(map[string]any, len(fields)+1)
		for key, value := range fields {
			payload[key] = value
		}
		payload["protected"] = dashboardProtected(fields)
		secureHeaders(w, "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(payload)
	})
	return mux
}

func dashboardProtected(data map[string]any) bool {
	if data["schema"] != "nftfw.status.v2" || data["status"] != "HEALTHY" ||
		data["active"] != true || data["policy_match"] != true || data["kill_switch_enforced"] != true {
		return false
	}
	primary, hasPrimary := data["policy_hash"]
	checksum, hasChecksum := data["policy_checksum"]
	if !hasPrimary || !hasChecksum {
		return false
	}
	primaryText, primaryOK := primary.(string)
	checksumText, checksumOK := checksum.(string)
	if hasPrimary && (!primaryOK || !validSHA256(primaryText)) {
		return false
	}
	if hasChecksum && (!checksumOK || !validSHA256(checksumText)) {
		return false
	}
	return primaryText == checksumText
}

func validSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func staticAsset(contentType, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeHTTPError(w, http.StatusMethodNotAllowed, "read-only")
			return
		}
		secureHeaders(w, contentType)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(body))
		}
	}
}

func writeHTTPError(w http.ResponseWriter, status int, message string) {
	secureHeaders(w, "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(message + "\n"))
}

func secureHeaders(w http.ResponseWriter, contentType string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}
