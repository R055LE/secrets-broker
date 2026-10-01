package adminweb

import (
	"bytes"
	"html/template"
	"net/http"
)

const pageCSS = `body{font:1rem/1.5 system-ui,sans-serif;max-width:60rem;margin:auto;padding:1rem;color:#17202a;background:#f5f7f9}a{color:#174a8b}header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:1rem}section{background:white;border:1px solid #d5dce4;border-radius:.5rem;padding:1rem;margin:1rem 0}button{font:inherit;min-height:44px;padding:.5rem 1rem;background:#174a8b;color:white;border:0;border-radius:.3rem;cursor:pointer}table{border-collapse:collapse;width:100%;text-align:left}td,th{padding:.5rem;border-bottom:1px solid #d5dce4}code{overflow-wrap:anywhere;white-space:pre-wrap}dt{font-weight:600;margin-top:.7rem}dd{margin:0;overflow-wrap:anywhere}.notice{padding:1rem;border-left:4px solid #207448;background:#eaf6ef}.warning{border-color:#9f5a14;background:#fff4e7}.scroll{overflow:auto}.muted{color:#526171}form{margin:.7rem 0}ol{padding-left:1.5rem}`

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secrets Broker</title><link rel="stylesheet" href="/style.css"></head>
<body><header><a href="/">Secrets Broker</a><span class="muted">{{.Login}}</span>{{if .ApprovalURL}}<a href="{{.ApprovalURL}}">Execution approvals</a>{{end}}</header>
{{if .Message}}<p class="notice {{if .Warning}}warning{{end}}" role="status">{{.Message}}</p>{{end}}
{{if .Detail}}
<h1>{{.Detail.Alias}}</h1>
<section><h2>Project policy</h2><dl>
<dt>Bitwarden project ID</dt><dd><code>{{.Detail.BWSProjectID}}</code></dd>
<dt>Token entry identifier</dt><dd><code>{{.Detail.TokenEntry}}</code></dd>
<dt>Working directory</dt><dd><code>{{.Detail.WorkingDir}}</code></dd>
<dt>Approval mode</dt><dd>{{.Detail.Mode}}: {{.Detail.Behavior}}</dd></dl></section>
<section><h2>Exact allowed arguments</h2><p>Each numbered line preserves one exact argument.</p>
{{range .Detail.Allow}}<ol>{{range .}}<li><code>{{.}}</code></li>{{end}}</ol>{{else}}<p>No commands are allowed.</p>{{end}}</section>
<section><h2>Readiness checks</h2><p>Checks run when you press a button. Page loads do not contact Bitwarden.</p>
<form method="post" action="/projects/path"><input type="hidden" name="csrf" value="{{.PathToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}"><button>Check working directory</button></form>
<form method="post" action="/projects/access"><input type="hidden" name="csrf" value="{{.AccessToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}"><button>Check Bitwarden access</button></form>
{{if .Path}}<dl><dt>Path resolution</dt><dd>{{.Path.Resolution}}</dd><dt>Resolved directory</dt><dd><code>{{.Path.ResolvedPath}}</code></dd><dt>Worker can enter</dt><dd>{{.Path.WorkerCanEnter}}</dd><dt>Runner can enter</dt><dd>{{.Path.RunnerCanEnter}}</dd><dt>Runner can write</dt><dd>{{.Path.RunnerCanWrite}}</dd></dl>
{{if not .Path.Ready}}<p>Review the configured path and permissions for the worker and runner. Use the root CLI path check on the broker host for further diagnosis.</p>{{end}}{{end}}
{{if .Access}}{{range .Access.Projects}}<p>Grant status: <strong>{{.Status}}</strong></p>{{end}}{{end}}</section>
{{else}}
<h1>Projects</h1><section><h2>Local broker policy</h2><div class="scroll"><table><thead><tr><th>Alias</th><th>Approval</th><th>Behavior</th></tr></thead><tbody>
{{range .Projects}}<tr><td><a href="/projects/{{.Index}}">{{.Alias}}</a></td><td>{{.Mode}}</td><td>{{.Behavior}}</td></tr>{{else}}<tr><td colspan="3">No local projects.</td></tr>{{end}}</tbody></table></div></section>
<section><h2>Bitwarden projects</h2><p>Refresh to see project names and IDs available to the worker. This check is recorded in the administrator audit.</p>
<form method="post" action="/projects/discover"><input type="hidden" name="csrf" value="{{.DiscoveryToken}}"><button>Refresh Bitwarden projects</button></form>
{{if .Available}}<div class="scroll"><table><thead><tr><th>Name</th><th>Project ID</th></tr></thead><tbody>{{range .Available}}<tr><td>{{.Name}}</td><td><code>{{.ID}}</code></td></tr>{{end}}</tbody></table></div>{{else}}<p>No current discovery list. Refresh it to check the worker's visible projects.</p>{{end}}</section>
{{end}}
</body></html>`))

func renderPage(w http.ResponseWriter, status int, data pageData) {
	var body bytes.Buffer
	if err := pageTemplate.Execute(&body, data); err != nil {
		http.Error(w, "Page could not be rendered.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}
