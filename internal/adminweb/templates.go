package adminweb

import (
	"bytes"
	"html/template"
	"net/http"
)

const pageCSS = `body{font:1rem/1.5 system-ui,sans-serif;max-width:60rem;margin:auto;padding:1rem;color:#17202a;background:#f5f7f9}a{color:#174a8b}header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:1rem}section{background:white;border:1px solid #d5dce4;border-radius:.5rem;padding:1rem;margin:1rem 0}button{font:inherit;min-height:44px;padding:.5rem 1rem;background:#174a8b;color:white;border:0;border-radius:.3rem;cursor:pointer}table{border-collapse:collapse;width:100%;text-align:left}td,th{padding:.5rem;border-bottom:1px solid #d5dce4}code{overflow-wrap:anywhere;white-space:pre-wrap}dt{font-weight:600;margin-top:.7rem}dd{margin:0;overflow-wrap:anywhere}.notice{padding:1rem;border-left:4px solid #207448;background:#eaf6ef}.warning{border-color:#9f5a14;background:#fff4e7}.scroll{overflow:auto}.muted{color:#526171}form{margin:.7rem 0}ol{padding-left:1.5rem}input:not([type=hidden]):not([type=checkbox]),select{font:inherit;box-sizing:border-box;min-height:44px;width:100%;padding:.5rem;margin:.3rem 0 1rem}label{display:block}li{margin:.5rem 0}.secondary{background:#526171}input[type=checkbox]{width:1.3rem;height:1.3rem;vertical-align:middle}`

const pageJS = `"use strict";
const list = document.getElementById("arguments");
const add = document.getElementById("add-argument");
if (list && add) {
  add.hidden = false;
  add.addEventListener("click", () => {
    if (list.children.length >= 256) return;
    const item = document.createElement("li");
    const input = document.createElement("input");
    input.name = "argv"; input.type = "text"; input.maxLength = 4096;
    input.setAttribute("aria-label", "Argument");
    const remove = document.createElement("button");
    remove.type = "button"; remove.className = "secondary"; remove.textContent = "Remove argument";
    remove.addEventListener("click", () => item.remove());
    item.append(input, remove); list.append(item); input.focus();
  });
}`

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Secrets Broker</title><link rel="stylesheet" href="/style.css"><script src="/forms.js" defer></script></head>
<body><header><a href="/">Secrets Broker</a><span class="muted">{{.Login}}</span>{{if .ApprovalURL}}<a href="{{.ApprovalURL}}">Execution approvals</a>{{end}}</header>
{{if .Message}}<p class="notice {{if .Warning}}warning{{end}}" role="status">{{.Message}}</p>{{end}}
{{if .Change}}
<h1>Review {{.Change.Kind}}</h1><p>Project: <strong>{{.Change.Alias}}</strong></p>
{{if .Current}}<section><h2>Current policy</h2><dl><dt>Bitwarden project ID</dt><dd><code>{{.Current.BWSProjectID}}</code></dd><dt>Token entry identifier</dt><dd><code>{{.Current.TokenEntry}}</code></dd><dt>Working directory</dt><dd><code>{{.Current.WorkingDir}}</code></dd><dt>Approval mode</dt><dd>{{.Current.Mode}}: {{.Current.Behavior}}</dd></dl>
{{range .Current.Allow}}<ol>{{range .}}<li><code>{{.}}</code>{{if eq . ""}}<span class="muted">empty argument</span>{{end}}</li>{{end}}</ol>{{end}}</section>{{end}}
<section><h2>Proposed change</h2>
{{if or (eq .Change.Kind "create") (eq .Change.Kind "metadata")}}<dl>
{{if .Change.ProjectName}}<dt>Bitwarden project</dt><dd>{{.Change.ProjectName}}</dd>{{end}}
<dt>Bitwarden project ID</dt><dd><code>{{.Change.Input.BWSProjectID}}</code></dd><dt>Token entry identifier</dt><dd><code>{{.Change.Input.TokenEntry}}</code></dd><dt>Working directory</dt><dd><code>{{.Change.Input.WorkingDir}}</code></dd></dl>
{{if eq .Change.Kind "create"}}<p>Starts in confirm mode with an empty allowlist. Commands remain denied until you add an exact argument list.</p>{{end}}{{end}}
{{if eq .Change.Kind "mode"}}<p>Set approval mode to <strong>{{.Change.Mode}}</strong>.</p>{{if eq .Change.Mode "automatic"}}<p class="notice warning">Allowed commands will run without a separate human approval.</p>{{else}}<p>Each allowed execution will require approval on the separate relay.</p>{{end}}{{end}}
{{if or (eq .Change.Kind "add") (eq .Change.Kind "remove")}}<p>{{.Change.Kind}} this exact argument list:</p><ol>{{range .Change.Argv}}<li><code>{{.}}</code>{{if eq . ""}}<span class="muted">empty argument</span>{{end}}</li>{{end}}</ol>{{end}}
{{if eq .Change.Kind "add"}}<p class="notice warning">Allow only an operation whose scripts, hooks, and configuration are trusted. In automatic mode it can run unattended.</p>{{end}}
{{if eq .Change.Kind "metadata"}}<p>These identifiers and the working directory determine which secrets and local files an allowed command can use.</p>{{end}}
<form method="post" action="/projects/commit"><input type="hidden" name="csrf" value="{{.CommitToken}}"><input type="hidden" name="alias" value="{{.Change.Alias}}">
{{if .Change.Widen}}<label><input type="checkbox" name="confirm" value="yes" required> I authorize this policy change.</label>{{end}}<button>Save reviewed change</button> <a href="/">Cancel</a></form></section>
{{else if .Detail}}
<h1>{{.Detail.Alias}}</h1>
<section><h2>Project policy</h2><dl>
<dt>Bitwarden project ID</dt><dd><code>{{.Detail.BWSProjectID}}</code></dd>
<dt>Token entry identifier</dt><dd><code>{{.Detail.TokenEntry}}</code></dd>
<dt>Working directory</dt><dd><code>{{.Detail.WorkingDir}}</code></dd>
<dt>Approval mode</dt><dd>{{.Detail.Mode}}: {{.Detail.Behavior}}</dd></dl></section>
<section><h2>Exact allowed arguments</h2><p>Each numbered line preserves one exact argument.</p>
{{range $index, $argv := .Detail.Allow}}<ol>{{range $argv}}<li><code>{{.}}</code>{{if eq . ""}}<span class="muted">empty argument</span>{{end}}</li>{{end}}</ol>
<form method="post" action="/projects/remove"><input type="hidden" name="csrf" value="{{$.RemoveToken}}"><input type="hidden" name="alias" value="{{$.Detail.Alias}}"><input type="hidden" name="entry" value="{{$index}}"><button class="secondary">Review removal</button></form>{{else}}<p>No commands are allowed.</p>{{end}}
<h3>Add exact arguments</h3><p>Enter one argument per field. Spaces and quotes stay inside that argument. An added blank field represents an empty argument.</p>
<form method="post" action="/projects/add"><input type="hidden" name="csrf" value="{{.AddToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}"><ol id="arguments"><li><input name="argv" type="text" aria-label="First argument" maxlength="4096" required></li></ol><button id="add-argument" type="button" class="secondary" hidden>Add argument</button> <button>Review addition</button></form></section>
<section><h2>Edit metadata</h2><form method="post" action="/projects/metadata"><input type="hidden" name="csrf" value="{{.MetadataToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}">
<label>Bitwarden project ID<input name="project_id" value="{{.Detail.BWSProjectID}}" maxlength="128" required></label><label>Token entry identifier<input name="token_entry" value="{{.Detail.TokenEntry}}" maxlength="256" required></label><label>Absolute working directory<input name="working_dir" value="{{.Detail.WorkingDir}}" maxlength="4096" required></label><button>Review metadata</button></form>
<h2>Approval mode</h2><form method="post" action="/projects/mode"><input type="hidden" name="csrf" value="{{.ModeToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}"><label>Mode<select name="mode"><option value="confirm" {{if eq .Detail.Mode "confirm"}}selected{{end}}>Confirm each allowed execution</option><option value="automatic" {{if eq .Detail.Mode "automatic"}}selected{{end}}>Run allowed commands automatically</option></select></label><button>Review approval mode</button></form></section>
<section><h2>Readiness checks</h2><p>Checks run when you press a button. Page loads do not contact Bitwarden.</p>
<form method="post" action="/projects/path"><input type="hidden" name="csrf" value="{{.PathToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}"><button>Check working directory</button></form>
<form method="post" action="/projects/access"><input type="hidden" name="csrf" value="{{.AccessToken}}"><input type="hidden" name="alias" value="{{.Detail.Alias}}"><button>Check Bitwarden access</button></form>
{{if or .PathMessage .AccessMessage}}<p class="muted">Recent results expire after ten minutes or a policy change.</p>{{end}}
{{if .PathMessage}}<p class="notice {{if .PathWarning}}warning{{end}}" role="status">{{.PathMessage}}</p>{{end}}
{{if .AccessMessage}}<p class="notice {{if .AccessWarning}}warning{{end}}" role="status">{{.AccessMessage}}</p>{{end}}
{{if .Path}}<dl><dt>Path resolution</dt><dd>{{.Path.Resolution}}</dd><dt>Resolved directory</dt><dd><code>{{.Path.ResolvedPath}}</code></dd><dt>Worker can enter</dt><dd>{{.Path.WorkerCanEnter}}</dd><dt>Runner can enter</dt><dd>{{.Path.RunnerCanEnter}}</dd><dt>Runner can write</dt><dd>{{.Path.RunnerCanWrite}}</dd></dl>
{{if not .Path.Ready}}<p>Review the configured path and permissions for the worker and runner. Use the root CLI path check on the broker host for further diagnosis.</p>{{end}}{{end}}
{{if .Access}}{{range .Access.Projects}}<p>Grant status: <strong>{{.Status}}</strong></p>{{end}}{{end}}</section>
{{else}}
<h1>Projects</h1><section><h2>Local broker policy</h2><div class="scroll"><table><thead><tr><th>Alias</th><th>Approval</th><th>Behavior</th></tr></thead><tbody>
{{range .Projects}}<tr><td><a href="/projects/{{.Index}}">{{.Alias}}</a></td><td>{{.Mode}}</td><td>{{.Behavior}}</td></tr>{{else}}<tr><td colspan="3">No local projects.</td></tr>{{end}}</tbody></table></div></section>
<section><h2>Bitwarden projects</h2><p>In Bitwarden Secrets Manager, create the project and give the worker machine account read access. Keep the worker's runtime token read-only. Refresh to see project names and IDs available to the worker. This check is recorded in the administrator audit.</p>
<form method="post" action="/projects/discover"><input type="hidden" name="csrf" value="{{.DiscoveryToken}}"><button>Refresh Bitwarden projects</button></form>
{{if .Available}}<div class="scroll"><table><thead><tr><th>Name</th><th>Project ID</th></tr></thead><tbody>{{range .Available}}<tr><td>{{.Name}}</td><td><code>{{.ID}}</code></td></tr>{{end}}</tbody></table></div>{{else}}<p>No current discovery list. Refresh it to check the worker's visible projects.</p>{{end}}</section>
{{if .CreateToken}}<section><h2>Create local project</h2><p>Select a worker-visible project. Creation adds local policy with confirm mode and no allowed commands.</p><form method="post" action="/projects/create"><input type="hidden" name="csrf" value="{{.CreateToken}}">
<label>Bitwarden project<select name="project_id" required>{{range .Available}}<option value="{{.ID}}">{{.Name}} ({{.ID}})</option>{{end}}</select></label><label>Local alias<input name="alias" maxlength="256" required></label><label>Token entry identifier<input name="token_entry" maxlength="256" required></label><p class="muted">Use the identifier of an existing worker token entry. Keep secret values in Bitwarden.</p><label>Absolute working directory<input name="working_dir" maxlength="4096" required></label><button>Review new project</button></form></section>{{end}}
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
