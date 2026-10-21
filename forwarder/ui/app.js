"use strict";

const TOKEN_KEY = "zandu-admin-token";
const state = { token: "", config: null, presets: [], tab: "clients", editing: null, auditTimer: null };

// ---------- helpers ----------

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function token() {
  if (!state.token) {
    try { state.token = sessionStorage.getItem(TOKEN_KEY) || ""; } catch {}
  }
  return state.token;
}

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { "Authorization": "Bearer " + token(), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) { signOut(); throw new Error("Session expired"); }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error((data && data.message) || res.statusText);
  return data;
}

let toastTimer;
function toast(msg, isError) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "show" + (isError ? " error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), 3500);
}

async function run(fn, okMsg) {
  try {
    const r = await fn();
    if (okMsg) toast(okMsg);
    return r;
  } catch (e) {
    toast(e.message, true);
    throw e;
  }
}

const lines = (s) => s.split("\n").map((l) => l.trim()).filter(Boolean);
const csv = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);

function parsePairs(text, sep) {
  const out = {};
  for (const l of lines(text)) {
    const i = l.indexOf(sep);
    if (i <= 0) throw new Error(`Expected "name${sep}value": ${l}`);
    out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
  }
  return out;
}

const formatPairs = (m, sep) => Object.entries(m || {}).map(([k, v]) => `${k}${sep}${v}`).join("\n");

function parseParams(text) {
  const out = {};
  for (const l of lines(text)) {
    const i = l.indexOf("=");
    if (i <= 0) throw new Error(`Expected "name=value1,value2": ${l}`);
    out[l.slice(0, i).trim()] = csv(l.slice(i + 1));
  }
  return out;
}

const formatParams = (m) => Object.entries(m || {}).map(([k, v]) => `${k}=${v.join(",")}`).join("\n");

// ---------- shell ----------

function signOut() {
  state.token = "";
  try { sessionStorage.removeItem(TOKEN_KEY); } catch {}
  clearInterval(state.auditTimer);
  document.getElementById("tabs").hidden = true;
  document.getElementById("logout").hidden = true;
  document.getElementById("view").replaceChildren();
  document.getElementById("login").hidden = false;
}

async function signIn() {
  document.getElementById("login").hidden = true;
  document.getElementById("tabs").hidden = false;
  document.getElementById("logout").hidden = false;
  await reload();
  state.presets = await api("GET", "/api/presets");
  render();
}

async function reload() {
  state.config = await api("GET", "/api/config");
}

function setTab(tab) {
  state.tab = tab;
  state.editing = null;
  render();
}

function render() {
  clearInterval(state.auditTimer);
  for (const b of document.querySelectorAll("#tabs button")) b.classList.toggle("active", b.dataset.tab === state.tab);
  const view = { clients: clientsView, policies: policiesView, upstreams: upstreamsView, test: testView, audit: auditView }[state.tab];
  document.getElementById("view").replaceChildren(view());
}

function listPanel(title, addLabel, onAdd, items, renderItem, extra) {
  return h("section", { class: "panel" },
    h("div", { class: "toolbar" }, h("h1", {}, title), h("div", { class: "row" }, extra, h("button", { onclick: onAdd }, addLabel))),
    items.length ? items.map(renderItem) : h("p", { class: "muted" }, "Nothing here yet."));
}

// ---------- upstreams ----------

function upstreamsView() {
  const c = state.config;
  const presets = state.presets.map((p) => h("button", {
    class: "ghost",
    title: p.description,
    onclick: async () => {
      const r = await run(() => api("POST", "/api/presets/" + p.id));
      await reload();
      toast(r.added && r.added.length ? "Added " + r.added.join(", ") : "Already present");
      render();
    },
  }, "+ " + p.title));
  return h("div", {},
    state.editing && state.editing.kind === "upstream" ? upstreamForm(state.editing.value) : null,
    listPanel("Upstreams", "New upstream", () => { state.editing = { kind: "upstream", value: null }; render(); }, c.upstreams, (u) =>
      h("div", { class: "item" },
        h("div", { class: "item-head" },
          h("div", {}, h("h2", {}, u.name), h("span", { class: "muted mono" }, u.base_url)),
          h("div", { class: "row" },
            h("button", { class: "ghost", onclick: () => { state.editing = { kind: "upstream", value: u }; render(); } }, "Edit"),
            h("button", { class: "danger", onclick: () => removeObj("upstreams", u.name) }, "Delete"))),
        u.description ? h("div", { class: "muted" }, u.description) : null,
        h("div", { class: "chips" },
          Object.keys(u.inject?.query || {}).map((k) => h("span", { class: "chip" }, "query: " + k)),
          Object.keys(u.inject?.headers || {}).map((k) => h("span", { class: "chip" }, "header: " + k)))),
      presets));
}

function upstreamForm(u) {
  const isNew = !u;
  u = u || { name: "", description: "", base_url: "https://", inject: {}, timeout_seconds: 0 };
  const f = h("form", { class: "panel" },
    h("h1", {}, isNew ? "New upstream" : "Edit " + u.name),
    h("div", { class: "grid" },
      h("label", {}, "Name", h("input", { name: "name", value: u.name, required: true, disabled: !isNew, pattern: "[a-z0-9][a-z0-9_-]*" })),
      h("label", {}, "Base URL", h("input", { name: "base_url", value: u.base_url, required: true })),
      h("label", {}, "Timeout (seconds)", h("input", { name: "timeout", type: "number", min: 0, value: u.timeout_seconds || "" }))),
    h("label", {}, "Description", h("input", { name: "description", value: u.description || "" })),
    h("p", { class: "muted" }, "Injected credentials replace any client-supplied values. Use env:NAME or file:/path to keep secrets out of the config file."),
    h("div", { class: "grid" },
      h("label", {}, "Query parameters (name=value per line)", h("textarea", { name: "query" }, formatPairs(u.inject?.query, "="))),
      h("label", {}, "Headers (Name: value per line)", h("textarea", { name: "headers" }, formatPairs(u.inject?.headers, ": ")))),
    h("div", { class: "row" }, h("button", { type: "submit" }, "Save"), h("button", { type: "button", class: "ghost", onclick: () => { state.editing = null; render(); } }, "Cancel")));
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = new FormData(f);
    const name = isNew ? d.get("name") : u.name;
    await run(async () => {
      const body = {
        description: d.get("description"),
        base_url: d.get("base_url"),
        timeout_seconds: Number(d.get("timeout")) || 0,
        inject: { query: parsePairs(d.get("query"), "="), headers: parsePairs(d.get("headers"), ":") },
      };
      await api("PUT", "/api/upstreams/" + encodeURIComponent(name), body);
      await reload();
    }, "Saved");
    state.editing = null;
    render();
  });
  return f;
}

// ---------- policies ----------

function policiesView() {
  const c = state.config;
  return h("div", {},
    state.editing && state.editing.kind === "policy" ? policyForm(state.editing.value) : null,
    listPanel("Policies", "New policy", () => { state.editing = { kind: "policy", value: null }; render(); }, c.policies, (p) =>
      h("div", { class: "item" },
        h("div", { class: "item-head" },
          h("div", {}, h("h2", {}, p.name), h("span", { class: "muted" }, " → " + p.upstream)),
          h("div", { class: "row" },
            h("button", { class: "ghost", onclick: () => { state.editing = { kind: "policy", value: p }; render(); } }, "Edit"),
            h("button", { class: "danger", onclick: () => removeObj("policies", p.name) }, "Delete"))),
        p.description ? h("div", { class: "muted" }, p.description) : null,
        p.rules.map((r) => h("div", { class: "chips" },
          h("span", { class: "chip " + r.effect }, r.effect),
          h("span", { class: "chip" }, (r.methods && r.methods.length ? r.methods.join(",") : "any method")),
          h("span", { class: "chip" }, r.path || "any path"),
          Object.entries(r.params || {}).map(([k, v]) => h("span", { class: "chip mono", title: v.join(", ") }, `${k} ∈ {${v.length > 4 ? v.slice(0, 4).join(", ") + ", …" : v.join(", ")}}`)))))));
}

function ruleEditor(r) {
  r = r || { effect: "allow", methods: [], path: "", params: {} };
  const el = h("div", { class: "rule" },
    h("div", { class: "grid" },
      h("label", {}, "Effect", h("select", { "data-f": "effect" },
        h("option", { value: "allow" }, "allow"), h("option", { value: "deny" }, "deny"))),
      h("label", {}, "Methods (comma-separated, empty = any)", h("input", { "data-f": "methods", value: (r.methods || []).join(", ") })),
      h("label", {}, "Path glob (empty = any)", h("input", { "data-f": "path", value: r.path || "", placeholder: "/api3.*" }))),
    h("label", {}, "Parameters (name=value1,value2 per line; * and ? are wildcards)", h("textarea", { "data-f": "params" }, formatParams(r.params))),
    h("div", { class: "row" },
      h("label", { style: "flex:1" }, "Description", h("input", { "data-f": "description", value: r.description || "" })),
      h("button", { type: "button", class: "danger", onclick: () => el.remove() }, "Remove rule")));
  el.querySelector('[data-f="effect"]').value = r.effect;
  return el;
}

function readRule(el) {
  const v = (f) => el.querySelector(`[data-f="${f}"]`).value;
  const rule = { effect: v("effect"), methods: csv(v("methods")).map((m) => m.toUpperCase()), path: v("path").trim(), params: parseParams(v("params")) };
  if (v("description").trim()) rule.description = v("description").trim();
  return rule;
}

function policyForm(p) {
  const isNew = !p;
  p = p || { name: "", description: "", upstream: state.config.upstreams[0]?.name || "", rules: [] };
  const rules = h("div", {}, (p.rules.length ? p.rules : [null]).map(ruleEditor));
  const upstream = h("select", { name: "upstream", required: true }, state.config.upstreams.map((u) => h("option", { value: u.name }, u.name)));
  upstream.value = p.upstream;
  const f = h("form", { class: "panel" },
    h("h1", {}, isNew ? "New policy" : "Edit " + p.name),
    h("div", { class: "grid" },
      h("label", {}, "Name", h("input", { name: "name", value: p.name, required: true, disabled: !isNew, pattern: "[a-z0-9][a-z0-9_-]*" })),
      h("label", {}, "Upstream", upstream)),
    h("label", {}, "Description", h("input", { name: "description", value: p.description || "" })),
    h("p", { class: "muted" }, "Requests are denied unless a rule allows them; a matching deny rule always wins. Matching is case-insensitive."),
    rules,
    h("div", { class: "row" },
      h("button", { type: "button", class: "ghost", onclick: () => rules.append(ruleEditor()) }, "+ Add rule"),
      h("button", { type: "submit" }, "Save"),
      h("button", { type: "button", class: "ghost", onclick: () => { state.editing = null; render(); } }, "Cancel")));
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = new FormData(f);
    const name = isNew ? d.get("name") : p.name;
    await run(async () => {
      const body = { description: d.get("description"), upstream: d.get("upstream"), rules: [...rules.children].map(readRule) };
      await api("PUT", "/api/policies/" + encodeURIComponent(name), body);
      await reload();
    }, "Saved");
    state.editing = null;
    render();
  });
  return f;
}

// ---------- clients ----------

function clientsView() {
  const c = state.config;
  return h("div", {},
    state.editing && state.editing.kind === "token" ? tokenPanel(state.editing.value) : null,
    state.editing && state.editing.kind === "client" ? clientForm(state.editing.value) : null,
    listPanel("Clients", "New client", () => { state.editing = { kind: "client", value: null }; render(); }, c.clients, (cl) =>
      h("div", { class: "item" },
        h("div", { class: "item-head" },
          h("div", {}, h("h2", {}, cl.name), cl.disabled ? h("span", { class: "chip deny" }, "disabled") : null),
          h("div", { class: "row" },
            h("button", { class: "ghost", onclick: () => { state.editing = { kind: "client", value: cl }; render(); } }, "Edit"),
            h("button", { class: "ghost", onclick: () => rotate(cl.name) }, cl.has_token ? "Rotate token" : "Issue token"),
            h("button", { class: "danger", onclick: () => removeObj("clients", cl.name) }, "Delete"))),
        cl.description ? h("div", { class: "muted" }, cl.description) : null,
        h("div", { class: "chips" },
          cl.policies.map((p) => h("span", { class: "chip" }, p)),
          (cl.allowed_ips || []).map((ip) => h("span", { class: "chip mono" }, ip))))));
}

function tokenPanel({ name, token }) {
  return h("section", { class: "panel" },
    h("h1", {}, "Token for " + name),
    h("p", {}, "Copy this token now. It is stored only as a hash and cannot be shown again."),
    h("div", { class: "secret mono" }, token),
    h("div", { class: "row" },
      h("button", { onclick: () => navigator.clipboard.writeText(token).then(() => toast("Copied")) }, "Copy"),
      h("button", { class: "ghost", onclick: () => { state.editing = null; render(); } }, "Done")),
    h("p", { class: "muted" }, "Send it as ", h("code", {}, "Authorization: Bearer <token>"), " or ", h("code", {}, "X-Zandu-Token: <token>"), "."));
}

async function rotate(name) {
  if (!confirm(`Issue a new token for ${name}? The current token stops working immediately.`)) return;
  const r = await run(() => api("POST", `/api/clients/${encodeURIComponent(name)}/token`));
  await reload();
  state.editing = { kind: "token", value: { name, token: r.token } };
  render();
}

function clientForm(cl) {
  const isNew = !cl;
  cl = cl || { name: "", description: "", policies: [], allowed_ips: [], disabled: false };
  const f = h("form", { class: "panel" },
    h("h1", {}, isNew ? "New client" : "Edit " + cl.name),
    h("div", { class: "grid" },
      h("label", {}, "Name", h("input", { name: "name", value: cl.name, required: true, disabled: !isNew, pattern: "[a-z0-9][a-z0-9_-]*" })),
      h("label", {}, "Allowed source IPs / CIDRs (comma-separated, empty = any)", h("input", { name: "ips", value: (cl.allowed_ips || []).join(", ") }))),
    h("label", {}, "Description", h("input", { name: "description", value: cl.description || "" })),
    h("fieldset", { class: "panel" }, h("legend", { class: "muted" }, "Policies"),
      state.config.policies.length ? state.config.policies.map((p) =>
        h("label", { class: "inline" }, h("input", { type: "checkbox", name: "policy", value: p.name, checked: cl.policies.includes(p.name) }), p.name, h("span", { class: "muted" }, " → " + p.upstream)))
        : h("p", { class: "muted" }, "Create a policy first.")),
    h("label", { class: "inline" }, h("input", { type: "checkbox", name: "disabled", checked: cl.disabled }), "Disabled"),
    h("div", { class: "row" }, h("button", { type: "submit" }, "Save"), h("button", { type: "button", class: "ghost", onclick: () => { state.editing = null; render(); } }, "Cancel")));
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = new FormData(f);
    const name = isNew ? d.get("name") : cl.name;
    const r = await run(async () => {
      const body = { description: d.get("description"), policies: d.getAll("policy"), allowed_ips: csv(d.get("ips")), disabled: d.get("disabled") === "" || d.get("disabled") === "on" };
      const res = await api("PUT", "/api/clients/" + encodeURIComponent(name), body);
      await reload();
      return res;
    }, "Saved");
    state.editing = r && r.token ? { kind: "token", value: { name, token: r.token } } : null;
    render();
  });
  return f;
}

async function removeObj(kind, name) {
  if (!confirm(`Delete ${name}?`)) return;
  await run(async () => {
    await api("DELETE", `/api/${kind}/${encodeURIComponent(name)}`);
    await reload();
  }, "Deleted");
  render();
}

// ---------- test ----------

function testView() {
  const c = state.config;
  const result = h("div");
  const f = h("form", { class: "panel" },
    h("h1", {}, "Test a request"),
    h("p", { class: "muted" }, "Evaluates a request against a client's policies without forwarding it."),
    h("div", { class: "grid" },
      h("label", {}, "Client", h("select", { name: "client", required: true }, c.clients.map((cl) => h("option", { value: cl.name }, cl.name)))),
      h("label", {}, "Method", h("select", { name: "method" }, ["GET", "POST", "PUT", "PATCH", "DELETE"].map((m) => h("option", { value: m }, m))))),
    h("label", {}, "Path and query, as sent to the forwarder",
      h("input", { name: "url", class: "mono", required: true, value: c.upstreams[0] ? `/${c.upstreams[0].name}/` : "/", placeholder: "/dynadot/api3.json?command=get_dns&domain=example.com" })),
    h("label", {}, "Form body (optional, application/x-www-form-urlencoded)", h("input", { name: "body", class: "mono" })),
    h("div", { class: "row" }, h("button", { type: "submit" }, "Evaluate")),
    result);
  f.addEventListener("submit", async (e) => {
    e.preventDefault();
    const d = new FormData(f);
    const r = await run(() => api("POST", "/api/evaluate", { client: d.get("client"), method: d.get("method"), url: d.get("url"), body: d.get("body") }));
    const ok = r.decision.allowed;
    result.replaceChildren(h("div", { class: "result " + (ok ? "allow" : "deny") },
      h("strong", {}, ok ? "Allowed" : "Denied"), " — ", r.decision.reason,
      h("pre", {}, `upstream: ${r.upstream}\npath:     ${r.path}\nparams:   ${JSON.stringify(r.params)}`)));
  });
  return f;
}

// ---------- audit ----------

function auditView() {
  const body = h("tbody");
  const auto = h("input", { type: "checkbox", checked: true });
  const load = async () => {
    const rows = await api("GET", "/api/audit?limit=200").catch((e) => { toast(e.message, true); return []; });
    body.replaceChildren(...(rows.length ? rows.map((e) => h("tr", {},
      h("td", { class: "mono" }, new Date(e.time).toLocaleString()),
      h("td", {}, e.client || "—"),
      h("td", { class: "mono" }, `${e.method} /${e.upstream || ""}${e.path}`, e.query ? h("div", { class: "muted" }, "?" + e.query) : null),
      h("td", {}, h("span", { class: "chip " + (e.allowed ? "allow" : "deny") }, e.status), h("div", { class: "muted" }, e.reason)),
      h("td", { class: "mono" }, e.remote_ip),
      h("td", { class: "mono" }, e.duration_ms + " ms")))
      : [h("tr", {}, h("td", { colspan: 6, class: "muted" }, "No requests yet."))]));
  };
  load();
  state.auditTimer = setInterval(() => auto.checked && load(), 5000);
  return h("section", { class: "panel" },
    h("div", { class: "toolbar" }, h("h1", {}, "Recent requests"),
      h("div", { class: "row" }, h("label", { class: "inline" }, auto, "Auto-refresh"), h("button", { class: "ghost", onclick: load }, "Refresh"))),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Time", "Client", "Request", "Result", "Source", "Duration"].map((t) => h("th", {}, t)))),
      body)));
}

// ---------- boot ----------

document.getElementById("tabs").addEventListener("click", (e) => {
  if (e.target.dataset.tab) setTab(e.target.dataset.tab);
});
document.getElementById("logout").addEventListener("click", signOut);
document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const t = new FormData(e.target).get("token");
  const errEl = document.getElementById("login-error");
  const res = await fetch("/api/config", { headers: { Authorization: "Bearer " + t } });
  if (!res.ok) { errEl.textContent = "Invalid token."; return; }
  state.token = t;
  try { sessionStorage.setItem(TOKEN_KEY, t); } catch {}
  errEl.textContent = "";
  e.target.reset();
  signIn().catch((err) => toast(err.message, true));
});

if (token()) signIn().catch(() => signOut());
else signOut();
