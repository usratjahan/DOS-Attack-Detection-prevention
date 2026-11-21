"use strict";
/* DosGuard Live - frontend. Plain JS, no libraries. Data arrives over Server-Sent Events (/events). */

const T = {
  en: {
    mode: "Protection", m_off: "No protection", m_monitor: "Detect only", m_protect: "DosGuard protect",
    h_off: "Default server: nothing defends it.", h_monitor: "DosGuard raises alerts but takes no action.", h_protect: "DosGuard detects and blocks automatically.",
    attacks: "Launch an attack", sim_only: "(simulation only)", speed: "Speed", reset: "Reset simulation",
    a_syn: "SYN flood", a_syn_d: "fake connection requests", a_http: "HTTP flood", a_http_d: "15 bots, 1500 req/s",
    a_slow: "Slowloris", a_slow_d: "300 half-open connections", a_dist: "Distributed flood", a_dist_d: "200 polite-looking bots",
    k_avail: "Real users served", k_avail_s: "last 4 seconds", k_lat: "Response time", k_lat_s: "average, successful requests",
    k_req: "Incoming requests", k_syn: "Incoming connection attempts", k_syn_s: "SYN packets per second",
    c_avail: "Real users served (%)", c_load: "Incoming traffic (per second)", lg_req: "requests/s", lg_syn: "SYN/s", lg_cap: "server capacity (400 req/s)",
    res: "Server resources", def: "Active defences", drops: "Dropped so far", feed: "Event feed", blocked: "Blocked IPs",
    r_syn: "SYN backlog (half-open connections)", r_conn: "Connection slots", r_queue: "Request queue", r_work: "Worker threads busy",
    d_cookies: "SYN cookies", d_rate: "Fair-share limit", d_header: "Header deadline", d_conn: "Max conns / IP", d_good: "Known-good IPs",
    s_ok: "SERVICE OK", s_deg: "DEGRADED", s_down: "SERVICE DOWN", s_wait: "starting…",
    noblock: "No IP is blocked right now.", secs: "s left", foot: "All attacks run inside an in-memory simulation. No real network traffic is sent.",
    cap_req: "server capacity 400/s",
    x_idle: "<b>Normal traffic.</b> About 43 real requests per second are being served. Launch an attack and watch what happens to the real users.",
    x_off: "<b>Attack in progress and nothing is protecting the server.</b> {A} Only <b>{P}%</b> of real users are being served.",
    x_mon: "<b>DosGuard can see the attack</b> (look at the event feed) <b>but it is only watching</b>, so real users are still locked out: <b>{P}%</b> served. Switch to “DosGuard protect”.",
    x_pro: "<b>DosGuard is defending.</b> {D} Real users served: <b>{P}%</b>.",
    x_pro_wait: "<b>DosGuard is analysing the attack…</b> It checks traffic once per second, so the first second still hurts.",
    A_syn: "A SYN flood sends 600 fake connection requests per second; they fill the server’s half-open queue, so real users cannot connect.",
    A_http: "An HTTP flood: 15 bots send 1500 requests/s but the server can only handle 400/s, so the queue overflows.",
    A_slow: "Slowloris: 5 attackers hold 300 half-finished connections open, using up all 250 connection slots with almost no traffic.",
    A_dist: "A distributed flood: 200 bots at only 6 req/s each (1200 req/s). Every bot looks polite, but together they overload the server.",
    D_syn: "SYN cookies make the handshake stateless, so fake SYNs now cost nothing.",
    D_http: "Bots that send far too many requests are banned for 30 s (longer if they return).",
    D_slow: "Slow connections are killed and the attacking IPs are blocked.",
    D_dist: "A fair-share rate limit caps unknown IPs while known-good visitors keep full service.",
  },
  bn: {
    mode: "সুরক্ষা", m_off: "কোনো সুরক্ষা নেই", m_monitor: "শুধু শনাক্ত", m_protect: "DosGuard সুরক্ষা",
    h_off: "ডিফল্ট সার্ভার: কিছুই একে রক্ষা করছে না।", h_monitor: "DosGuard সতর্কতা দেয়, কিন্তু কোনো ব্যবস্থা নেয় না।", h_protect: "DosGuard নিজে নিজেই শনাক্ত করে ও আটকায়।",
    attacks: "আক্রমণ চালান", sim_only: "(শুধু সিমুলেশন)", speed: "গতি", reset: "সিমুলেশন রিসেট",
    a_syn: "SYN ফ্লাড", a_syn_d: "ভুয়া কানেকশন অনুরোধ", a_http: "HTTP ফ্লাড", a_http_d: "১৫টি বট, ১৫০০ রিকোয়েস্ট/সেকেন্ড",
    a_slow: "Slowloris", a_slow_d: "৩০০টি অর্ধ-খোলা কানেকশন", a_dist: "ডিস্ট্রিবিউটেড ফ্লাড", a_dist_d: "২০০টি ভদ্র-চেহারার বট",
    k_avail: "আসল ব্যবহারকারী সেবা পাচ্ছে", k_avail_s: "গত ৪ সেকেন্ড", k_lat: "সাড়া দেওয়ার সময়", k_lat_s: "সফল রিকোয়েস্টের গড়",
    k_req: "আসা রিকোয়েস্ট", k_syn: "আসা কানেকশন চেষ্টা", k_syn_s: "প্রতি সেকেন্ডে SYN প্যাকেট",
    c_avail: "আসল ব্যবহারকারী সেবা পাচ্ছে (%)", c_load: "আসা ট্রাফিক (প্রতি সেকেন্ডে)", lg_req: "রিকোয়েস্ট/সে.", lg_syn: "SYN/সে.", lg_cap: "সার্ভারের ক্ষমতা (৪০০ রিকোয়েস্ট/সে.)",
    res: "সার্ভারের সম্পদ", def: "চালু প্রতিরক্ষা", drops: "এ পর্যন্ত ফেলে দেওয়া", feed: "ঘটনার তালিকা", blocked: "ব্লক করা IP",
    r_syn: "SYN ব্যাকলগ (অর্ধ-খোলা কানেকশন)", r_conn: "কানেকশন স্লট", r_queue: "রিকোয়েস্টের সারি", r_work: "ব্যস্ত ওয়ার্কার",
    d_cookies: "SYN কুকি", d_rate: "ন্যায্য-ভাগ সীমা", d_header: "হেডার ডেডলাইন", d_conn: "প্রতি IP-তে সর্বোচ্চ কানেকশন", d_good: "বিশ্বস্ত IP",
    s_ok: "সেবা ঠিক আছে", s_deg: "ধীর/আংশিক", s_down: "সেবা বন্ধ", s_wait: "শুরু হচ্ছে…",
    noblock: "এখন কোনো IP ব্লক করা নেই।", secs: "সে. বাকি", foot: "সব আক্রমণ শুধু কম্পিউটারের ভেতরের সিমুলেশনে চলে। কোনো আসল নেটওয়ার্কে ট্রাফিক পাঠানো হয় না।",
    cap_req: "সার্ভারের ক্ষমতা ৪০০/সে.",
    x_idle: "<b>স্বাভাবিক ট্রাফিক।</b> প্রতি সেকেন্ডে প্রায় ৪৩টি আসল রিকোয়েস্ট সেবা পাচ্ছে। একটি আক্রমণ চালান এবং দেখুন আসল ব্যবহারকারীদের কী হয়।",
    x_off: "<b>আক্রমণ চলছে, আর সার্ভারকে কিছুই রক্ষা করছে না।</b> {A} আসল ব্যবহারকারীদের মাত্র <b>{P}%</b> সেবা পাচ্ছে।",
    x_mon: "<b>DosGuard আক্রমণটা দেখতে পাচ্ছে</b> (ঘটনার তালিকা দেখুন) <b>কিন্তু শুধু তাকিয়ে আছে</b>, তাই আসল ব্যবহারকারীরা এখনও আটকে আছে: <b>{P}%</b> সেবা পাচ্ছে। “DosGuard সুরক্ষা” চালু করুন।",
    x_pro: "<b>DosGuard প্রতিরক্ষা করছে।</b> {D} আসল ব্যবহারকারী সেবা পাচ্ছে: <b>{P}%</b>।",
    x_pro_wait: "<b>DosGuard আক্রমণ বিশ্লেষণ করছে…</b> সে প্রতি সেকেন্ডে একবার ট্রাফিক পরীক্ষা করে, তাই প্রথম সেকেন্ডে ক্ষতি হয়।",
    A_syn: "SYN ফ্লাড প্রতি সেকেন্ডে ৬০০টি ভুয়া কানেকশন অনুরোধ পাঠায়; এগুলো সার্ভারের অর্ধ-খোলা সারি ভরে দেয়, তাই আসল ব্যবহারকারী ঢুকতে পারে না।",
    A_http: "HTTP ফ্লাড: ১৫টি বট প্রতি সেকেন্ডে ১৫০০ রিকোয়েস্ট পাঠায়, কিন্তু সার্ভার সামলাতে পারে মাত্র ৪০০, তাই সারি উপচে পড়ে।",
    A_slow: "Slowloris: ৫টি আক্রমণকারী ৩০০টি অর্ধ-সমাপ্ত কানেকশন খুলে রাখে, প্রায় কোনো ট্রাফিক ছাড়াই ২৫০টি স্লট দখল করে নেয়।",
    A_dist: "ডিস্ট্রিবিউটেড ফ্লাড: ২০০টি বট, প্রতিটি মাত্র ৬ রিকোয়েস্ট/সে.। প্রতিটি বট ভদ্র দেখায়, কিন্তু সব মিলে সার্ভার অচল করে দেয়।",
    D_syn: "SYN কুকি হ্যান্ডশেককে স্টেটলেস করে, তাই ভুয়া SYN-এর এখন কোনো খরচ নেই।",
    D_http: "অতিরিক্ত রিকোয়েস্ট পাঠানো বটগুলো ৩০ সেকেন্ডের জন্য নিষিদ্ধ (ফিরে এলে আরও বেশি সময়)।",
    D_slow: "ধীর কানেকশনগুলো বন্ধ করা হয়েছে এবং আক্রমণকারী IP ব্লক করা হয়েছে।",
    D_dist: "ন্যায্য-ভাগ রেট সীমা অচেনা IP-কে আটকায়, আর পরিচিত ভালো ব্যবহারকারীরা পুরো সেবা পায়।",
  },
};
const ATK_KEYS = { syn_flood: "syn", http_flood: "http", slowloris: "slow", http_distributed: "dist" };
const WINDOW_PTS = 240;                       // 120 s at 0.5 s
let lang = "en", snap = null, hist = [], lastT = -1;
try { lang = localStorage.getItem("lang") || "en"; } catch (e) {}

const $ = (id) => document.getElementById(id);
const t = (k) => (T[lang][k] ?? T.en[k] ?? k);
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

function applyLang() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i]").forEach((el) => { el.textContent = t(el.dataset.i); });
  $("lang").textContent = lang === "en" ? "বাংলা" : "English";
  if (snap) render();
}

async function post(path, body) {
  try { await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) }); } catch (e) {}
}

/* ---------------------------------------------------------------- controls */
$("modes").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) post("/api/mode", { mode: b.dataset.mode }); });
$("speeds").addEventListener("click", (e) => { const b = e.target.closest("button"); if (b) post("/api/speed", { speed: +b.dataset.speed }); });
$("attacks").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  const on = snap && snap.attacks && b.dataset.atk in snap.attacks;
  post("/api/attack", { type: b.dataset.atk, action: on ? "stop" : "start" });
});
$("reset").addEventListener("click", () => { hist = []; lastT = -1; post("/api/reset"); });
$("lang").addEventListener("click", () => { lang = lang === "en" ? "bn" : "en"; try { localStorage.setItem("lang", lang); } catch (e) {} applyLang(); });

/* ------------------------------------------------------------------ charts */
function prep(c) {
  const r = c.getBoundingClientRect(), dpr = window.devicePixelRatio || 1;
  c.width = Math.max(1, r.width * dpr); c.height = Math.max(1, r.height * dpr);
  const g = c.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0);
  return [g, r.width, r.height];
}

function chart(canvas, o) {
  const [g, W, H] = prep(canvas), L = 40, R = 8, Tp = 8, B = 20;
  const pts = hist.slice(-WINDOW_PTS), tEnd = pts.length ? pts[pts.length - 1].t : 0, tStart = tEnd - 120;
  const X = (tt) => L + (W - L - R) * (tt - tStart) / 120;
  const Y = (v) => Tp + (H - Tp - B) * (1 - v / o.ymax);
  g.font = "11px system-ui"; g.fillStyle = css("--mut"); g.strokeStyle = css("--bd"); g.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const v = o.ymax * i / 4, y = Y(v);
    g.beginPath(); g.moveTo(L, y); g.lineTo(W - R, y); g.stroke();
    g.textAlign = "right"; g.fillText(o.fmt(v), L - 5, y + 4);
  }
  g.textAlign = "center";
  [[-120, 0], [-60, 0], [0, 0]].forEach(([d]) => { const tt = tEnd + d; if (tt >= tStart) g.fillText(d === 0 ? "now" : d + " s", Math.min(W - 16, Math.max(L + 8, X(tt))), H - 5); });
  // shaded bands while an attack was active
  g.fillStyle = css("--bad") + "22";
  let start = null;
  pts.forEach((p, i) => {
    if (p.atk > 0 && start === null) start = p.t;
    if ((p.atk === 0 || i === pts.length - 1) && start !== null) { g.fillRect(X(Math.max(start, tStart)), Tp, X(p.t) - X(Math.max(start, tStart)), H - Tp - B); start = null; }
  });
  if (o.cap) { g.setLineDash([5, 4]); g.strokeStyle = css("--mut"); g.beginPath(); g.moveTo(L, Y(o.cap)); g.lineTo(W - R, Y(o.cap)); g.stroke(); g.setLineDash([]); }
  o.series.forEach((s) => {
    g.beginPath(); g.strokeStyle = css(s.color); g.lineWidth = 2.2; g.lineJoin = "round";
    let pen = false, firstX = 0, lastX = 0;
    pts.forEach((p) => {
      const v = p[s.key]; if (v === null || v === undefined) { pen = false; return; }
      const x = X(p.t), y = Y(Math.min(v, o.ymax));
      if (!pen) { g.moveTo(x, y); pen = true; firstX = x; } else g.lineTo(x, y);
      lastX = x;
    });
    g.stroke();
    if (s.fill && pts.length > 1) { g.lineTo(lastX, Y(0)); g.lineTo(firstX, Y(0)); g.closePath(); g.fillStyle = css(s.color) + "18"; g.fill(); }
  });
}

function drawCharts() {
  chart($("cAvail"), { ymax: 100, fmt: (v) => Math.round(v) + "%", series: [{ key: "avail", color: "--ok", fill: true }] });
  const mx = Math.max(500, ...hist.slice(-WINDOW_PTS).map((p) => Math.max(p.req_rate || 0, p.syn_rate || 0)));
  const top = Math.ceil(mx / 500) * 500;
  chart($("cLoad"), { ymax: top, cap: 400, fmt: (v) => Math.round(v), series: [{ key: "syn_rate", color: "--orange" }, { key: "req_rate", color: "--acc" }] });
}

/* ------------------------------------------------------------------ render */
function level(frac) { return frac >= 0.85 ? "bad" : frac >= 0.6 ? "warn" : ""; }

function render() {
  const s = snap; if (!s) return;
  $("clock").textContent = "t = " + Math.round(s.t) + " s";
  // status pill
  const pill = $("status");
  if (s.avail === null) { pill.className = "pill wait"; pill.textContent = t("s_wait"); }
  else if (s.avail >= 90) { pill.className = "pill ok"; pill.textContent = t("s_ok"); }
  else if (s.avail >= 60) { pill.className = "pill warn"; pill.textContent = t("s_deg") + " " + Math.round(s.avail) + "%"; }
  else { pill.className = "pill bad"; pill.textContent = t("s_down") + " " + Math.round(s.avail) + "%"; }
  // controls
  document.querySelectorAll("#modes button").forEach((b) => b.classList.toggle("on", b.dataset.mode === s.mode));
  document.querySelectorAll("#speeds button").forEach((b) => b.classList.toggle("on", +b.dataset.speed === s.speed));
  document.querySelectorAll("#attacks .atk").forEach((b) => b.classList.toggle("on", b.dataset.atk in s.attacks));
  $("modeHint").textContent = t("h_" + s.mode);
  // KPIs
  const av = $("kAvail"); av.textContent = s.avail === null ? "–" : Math.round(s.avail) + "%";
  av.className = "val " + (s.avail === null ? "" : s.avail >= 90 ? "ok" : s.avail >= 60 ? "warn" : "bad");
  $("kLat").textContent = s.latency_ms === null ? "–" : s.latency_ms + " ms";
  $("kReq").textContent = s.req_rate; $("kReqS").textContent = t("cap_req");
  $("kSyn").textContent = s.syn_rate;
  // resource bars
  const rows = [["r_syn", s.half_open], ["r_conn", s.conns], ["r_queue", s.queue], ["r_work", s.workers]];
  $("bars").innerHTML = rows.map(([k, [v, m]]) => `<div class="bar"><div class="row"><span>${t(k)}</span><span>${v} / ${m}</span></div><div class="track"><div class="fill ${level(v / m)}" style="width:${Math.min(100, 100 * v / m)}%"></div></div></div>`).join("");
  // defences
  const p = s.protections, chips = [
    [t("d_cookies"), p.syn_cookies, p.syn_cookies ? "ON" : "off"],
    [t("d_rate"), p.rate_limit !== null, p.rate_limit !== null ? p.rate_limit + " req/s" : "off"],
    [t("d_header"), p.header_deadline !== null, p.header_deadline !== null ? p.header_deadline + " s" : "off"],
    [t("d_conn"), p.conn_limit !== null, p.conn_limit !== null ? p.conn_limit : "off"],
    [t("d_good"), p.known_good > 0, p.known_good],
  ];
  $("chips").innerHTML = chips.map(([n, on, v]) => `<span class="chip ${on ? "on" : ""}">${n}: ${v}</span>`).join("");
  const d = s.drops, names = { syn_dropped: "SYN dropped", conn_refused: "conn refused", overload_503: "503 overload", rate_limited: "429 rate-limited", fw_drop: "firewall drop", connlimit_drop: "conn-limit drop", slow_killed: "slow killed" };
  $("drops").innerHTML = Object.keys(names).map((k) => `<span>${names[k]}<b>${d[k] || 0}</b></span>`).join("");
  // feed
  $("feed").innerHTML = s.feed.slice().reverse().map((e) => `<li><span class="t">${e.t.toFixed(0)}s</span><span class="k k-${e.kind}">${e.kind.toUpperCase()}</span><span></span></li>`).join("");
  const lis = $("feed").children; s.feed.slice().reverse().forEach((e, i) => { lis[i].lastChild.textContent = e.msg; });
  // blocked
  $("blockedN").textContent = s.blocked_total ? "(" + s.blocked_total + ")" : "";
  $("blocked").firstElementChild.innerHTML = s.blocked.length ? s.blocked.map((b) => `<tr><td class="mono">${b.ip}</td><td>${b.secs} ${t("secs")}</td></tr>`).join("") : `<tr><td class="empty" colspan="2">${t("noblock")}</td></tr>`;
  explain(s);
  drawCharts();
}

function explain(s) {
  const keys = Object.keys(s.attacks), box = $("explain");
  const P = s.avail === null ? "…" : Math.round(s.avail);
  let html, cls = "";
  if (!keys.length) { html = t("x_idle"); cls = "ok"; }
  else {
    const A = keys.map((k) => t("A_" + ATK_KEYS[k])).join(" ");
    const D = keys.map((k) => t("D_" + ATK_KEYS[k])).join(" ");
    if (s.mode === "off") { html = t("x_off").replace("{A}", A).replace("{P}", P); cls = "bad"; }
    else if (s.mode === "monitor") { html = t("x_mon").replace("{P}", P); cls = "warn"; }
    else if (s.alerts === 0) { html = t("x_pro_wait"); cls = "warn"; }
    else { html = t("x_pro").replace("{D}", D).replace("{P}", P); cls = s.avail !== null && s.avail >= 85 ? "ok" : "warn"; }
  }
  box.className = "panel explain " + cls; box.innerHTML = "<p>" + html + "</p>";
}

/* -------------------------------------------------------------- data feed */
function ingest(s) {
  if (s.t < lastT) hist = [];               // simulation was reset
  lastT = s.t; snap = s;
  hist.push({ t: s.t, avail: s.avail, req_rate: s.req_rate, syn_rate: s.syn_rate, atk: Object.keys(s.attacks).length });
  if (hist.length > WINDOW_PTS) hist.shift();
  render();
}

async function boot() {
  applyLang();
  try {
    const r = await (await fetch("/api/state")).json();
    hist = r.history.map((p) => ({ t: p.t, avail: p.avail, req_rate: p.req_rate, syn_rate: p.syn_rate, atk: p.atk }));
    snap = r.snapshot; lastT = snap.t; render();
  } catch (e) {}
  const es = new EventSource("/events");
  es.onopen = () => { $("conn").className = "dot on"; };
  es.onerror = () => { $("conn").className = "dot off"; };
  es.onmessage = (m) => { try { ingest(JSON.parse(m.data)); } catch (e) {} };
}
window.addEventListener("resize", () => { if (snap) drawCharts(); });
boot();
