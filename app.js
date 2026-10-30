// Stamp — verification tool pulled from the kin-security rule engine
// Paste a claim or code snippet. Get one structured card. Refuses to invent.

const RULES = [
  { id:"sqli", pattern:/['"]\s*\+\s*.*SELECT|query\s*\(.*\+|exec\s*\(.*\$/i, name:"SQL injection risk", cwe:"CWE-89", blast:"Database access or data theft.", check:"Parameterized queries or prepared statements.", falsify:"Input never reaches a query string." },
  { id:"cmd", pattern:/exec\s*\(|system\s*\(|spawn\s*\(.*\$|os\.system/i, name:"Command injection risk", cwe:"CWE-78", blast:"Remote code execution.", check:"No user input in shell commands.", falsify:"Command constructed only from allow-list." },
  { id:"xss", pattern:/innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML/i, name:"XSS risk", cwe:"CWE-79", blast:"Session theft or script execution in browser.", check:"Output encoding or DOMPurify.", falsify:"All user content escaped before DOM insertion." },
  { id:"secret", pattern:/(api[_-]?key|secret|password|token)\s*[:=]\s*['"][^'"]{8,}/i, name:"Hardcoded secret", cwe:"CWE-798", blast:"Credential leak.", check:"Secrets from environment or vault.", falsify:"No secrets in source." },
  { id:"path", pattern:/\.\.\/|path\.join\s*\(.*req\.|fs\.readFile\s*\(.*\+/i, name:"Path traversal risk", cwe:"CWE-22", blast:"Arbitrary file read.", check:"Path normalization and allow-list.", falsify:"Resolved path stays inside intended root." }
];

let log = JSON.parse(localStorage.getItem("stamp-log") || "[]");

function save() { localStorage.setItem("stamp-log", JSON.stringify(log.slice(0,40))); }

function stamp(text) {
  if (!text.trim()) return null;
  const hits = RULES.filter(r => r.pattern.test(text));
  if (hits.length) return { type:"code", hits };
  const lower = text.toLowerCase();
  if (lower.includes("earth is flat") || lower.includes("vaccines cause autism")) {
    return { type:"claim", verdict:"refuted", confidence:0.9, blast:"Public decisions.", check:"Direct evidence or large studies.", falsify:"Reproducible contrary result." };
  }
  return { type:"none" };
}

function render() {
  const tab = document.querySelector(".tab.active").dataset.tab;
  const app = document.getElementById("app");
  if (tab === "stamp") {
    app.innerHTML = `
      <div class="card">
        <textarea id="input" placeholder="Paste a claim or a short code snippet"></textarea>
        <button class="primary" id="go">Stamp</button>
      </div>
      <div id="result"></div>`;
    document.getElementById("go").onclick = () => {
      const text = document.getElementById("input").value;
      const s = stamp(text);
      let html = "";
      if (!s || s.type === "none") {
        html = `<div class="card"><div class="muted">No stamp</div><p>Nothing matched the shipped pack. Stamp refuses to invent a finding.</p></div>`;
      } else if (s.type === "code") {
        html = s.hits.map(h => `<div class="card">
          <strong>${h.name}</strong> <span class="muted">${h.cwe}</span>
          <p><strong>Blast</strong><br>${h.blast}</p>
          <p><strong>How to check</strong><br>${h.check}</p>
          <p><strong>What would kill it</strong><br>${h.falsify}</p>
        </div>`).join("");
      } else {
        html = `<div class="card">
          <strong>${s.verdict}</strong> <span class="muted">${Math.round(s.confidence*100)}%</span>
          <p><strong>Blast</strong><br>${s.blast}</p>
          <p><strong>How to check</strong><br>${s.check}</p>
          <p><strong>What would kill it</strong><br>${s.falsify}</p>
        </div>`;
      }
      document.getElementById("result").innerHTML = html;
      if (s && s.type !== "none") {
        log.unshift({ t:Date.now(), preview:text.slice(0,60), type:s.type });
        save();
      }
    };
  } else if (tab === "log") {
    let html = `<div class="card"><strong>Log</strong> <span class="muted">${log.length}</span></div>`;
    log.slice(0,15).forEach(e => html += `<div class="card">${e.preview}…</div>`);
    app.innerHTML = html;
  } else {
    app.innerHTML = `
      <div class="card"><strong>Shipped pack</strong><p class="muted">5 deterministic rules. Offline.</p></div>
      <div class="card muted">Advanced packs (paid) add more CWEs and claim sets. Same refusal rule.</div>`;
  }
}

document.querySelectorAll(".tab").forEach(t => {
  t.onclick = () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    t.classList.add("active");
    render();
  };
});

if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(()=>{});
render();
