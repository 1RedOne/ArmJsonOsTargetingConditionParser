<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OS Family Policy Parser</title>
  <style>
    :root{
      --bg:#0b1020; --panel:#121a2e; --muted:#a9b4d0; --text:#e7ecf7; --accent:#6aa2ff; --good:#2ecc71; --warn:#f1c40f; --bad:#ff6b6b;
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{margin:0;background:linear-gradient(180deg,#0b1020,#0e1630 30%,#0b1020);color:var(--text);font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,"Helvetica Neue",Arial}
    .container{max-width:1100px;margin:40px auto;padding:0 16px}
    header{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:16px}
    .title{font-size:24px;font-weight:700;letter-spacing:.2px}
    .subtitle{color:var(--muted);font-size:13px}
    .panel{background:var(--panel);border:1px solid #253155;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.3);overflow:hidden}
    .grid{display:grid;grid-template-columns:1fr;gap:16px}
    @media(min-width:900px){.grid{grid-template-columns:1.1fr .9fr}}
    textarea{width:100%;min-height:320px;background:#0a1230;color:var(--text);border:1px solid #2a3865;border-radius:12px;padding:14px 12px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
    textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(106,162,255,.2)}
    .controls{display:flex;flex-wrap:wrap;gap:10px;margin-top:10px}
    button{cursor:pointer;background:#1b2a52;border:1px solid #2a3865;color:var(--text);padding:10px 14px;border-radius:12px;font-weight:600;transition:.15s}
    button:hover{transform:translateY(-1px);box-shadow:0 6px 16px rgba(0,0,0,.35)}
    button.primary{background:linear-gradient(180deg,#2a61ff,#2046c9);border-color:#2342b8}
    .chip{display:inline-flex;align-items:center;gap:6px;border-radius:999px;padding:6px 10px;font-weight:700;border:1px solid #2a3865;background:#0f1730;}
    .chip.good{color:#d9ffe7;border-color:#2e7d50;background:linear-gradient(180deg,#10341f,#0d2a19)}
    .chip.warn{color:#fff4d6;border-color:#8a6d1f;background:linear-gradient(180deg,#2c240e,#241e0c)}
    .chip.bad{color:#ffe5e5;border-color:#7d2e2e;background:linear-gradient(180deg,#2c1010,#240d0d)}
    .section{padding:16px;border-top:1px solid #223056}
    .section h3{margin:0 0 10px;font-size:16px}
    .kv{display:grid;grid-template-columns:160px 1fr;gap:12px;align-items:start}
    .muted{color:var(--muted)}
    table{width:100%;border-collapse:separate;border-spacing:0 8px}
    th,td{text-align:left;padding:10px 12px;background:#0b1434;border:1px solid #223056}
    th:first-child,td:first-child{border-top-left-radius:8px;border-bottom-left-radius:8px}
    th:last-child,td:last-child{border-top-right-radius:8px;border-bottom-right-radius:8px}
    th{background:#0e1a40;color:#c9d6ff}
    .pill{display:inline-block;padding:2px 8px;border-radius:999px;border:1px solid #2a3865;background:#0f1730}
    .stack{display:flex;flex-direction:column;gap:8px}
    .error{white-space:pre-wrap;color:#ffe0e0;background:#2b0f12;border:1px solid #6b1f26;padding:10px;border-radius:12px}
    footer{margin-top:18px;color:var(--muted);font-size:12px;text-align:center}
    .tiny{font-size:12px}
    .tip{border-left:3px solid #2a61ff;padding-left:10px}
    code{background:#091033;border:1px solid #223056;padding:2px 6px;border-radius:6px}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <div class="title">OS Family Policy Parser</div>
        <div class="subtitle">Paste an Azure Policy rule JSON to families are allowed & why. No cloud needed.</div>
      </div>
      <div class="chip" title="All local, no network calls">🔒 Local-only</div>
    </header>

    <div class="grid">
      <div class="panel" style="padding:16px">
        <label for="input" class="muted tiny">INPUT JSON</label>
        <textarea id="input" spellcheck="false" placeholder="Paste your Azure Policy rule JSON here…"></textarea>
        <div class="controls">
          <button class="primary" id="parseBtn">Parse JSON</button>
          <button id="sampleBtn">Load Sample</button>
          <button id="clearBtn">Clear</button>
        </div>
        <div id="inputError" class="error" style="display:none;margin-top:10px"></div>
        <div class="tip tiny" style="margin-top:10px">TIP: We look for signals like <code>linuxConfiguration</code>, <code>osDisk.osType</code>,
          Publisher/Offer/SKU patterns, and positive/negative matches (<code>like</code>, <code>notLike</code>, <code>in</code>, <code>notIn</code>) across <code>anyOf</code>/<code>allOf</code> trees.</div>
      </div>

      <div class="panel" style="padding:16px">
        <div class="section" style="border-top:none">
          <h3>Detected OS Families</h3>
          <div id="familyChips" class="stack"></div>
        </div>
        <div class="section">
          <h3>Summary</h3>
          <div class="kv">
            <div class="muted">Verdict</div>
            <div id="verdict">—</div>
            <div class="muted">Confidence</div>
            <div id="confidence">—</div>
            <div class="muted">Signals</div>
            <div id="signals" class="stack"></div>
          </div>
        </div>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="section" style="border-top:none">
        <h3>Publisher Allowlist (explicit)</h3>
        <table id="allowPublishersTbl">
          <thead><tr><th>Source</th><th>Publisher(s)</th><th>Notes</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="section">
        <h3>Constraints & Patterns</h3>
        <table id="constraintsTbl">
          <thead><tr><th>Field</th><th>Operator</th><th>Value</th><th>Context</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="section">
        <h3>Image Matrix (Publisher × SKU × Version)</h3>
        <table id="imageMatrixTbl">
          <thead><tr><th>ImagePublisher</th><th>SKU(s)</th><th>Version(s)</th></tr></thead>
          <tbody></tbody>
        </table>
        <div class="tiny muted" style="margin-top:8px">
          Rows are derived by correlating predicates that share the same rule branch (context).
        </div>
      </div>
    </div>

    <footer>
      Built for devbro ⚡ Paste policy JSON, click <b>Parse</b>, and ship it. If the result seems off, ping me with your weirdest edge case 🧪
    </footer>
  </div>

<script>
(function(){
  const el = id => document.getElementById(id);
  const input = el('input');
  const parseBtn = el('parseBtn');
  const sampleBtn = el('sampleBtn');
  const clearBtn = el('clearBtn');
  const inputError = el('inputError');
  const familyChips = el('familyChips');
  const verdict = el('verdict');
  const confidence = el('confidence');
  const signalsDiv = el('signals');
  const allowPublishersTbl = el('allowPublishersTbl').querySelector('tbody');
  const constraintsTbl = el('constraintsTbl').querySelector('tbody');
  const imageMatrixTbl = el('imageMatrixTbl').querySelector('tbody'); // NEW

  function safeJSON(str){
    try { return JSON.parse(str); } catch (e) { return { __error: e.message }; }
  }

  function addConstraint(field, op, value, context){
    constraints.push({field, op, value, context});
  }

  function addSignal(text){ signals.push(text); }

  function walk(node, contextPath = []){
    if (!node || typeof node !== 'object') return;

    // Composite clauses
    if (Array.isArray(node.allOf)){
      node.allOf.forEach((n,i)=> walk(n, contextPath.concat(`allOf[${i}]`)));
    }
    if (Array.isArray(node.anyOf)){
      node.anyOf.forEach((n,i)=> walk(n, contextPath.concat(`anyOf[${i}]`)));
    }
    
    if (node.if){
      walk(node.if, contextPath.concat('if'));
    }
    // if (Array.isArray(node.if.anyOf)){
    //   node.if.anyOf.forEach((n,i)=> walk(n, contextPath.concat(`if[${i}]`)));
    // }

    const ctx = contextPath.join(' > ');

    // Primitive predicate
    const field = node.field;
    if (field){
      const ops = ['equals','like','notLike','in','notIn','exists'];
      const op = ops.find(k => Object.prototype.hasOwnProperty.call(node,k));
      const val = node[op];

      // Capture constraints table
      if (op){
        addConstraint(field, op, Array.isArray(val)? val.join(', ') : String(val), ctx || 'root');
      }

      // Heuristics for OS
      if (field.endsWith('osProfile.linuxConfiguration') && op === 'exists' && val === true){
        linuxAllowed = true; addSignal('linuxConfiguration exists → Linux');
      }
      if (field.endsWith('osDisk.osType')){
        const v = String(val || '').toLowerCase();
        if ((op === 'like' || op === 'equals') && v.startsWith('linux')){ linuxAllowed = true; addSignal('osDisk.osType matches Linux*'); }
        if ((op === 'like' || op === 'equals') && v.startsWith('windows')){ windowsAllowed = true; addSignal('osDisk.osType matches Windows*'); }
      }

      // Publisher allowlists
      if (field === 'Microsoft.Compute/imagePublisher'){
        if (op === 'equals' && typeof val === 'string'){
          allowPublishers.add(val);
          addSignal(`Publisher equals '${val}'`);
        }
        if (op === 'in' && Array.isArray(val)){
          val.forEach(v=> allowPublishers.add(v));
          addSignal(`Publisher in [${val.join(', ')}]`);
        }
        if (op === 'notIn' && Array.isArray(val)){
          // Negative list; implies others allowed in that branch
          negativePublishers = negativePublishers.concat(val);
        }
      }

      // Offer/SKU patterns hint Windows-vs-Linux
      if (field === 'Microsoft.Compute/imageOffer'){
        const sval = String(val || '').toLowerCase();
        if (op === 'like' && sval.startsWith('linux')){ linuxAllowed = true; addSignal('imageOffer like linux*'); }
        if (op === 'notLike' && sval.startsWith('cis-win')){ windowsExcluded = true; addSignal('exclude CIS Windows offers'); }
        if (op === 'notLike' && sval.startsWith('dsvm-win')){ windowsExcluded = true; addSignal('exclude DSVM Windows offers'); }
      }
      if (field === 'Microsoft.Compute/imageSKU'){
        // Exclusions like 6* map to older distros (CentOS/RHEL/Oracle 6, SUSE 11, Ubuntu 12 handled via publisher+sku)
        skuConstraints.push({ op, value: val, context: ctx });
      }
      if (field === 'Microsoft.Compute/imageVersion' || field === 'Microsoft.Compute/version'){
        // captured by constraints table; matrix will consume
      }
    }
  }

  function renderChips(){
    familyChips.innerHTML='';
    const chips=[];
    if (linuxAllowed) chips.push(["Linux", 'good']);
    if (windowsAllowed) chips.push(["Windows", windowsExcluded? 'warn' : 'good']);
    if (!chips.length) chips.push(["Unknown / Not explicit", 'bad']);
    chips.forEach(([t,kind])=>{
      const c=document.createElement('div');
      c.className=`chip ${kind}`; c.textContent=t; familyChips.appendChild(c);
    });
  }

  function renderTables(){
    // Allow publishers
    allowPublishersTbl.innerHTML='';
    if (allowPublishers.size){
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>imagePublisher</td><td>${[...allowPublishers].map(p=>`<span class="pill">${p}</span>`).join(' ')}</td><td>Explicit allow</td>`;
      allowPublishersTbl.appendChild(tr);
    } else {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="3" class="muted">No explicit allowlist of publishers detected.</td>`;
      allowPublishersTbl.appendChild(tr);
    }

    // Constraints & patterns
    constraintsTbl.innerHTML='';
    constraints.forEach(r=>{
      const tr=document.createElement('tr');
      tr.innerHTML = `<td><code>${r.field}</code></td><td>${r.op}</td><td>${escapeHtml(r.value)}</td><td class="muted">${r.context}</td>`;
      constraintsTbl.appendChild(tr);
    });

    // Image Matrix
    imageMatrixTbl.innerHTML = '';
    if (!imageMatrixRows.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="3" class="muted">No publisher/SKU/version correlations detected.</td>`;
      imageMatrixTbl.appendChild(tr);
    } else {
      imageMatrixRows.forEach(r => {
        const skuHtml = r.skus.size
          ? [...r.skus].map(s => `<span class="pill">${escapeHtml(s)}</span>`).join(' ')
          : '<span class="muted">—</span>';
        const verHtml = r.versions.size
          ? [...r.versions].map(v => `<span class="pill">${escapeHtml(v)}</span>`).join(' ')
          : '<span class="muted">—</span>';
        const tr = document.createElement('tr');
        tr.innerHTML = `<td><span class="pill">${escapeHtml(r.publisher)}</span></td><td>${skuHtml}</td><td>${verHtml}</td>`;
        imageMatrixTbl.appendChild(tr);
      });
    }
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, m=>({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[m]));
  }

  function computeVerdict(){
    let v = '—'; let conf = 'medium';
    if (linuxAllowed && !windowsAllowed){ v = 'Linux-only (inferred)'; conf = 'high'; }
    else if (linuxAllowed && windowsAllowed){ v = 'Linux & Windows (mixed)'; conf = windowsExcluded? 'medium' : 'low-med'; }
    else if (!linuxAllowed && windowsAllowed){ v = 'Windows-only (inferred)'; conf = 'medium'; }
    else { v = 'Not explicit in rules'; conf = 'low'; }
    verdict.textContent = v; confidence.textContent = conf;
  }

  function renderSignals(){
    signalsDiv.innerHTML='';
    if (!signals.length){ signalsDiv.innerHTML = '<span class="muted">No strong OS signals found.</span>'; return; }
    signals.forEach(s=>{
      const d=document.createElement('div'); d.className='pill'; d.textContent=s; signalsDiv.appendChild(d);
    });
  }

  function parseNow(){
    inputError.style.display='none'; inputError.textContent='';

    const obj = safeJSON(input.value.trim());
    if (obj.__error){
      inputError.style.display='block'; inputError.textContent = 'JSON Parse Error: ' + obj.__error;
      return;
    }

    // Reset accumulators
    linuxAllowed=false; windowsAllowed=false; windowsExcluded=false;
    allowPublishers=new Set(); negativePublishers=[]; skuConstraints=[]; constraints=[]; signals=[];

    walk(obj, []);

    // Post-process negative publishers
    if (negativePublishers.length){
      addSignal(`Publishers explicitly excluded in a branch: [${negativePublishers.join(', ')}]`);
    }

    // Build the Publisher × SKU × Version rows
    imageMatrixRows = buildImageMatrix(constraints);

    renderChips();
    renderTables();
    computeVerdict();
    renderSignals();
  }

  // State
  let linuxAllowed=false, windowsAllowed=false, windowsExcluded=false;
  let allowPublishers=new Set();
  let negativePublishers=[];
  let skuConstraints=[];
  let constraints=[];
  let signals=[];
  let imageMatrixRows=[]; // [{publisher, skus:Set, versions:Set}]

  // Wire buttons
  parseBtn.addEventListener('click', parseNow);
  clearBtn.addEventListener('click', ()=>{
    input.value='';
    familyChips.innerHTML='';
    verdict.textContent='—';
    confidence.textContent='—';
    signalsDiv.innerHTML='';
    allowPublishersTbl.innerHTML='';
    constraintsTbl.innerHTML='';
    imageMatrixTbl.innerHTML='';
  });

  sampleBtn.addEventListener('click', ()=>{
    input.value = SAMPLE_JSON.trim();
  });

  // Load sample if empty on first visit
  if (!input.value.trim()) input.value = SAMPLE_JSON.trim();
})();

// Build Publisher × SKU × Version matrix by correlating constraints that share a branch context
function buildImageMatrix(constraints){
  // context -> { publishers:Set, skus:Set, versions:Set }
  const byContext = new Map();
  const ensure = (ctx) => {
    if(!byContext.has(ctx)) byContext.set(ctx,{publishers:new Set(), skus:new Set(), versions:new Set()});
    return byContext.get(ctx);
  };

  constraints.forEach(c => {
    const ctx = c.context || 'root';
    const entry = ensure(ctx);
    const raw = String(c.value ?? '').trim();

    if (c.field === 'Microsoft.Compute/imagePublisher' && (c.op === 'equals' || c.op === 'in')) {
      raw.split(/,\s*/).filter(Boolean).forEach(v => entry.publishers.add(v));
    }
    if (c.field === 'Microsoft.Compute/imageSKU') {
      raw.split(/,\s*/).filter(Boolean).forEach(v => entry.skus.add(v.replace(/\*+$/,'')));
    }
    if (c.field === 'Microsoft.Compute/imageVersion' || c.field === 'Microsoft.Compute/version') {
      raw.split(/,\s*/).filter(Boolean).forEach(v => entry.versions.add(v.replace(/\*+$/,'')));
    }
  });

  // Aggregate across contexts by publisher
  const byPublisher = new Map();
  byContext.forEach(entry => {
    entry.publishers.forEach(pub => {
      if (!byPublisher.has(pub)) byPublisher.set(pub, {publisher: pub, skus:new Set(), versions:new Set()});
      const agg = byPublisher.get(pub);
      entry.skus.forEach(s => agg.skus.add(s));
      entry.versions.forEach(v => agg.versions.add(v));
    });
  });

  return [...byPublisher.values()].sort((a,b)=> a.publisher.localeCompare(b.publisher));
}

// Sample from your snippet
const SAMPLE_JSON = `{
  "anyOf": [
    {
      "allOf": [
        {"anyOf": [
          {"field": "type", "equals": "Microsoft.Compute/virtualMachines"},
          {"field": "type", "equals": "Microsoft.Compute/virtualMachineScaleSets"}
        ]},
        {"field": "tags['aks-managed-orchestrator']", "exists": false},
        {"field": "tags['aks-managed-poolName']", "exists": false},
        {"anyOf": [
          {"field": "Microsoft.Compute/imagePublisher", "in": [
            "microsoft-aks","qubole-inc","datastax","couchbase","scalegrid",
            "checkpoint","paloaltonetworks","debian","credativ"]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "OpenLogic"},
            {"field": "Microsoft.Compute/imageSKU", "notLike": "6*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "Oracle"},
            {"field": "Microsoft.Compute/imageSKU", "notLike": "6*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "RedHat"},
            {"field": "Microsoft.Compute/imageSKU", "notLike": "6*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "center-for-internet-security-inc"},
            {"field": "Microsoft.Compute/imageOffer", "notLike": "cis-win*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "Suse"},
            {"field": "Microsoft.Compute/imageSKU", "notLike": "11*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "Canonical"},
            {"field": "Microsoft.Compute/imageSKU", "notLike": "12*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "microsoft-dsvm"},
            {"field": "Microsoft.Compute/imageOffer", "notLike": "dsvm-win*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "cloudera"},
            {"field": "Microsoft.Compute/imageSKU", "notLike": "6*"}
          ]},
          {"allOf": [
            {"field": "Microsoft.Compute/imagePublisher", "equals": "microsoft-ads"},
            {"field": "Microsoft.Compute/imageOffer", "like": "linux*"}
          ]},
          {"allOf": [
            {"anyOf": [
              {"field": "Microsoft.Compute/virtualMachines/osProfile.linuxConfiguration", "exists": true},
              {"field": "Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType", "like": "Linux*"}
            ]},
            {"anyOf": [
              {"field": "Microsoft.Compute/imagePublisher", "exists": false},
              {"field": "Microsoft.Compute/imagePublisher", "notIn": [
                "OpenLogic","RedHat","credativ","Suse","Canonical","microsoft-dsvm",
                "cloudera","microsoft-ads","center-for-internet-security-inc","Oracle",
                "AzureDatabricks","azureopenshift"
              ]}
            ]}
          ]}
        ]}
      ]
    }
  ]
}`;
</script>
</body>
</html>
