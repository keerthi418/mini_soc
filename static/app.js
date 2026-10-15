let severityChart;
let latestData = null;
const $ = (id) => document.getElementById(id);

const pageHistory = [];
let currentPage = "overview";
function showPage(page, push=true) {
  if (push && page !== currentPage) pageHistory.push(currentPage);
  currentPage = page;
  const visible = {
    overview:["welcome","metrics","content-grid"],
    alerts:["alerts"],
    timeline:["timeline"],
    ingest:["content-grid"],
    devices:["devices"],
    requests:["requests"],
    audit:["audit"],
    storage:["storage"]
  }[page] || ["welcome","metrics","content-grid"];
  document.querySelectorAll(".main > section, .main > .welcome, .main > .metrics").forEach(el => {
    el.hidden = !visible.includes(el.id || (el.classList.contains("welcome")?"welcome":el.classList.contains("metrics")?"metrics":""));
  });
  // On the log analysis page, show only the upload panel.
  const contentGrid=document.querySelector(".content-grid");
  if(page==="ingest") {
    contentGrid.hidden=false;
    contentGrid.querySelector(".chart-panel").hidden=true;
    contentGrid.querySelector(".upload-panel").style.gridColumn="1 / -1";
  } else {
    contentGrid.querySelector(".chart-panel").hidden=false;
    contentGrid.querySelector(".upload-panel").style.gridColumn="";
  }
  document.querySelectorAll(".nav").forEach(n=>n.classList.toggle("active",n.dataset.target===page));
  $("back-btn").hidden=pageHistory.length===0;
  const titles={overview:"Investigation Overview",alerts:"Threat Alerts",timeline:"Event Timeline",ingest:"Log Analysis",devices:"Wi-Fi Device Inventory",requests:"Consent Requests",audit:"Audit Trail",storage:"Database & Storage"};
  document.querySelector(".topbar h1").textContent=titles[page]||"SentinelX";
  if(page==="devices") loadDevices();
  if(page==="requests") loadRequests();
  if(page==="audit") loadAudit();
  if(page==="storage") loadStorage();
  window.scrollTo({top:0,behavior:"smooth"});
}
document.querySelectorAll(".nav").forEach(btn=>btn.addEventListener("click",()=>showPage(btn.dataset.target)));
$("back-btn").addEventListener("click",()=>{const previous=pageHistory.pop(); if(previous) showPage(previous,false);});

$("log-file").addEventListener("change", (event) => {
  const file = event.target.files[0];
  $("file-name").textContent = file ? `${file.name} · ${(file.size/1024).toFixed(1)} KB` : "No file selected";
  $("upload-message").textContent = "";
});

$("analyze-btn").addEventListener("click", async () => {
  const file = $("log-file").files[0];
  if (!file) {
    $("upload-message").textContent = "Choose a CSV file first, or download the sample CSV.";
    return;
  }
  const data = new FormData();
  data.append("file", file);
  $("analyze-btn").disabled = true;
  $("analyze-btn").textContent = "Analyzing…";
  $("upload-message").textContent = "";
  try {
    const response = await fetch("/api/analyze", {method:"POST", body:data});
    const result = await response.json();
    if (!response.ok) throw new Error(result.detail || "Analysis failed");
    render(result);
    $("upload-message").textContent = `Analysis complete: ${result.summary.total_logs} rows inspected.`;
    $("footer-status").textContent = "Upload analyzed";
  } catch (err) {
    $("upload-message").textContent = err.message;
  } finally {
    $("analyze-btn").disabled = false;
    $("analyze-btn").innerHTML = 'Analyze logs <span>→</span>';
  }
});

$("refresh-btn").addEventListener("click", loadSample);

async function loadSample() {
  $("footer-status").textContent = "Refreshing…";
  try {
    const [health, response] = await Promise.all([fetch("/api/health"), fetch("/api/sample")]);
    if (!health.ok || !response.ok) throw new Error("API unavailable");
    const h = await health.json();
    $("engine-status").textContent = h.status === "online" ? "Online · v" + h.version : "Unavailable";
    render(await response.json());
    $("footer-status").textContent = "Sample data loaded";
  } catch (err) {
    $("engine-status").textContent = "Connection error";
    $("footer-status").textContent = err.message;
  }
}

function render(data) {
  latestData = data;
  const s = data.summary;
  $("total-logs").textContent = s.total_logs;
  $("total-alerts").textContent = s.total_alerts;
  $("high-alerts").textContent = s.high;
  $("failed-logins").textContent = s.failed_logins;
  $("nav-alert-count").textContent = s.total_alerts;
  $("alert-badge").textContent = `${s.total_alerts} FINDINGS`;

  const body = $("alerts-body");
  if (!data.alerts.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty-cell">No rule matches found in this dataset.</td></tr>';
  } else {
    body.innerHTML = data.alerts.map(a => `
      <tr>
        <td><div class="alert-title">${escapeHtml(a.title)}</div><div class="alert-id">${escapeHtml(a.id)} · ${escapeHtml(a.mitre)}</div></td>
        <td>${escapeHtml(a.source_ip)}</td>
        <td><span class="severity ${a.severity.toLowerCase()}">${escapeHtml(a.severity)}</span></td>
        <td><span class="risk">${a.risk_score}/100</span></td>
        <td class="evidence" title="${escapeHtml(a.recommendation)}">${escapeHtml(a.evidence)}</td>
      </tr>`).join("");
  }
  const tBody = $("timeline-body");
  if (!data.timeline.length) {
    tBody.innerHTML = '<tr><td colspan="5" class="empty-cell">No events to display.</td></tr>';
  } else {
    tBody.innerHTML = [...data.timeline].reverse().map(e => `
      <tr><td>${escapeHtml(e.timestamp)}</td><td>${escapeHtml(e.username)}</td><td>${escapeHtml(e.source_ip)}</td><td>${escapeHtml(e.event)}</td><td class="${/fail|denied|error/i.test(e.status) ? "status-failed" : "status-success"}">${escapeHtml(e.status)}</td></tr>
    `).join("");
  }
  const counts = {High:s.high, Medium:s.medium, Low:s.low};
  $("chart-empty").hidden = s.total_alerts !== 0;
  const canvas = $("severityChart");
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(canvas, {
    type:"doughnut",
    data:{labels:Object.keys(counts),datasets:[{data:Object.values(counts),backgroundColor:["#ff6b78","#ffb45b","#59e0a0"],borderColor:"#111822",borderWidth:5,hoverOffset:5}]},
    options:{responsive:true,maintainAspectRatio:false,cutout:"70%",plugins:{legend:{position:"right",labels:{color:"#a8b5c4",usePointStyle:true,pointStyle:"circle",padding:18,font:{family:"Manrope",size:11}}}}}
  });
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
loadSample();


async function apiJson(url, options={}) {
  const response=await fetch(url,options);
  const data=await response.json();
  if(!response.ok) throw new Error(data.detail || "Request failed");
  return data;
}
function safeText(v){return escapeHtml(v ?? "—");}
async function loadDevices(){
  try {
    const data=await apiJson("/api/devices");
    $("devices-body").innerHTML=data.devices.length?data.devices.map(d=>`<tr><td>${safeText(d.ip)}</td><td>${safeText(d.mac)}</td><td>${safeText(d.hostname)}</td><td>${safeText(d.discovered_at)}</td></tr>`).join(""):'<tr><td colspan="4" class="empty-cell">No saved devices. Scan the local cache.</td></tr>';
  } catch(e){$("device-message").textContent=e.message;}
}
$("scan-devices").addEventListener("click",async()=>{
  $("scan-devices").disabled=true;$("device-message").textContent="Reading local ARP cache…";
  try {const d=await apiJson("/api/devices/scan",{method:"POST"});$("device-message").textContent=`Found ${d.count} cached private-network device(s). ${d.notice}`;await loadDevices();await loadAudit();}
  catch(e){$("device-message").textContent=e.message;}finally{$("scan-devices").disabled=false;}
});
$("create-request").addEventListener("click",async()=>{
  const payload={device_name:$("req-name").value,device_ip:$("req-ip").value,purpose:$("req-purpose").value,requested_by:$("req-by").value};
  try {const d=await apiJson("/api/requests",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});alert(`Consent request #${d.id} saved as pending. ${d.message}`);$("req-purpose").value="";showPage("requests");}
  catch(e){alert(e.message);}
});
async function loadRequests(){
  try {const d=await apiJson("/api/requests");$("requests-list").innerHTML=d.requests.length?d.requests.map(r=>`<article class="request-card"><div><strong>#${r.id} · ${safeText(r.device_name)}</strong><span class="request-status ${safeText(r.status)}">${safeText(r.status)}</span></div><p>${safeText(r.device_ip)} · Requested by ${safeText(r.requested_by)}</p><p><b>Purpose:</b> ${safeText(r.purpose)}</p><p><b>Decision reason:</b> ${safeText(r.decision_reason || "Not decided yet")}</p>${r.status==="pending"?`<label>Reason (required)<input id="reason-${r.id}" placeholder="Explain why you accept or deny"></label><div class="request-actions"><button class="button primary" data-decision="accepted" data-id="${r.id}">Accept</button><button class="button secondary" data-decision="denied" data-id="${r.id}">Deny</button></div>`:""}</article>`).join(""):'<p class="muted">No requests yet. Create one from Wi-Fi Devices.</p>';
    $("requests-list").querySelectorAll("[data-decision]").forEach(btn=>btn.addEventListener("click",async()=>{const id=btn.dataset.id;const reason=$(`reason-${id}`).value.trim();if(!reason){alert("Explain why you accepted or denied this request.");return;}try{await apiJson(`/api/requests/${id}/decision`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({decision:btn.dataset.decision,reason})});await loadRequests();}catch(e){alert(e.message);}}));
  }catch(e){$("requests-list").textContent=e.message;}
}
$("refresh-requests").addEventListener("click",loadRequests);
async function loadAudit(){try{const d=await apiJson("/api/audit");$("audit-body").innerHTML=d.events.length?d.events.map(e=>`<tr><td>${safeText(e.created_at)}</td><td>${safeText(e.action)}</td><td>${safeText(e.details)}</td></tr>`).join(""):'<tr><td colspan="3" class="empty-cell">No audit events yet.</td></tr>';}catch(e){$("audit-body").innerHTML=`<tr><td colspan="3">${safeText(e.message)}</td></tr>`;}}
$("refresh-audit").addEventListener("click",loadAudit);
async function loadStorage(){try{const d=await apiJson("/api/storage/status");$("storage-status").innerHTML=`<p><b>Database:</b> ${safeText(d.database)}</p><p><b>File:</b> ${safeText(d.database_file)}</p><p><b>Cloud storage:</b> ${safeText(d.cloud_storage)}</p><p>${safeText(d.cloud_note)}</p>`;}catch(e){$("storage-status").textContent=e.message;}}
