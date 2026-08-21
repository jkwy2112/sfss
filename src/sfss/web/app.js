const $ = (selector) => document.querySelector(selector);
const portal = location.pathname === "/green" ? "green" : location.pathname === "/red" ? "red" : location.pathname === "/admin" ? "admin" : "combined";
const state = { token: sessionStorage.getItem("sfss_token") || "", cookieSession: false, user: "", globalAdmin: false, approver: false, deploymentMode: "combined", generation: 0 };
const statusNames = {pending_scan:"待扫描",scanning:"扫描中",quarantined:"已隔离",released:"已放行",rejected:"已拒绝",expired:"已过期"};
const outboundStatusNames = {pending_scan:"待扫描",scanning:"扫描中",quarantined:"已隔离",classified:"已分类",pending_approval:"待审批",approved:"已批准",approval_rejected:"审批拒绝",released_to_green:"已放行至绿区",expired:"已过期"};
const actionNames = {"object.upload":"上传文件","object.list":"查看对象列表","object.download":"下载文件","object.read_metadata":"查看元数据","object.state_changed":"状态变化","outbound.list":"查看外发列表","outbound.upload":"外发上传","outbound.approval.decision":"外发审批","scan.complete":"扫描完成","scan.error":"扫描错误","session.login":"用户登录","session.logout":"用户退出","session.records_purged":"清理失效会话记录","service_token.expired":"服务令牌自动过期","audit.list":"查看审计","admin.overview":"管理总览","admin.config.read":"查看系统配置","admin.session.list":"查看活动会话","admin.session.revoke_user":"撤销用户会话","admin.session.revoke_all":"紧急撤销全部会话","admin.service_identity.create":"创建服务身份","admin.service_token.list":"查看服务令牌","admin.service_token.create":"签发服务令牌","admin.service_token.revoke":"撤销服务令牌","admin.user.create":"创建账号","admin.user.update":"更新账号","admin.user.approver":"变更审批员","admin.ldap_sync.read":"查看LDAP同步配置","admin.ldap_sync.config":"更新LDAP同步配置","admin.ldap_sync.run":"执行LDAP同步","outbound.policy.update":"更新外发策略","platform.network_policy.update":"更新IP策略","request.denied":"请求拒绝","upload.session.create":"创建分片上传","upload.session.read":"查看上传会话","upload.part.complete":"完成上传分片","upload.session.complete":"完成分片上传","upload.session.cancel":"取消分片上传"};

function toast(message){ const el=$("#toast"); el.textContent=message; el.classList.add("show"); clearTimeout(window.toastTimer); window.toastTimer=setTimeout(()=>el.classList.remove("show"),2600); }
async function api(path, options={}){
  const headers = new Headers(options.headers || {});
  if(state.token) headers.set("Authorization",`Bearer ${state.token}`);
  if(!state.token && !["GET","HEAD"].includes((options.method||"GET").toUpperCase()) && path!=="/v1/auth/login") headers.set("X-SFSS-CSRF","1");
  // 登录请求不带任何门户头:签发全门户通用的 development 会话。
  // 生产环境的入口绑定由可信网关(mTLS nginx 覆盖 X-SFSS-* 头)完成,与本前端无关。
  // 数据请求仍带 zone 头以维持"绿区上传/红区下载"的分区语义。
  const isLogin = path==="/v1/auth/login";
  if(!isLogin){
    if(portal==="green"||portal==="red") headers.set("X-SFSS-Zone",portal);
    if(portal==="admin") headers.set("X-SFSS-Gateway-Role","admin");
  }
  if(options.json){ headers.set("Content-Type","application/json"); options.body=JSON.stringify(options.json); }
  const response=await fetch(path,{...options,headers,credentials:"same-origin"});
  if(response.status===401){
    if(isLogin){ throw new Error("用户名或密码错误"); }
    // 会话已失效(退出/过期/撤销):干净登出。不再做入口探测——登录会话本就全门户通用。
    logout();
    throw new Error("登录已失效,请重新登录");
  }
  if(!response.ok){
    let data={}; try{data=await response.json()}catch{}
    if(response.status===403 && /platform administrator/.test(data.error||"")){
      logout(); throw new Error("当前账号不是平台管理员,请重新登录");
    }
    throw new Error(data.error || `请求失败 (${response.status})`);
  }
  return response.status===204 ? null : response.json();
}
async function downloadFile(path,record,zone){
  const headers={"X-SFSS-Zone":zone};if(state.token)headers.Authorization=`Bearer ${state.token}`;
  let handle=null;
  if("showSaveFilePicker" in window){
    handle=await window.showSaveFilePicker({suggestedName:record.filename});
  }else if(record.size>256*1024*1024){
    throw new Error("当前浏览器不支持大文件流式保存，请使用 sfss-agent 断点续传下载");
  }
  const response=await fetch(path,{headers});
  if(response.status===401){logout();throw new Error("登录已失效,请重新登录");}
  if(!response.ok){let data={};try{data=await response.json()}catch{}throw new Error(data.error||"下载失败");}
  if(!handle){
    const blob=await response.blob();const url=URL.createObjectURL(blob);const a=document.createElement("a");
    a.href=url;a.download=record.filename;document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);return;
  }
  if(!response.body)throw new Error("浏览器没有提供下载数据流");
  const writable=await handle.createWritable({keepExistingData:false});let received=0;
  try{
    const reader=response.body.getReader();
    while(true){const {done,value}=await reader.read();if(done)break;await writable.write(value);received+=value.byteLength;}
    if(received!==record.size)throw new Error(`下载不完整：预期 ${record.size} 字节，实际 ${received} 字节`);
    await writable.close();
  }catch(err){try{await writable.abort();}catch{}throw err;}
}
function showLogin(){
  $("#login-view").hidden=false; $("#app-view").hidden=true; clearLoginForm();
  resetWorkspaceLayout();
}
function resetWorkspaceLayout(){
  // 任何登录/退出边界都复位布局:主视图显示、管理视图隐藏、管理员入口按钮复位,
  // 防止上一身份渲染的管理后台内容在下一个身份页面里残留可见。
  const main=$("#main-view"),admin=$("#admin-view");
  if(admin){admin.hidden=true;if(admin.dataset.stocked!=="1"){admin.dataset.stocked="1";admin.dataset.original=admin.innerHTML;}}
  if(main) main.hidden=false;
  const back=$("#back-to-files"); if(back) back.hidden=true;
  const consoleBtn=$("#admin-console"); if(consoleBtn) consoleBtn.hidden=true;
}
function clearLoginForm(){ const form=$("#login-form"); if(form){ $("#username").value=""; $("#password").value=""; $("#login-error").hidden=true; } }
document.addEventListener("DOMContentLoaded",()=>{ const u=$("#username"); if(u){ u.setAttribute("autocomplete","off"); } });
function showApp(){ $("#login-view").hidden=true; $("#app-view").hidden=false; $("#current-user").textContent=state.user; renderSpaceCard(); resetWorkspaceLayout(); }
function logout(){
  state.generation++;   // 使所有在途回调携带的旧代失配,其响应不再渲染
  state.token=""; state.cookieSession=false; state.user=""; state.globalAdmin=false; state.approver=false;
  try{
    sessionStorage.removeItem("sfss_token");
    sessionStorage.setItem("sfss_logged_out","1");   // 显式墓碑:Safari bfcache/sessionStorage 恢复防御
    for(let i=localStorage.length-1;i>=0;i--){const k=localStorage.key(i);if(k&&k.startsWith("sfss-upload:"))localStorage.removeItem(k);}
  }catch{}
  showLogin();
}
async function performLogout(){
  // 用户主动退出:先立刻本地登出(清token、回登录页),再尽力通知服务端撤销会话。
  // 顺序反转后,即使服务端请求失败或页面导航,本地凭据不可能残留。
  const token=state.token; logout();
  if(token){
    const headers={Authorization:`Bearer ${token}`,"X-SFSS-CSRF":"1"};
    // 会话绑定签发入口:撤销请求必须带同样的门户头,否则服务端按入口不匹配拒绝,
    // 旧会话就会在服务端存活(曾导致切换账号后旧身份"复活")。
    if(portal==="green"||portal==="red") headers["X-SFSS-Zone"]=portal;
    if(portal==="admin") headers["X-SFSS-Gateway-Role"]="admin";
    try{await fetch("/v1/auth/logout",{method:"POST",headers});}catch{}
  }
}
function renderSpaceCard(){
  const card=$("#space-card");
  const badges=[];
  if(state.globalAdmin) badges.push("平台管理员");
  if(state.approver) badges.push("审批员");
  card.textContent=`${state.user}${badges.length?" · "+badges.join(" · "):""}`;
  card.title=state.user;
}
function applyPortalLayout(){
  if(portal==="green"){
    document.title="SFSS 绿区文件门户"; $("#portal-login-title").textContent="登录绿区文件门户";
  }else if(portal==="red"){
    document.title="SFSS 红区文件门户"; $("#portal-login-title").textContent="登录红区文件门户";
  }else if(portal==="admin"){
    document.title="SFSS 管理后台"; $("#portal-login-title").textContent="登录管理员后台";
  }
}
applyPortalLayout();

$("#login-form").addEventListener("submit",async event=>{
  event.preventDefault(); const error=$("#login-error"); error.hidden=true;
  try{ const result=await api("/v1/auth/login",{method:"POST",json:{username:$("#username").value,password:$("#password").value}}); clearLoginForm(); state.token=result.token||"";state.cookieSession=result.session_transport==="cookie";if(state.token)sessionStorage.setItem("sfss_token",state.token);else sessionStorage.removeItem("sfss_token"); const me=await api("/v1/me");sessionStorage.removeItem("sfss_logged_out");localStorage.setItem("sfss_session_epoch",String(Date.now()));state.generation++;state.user=me.username;state.globalAdmin=me.global_admin;state.approver=Boolean(me.approver);state.deploymentMode=me.deployment_mode||"combined";toast(`已登录:${state.user}${me.global_admin?"(平台管理员)":""}`);showApp(); await loadHealth(); await renderWorkspace(); }
  catch(err){ error.textContent=err.message; error.hidden=false; }
});
$("#logout").addEventListener("click",performLogout);

async function loadHealth(){ try{const health=await api("/health"); $("#scanner-state").textContent=health.status==="ok"?"服务在线":"服务异常";}catch{} }

async function renderWorkspace(){
  if(portal==="admin"&&!state.globalAdmin){
    renderAdminDenied();return;
  }
  $("#admin-console").hidden=!(state.globalAdmin&&(portal==="combined"||portal==="admin"));
  if(location.pathname==="/admin"&&state.globalAdmin){ await openAdmin(); return; }
  $("#admin-view").hidden=true; $("#main-view").hidden=false; $("#back-to-files").hidden=true;
  const mode=state.deploymentMode; const inboundAvailable=mode==="inbound"||mode==="combined"; const outboundAvailable=mode==="outbound"||mode==="combined";
  $("#files-tab-button").hidden=!inboundAvailable;
  $("#outbound-tab-button").hidden=!outboundAvailable;
  if(portal==="green"){
    $("#space-title").textContent=outboundAvailable&&!inboundAvailable?"我的已放行外发":"我的上传";
    $("#upload-form").hidden=!inboundAvailable;
    $("#object-table-title").textContent=inboundAvailable?"我的上传状态":"我的文件";
  }else if(portal==="red"){
    $("#space-title").textContent=inboundAvailable?"绿区放行缓冲区":"文件外发";
    $("#upload-form").hidden=true;
    $("#object-table-title").textContent="可下载文件";
  }else{
    $("#space-title").textContent="我的文件";
    $("#upload-form").hidden=!inboundAvailable;
  }
  $("#space-meta").textContent=`${state.user} · 系统模式：${mode==="inbound"?"绿区上传→红区下载":mode==="outbound"?"红区上传→外发审批":"全功能开发模式"} · 每人仅可见自己的文件`;
  $("#outbound-upload-form").hidden=!(portal==="red"||portal==="combined")||!outboundAvailable;
  if(inboundAvailable){ activateTab("files"); await loadObjects(); }
  else{ activateTab("outbound"); await loadOutbound(); }
}
function renderAdminDenied(){
  $("#admin-console").hidden=true;$("#back-to-files").hidden=true;
  $("#main-view").hidden=true;$("#admin-view").hidden=false;
  const view=$("#admin-view");
  if(view.dataset.denied!=="1"){
    view.dataset.denied="1";view.dataset.adminHtml=view.innerHTML;  // 保存原始后台DOM
    view.innerHTML="";
    const box=document.createElement("div");box.className="empty card";box.style.marginTop="8vh";
    const h=document.createElement("h2");h.textContent="无权访问管理后台";
    const p=document.createElement("p");p.className="subtle";
    p.textContent=`账号 ${state.user} 不是平台管理员。即将返回个人空间…`;
    const btn=document.createElement("button");btn.className="primary";btn.textContent="立即返回个人空间";
    btn.onclick=()=>location.replace("/");
    box.append(h,p,btn);view.append(box);
  }
  clearTimeout(window.adminDeniedTimer);
  window.adminDeniedTimer=setTimeout(()=>location.replace("/"),3000);
}
function restoreAdminView(){
  const view=$("#admin-view");
  if(view&&view.dataset.denied==="1"&&view.dataset.adminHtml){
    view.innerHTML=view.dataset.adminHtml;view.dataset.denied="";  // 恢复原始后台DOM(事件由loadAdmin重挂)
  }
}
function activateTab(name){document.querySelectorAll(".tab").forEach(button=>button.classList.toggle("active",button.dataset.tab===name));document.querySelectorAll(".tab-panel").forEach(panel=>panel.hidden=panel.id!==`tab-${name}`);}

async function openAdmin(){restoreAdminView();$("#main-view").hidden=true;$("#admin-view").hidden=false;$("#back-to-files").hidden=portal==="admin";await loadAdmin();}
$("#admin-console").onclick=openAdmin;
$("#back-to-files").onclick=async()=>{await renderWorkspace();};
$("#admin-refresh").onclick=async()=>{await loadAdmin();toast("管理员页面已刷新");};
document.querySelectorAll(".admin-tab").forEach(button=>button.onclick=()=>{document.querySelectorAll(".admin-tab").forEach(tab=>tab.classList.toggle("active",tab===button));document.querySelectorAll(".admin-page").forEach(page=>page.hidden=page.id!==`admin-page-${button.dataset.adminPage}`);});
async function loadAdmin(){
  const gen=state.generation;
  try{if(gen!==state.generation)return;const [data,config,serviceTokens,humanSessions]=await Promise.all([api("/v1/admin/overview"),api("/v1/admin/config"),api("/v1/admin/service-tokens"),api("/v1/admin/sessions")]);$("#metric-users").textContent=data.counts.users;$("#metric-objects").textContent=data.counts.objects;$("#metric-bytes").textContent=formatSize(data.counts.bytes);$("#metric-storage-available").textContent=formatSize(data.storage?.available_bytes||0);$("#metric-active-uploads").textContent=data.counts.active_uploads||0;$("#metric-staged-bytes").textContent=formatSize(data.counts.staged_bytes||0);$("#metric-scan-jobs").textContent=(data.queue?.queued||0)+(data.queue?.running||0);$("#metric-audit-chain").textContent=`已验证 ${data.audit_chain?.events||0} 条`;
    $("#config-retention").value=config.retention_hours;$("#config-upload").value=config.max_upload_mb;$("#config-chunk").value=config.multipart_chunk_mb;$("#config-upload-session").value=config.upload_session_hours;$("#config-active-uploads").value=config.max_active_uploads_per_user;$("#config-staged-gb").value=config.max_staged_gb_per_user;$("#config-min-free-gb").value=config.min_free_gb;$("#config-speed-limit").value=config.upload_speed_mbps??0;{const sel=$("#config-scanners");const known=[...sel.options].some(o=>o.value===config.scanners);if(!known){const opt=document.createElement("option");opt.value=config.scanners;opt.textContent=`当前自定义组合: ${config.scanners}`;sel.append(opt);}sel.value=config.scanners;}$("#config-clam-host").value=config.clamav_host;$("#config-clam-port").value=config.clamav_port;$("#config-clam-stream").value=config.clamav_stream_max_mb;$("#config-yara").value=config.yara_rules;$("#service-token-hours").max=config.service_token_max_hours;if(Number($("#service-token-hours").value)>config.service_token_max_hours)$("#service-token-hours").value=config.service_token_max_hours;
    const outboundAvailable=state.deploymentMode==="outbound"||state.deploymentMode==="combined";
    document.querySelectorAll("[data-outbound-only]").forEach(el=>el.hidden=!outboundAvailable);
    if(outboundAvailable) try{const policy=await api("/v1/admin/outbound-policy");$("#outbound-enabled").checked=Boolean(policy.enabled);const localOption=$("#outbound-provider").querySelector('option[value="local"]');localOption.disabled=!policy.local_approval_allowed;$("#outbound-provider").value=policy.approval_provider;$("#outbound-approval-hours").value=policy.approval_timeout_hours;$("#outbound-download-hours").value=policy.download_ttl_hours;document.querySelectorAll(".outbound-class").forEach(input=>input.checked=policy.allowed_classifications.includes(input.value));}catch{}
    try{const network=await api("/v1/admin/network-policy");$("#inbound-cidrs").value=network.inbound_upload_cidrs.join("\n");$("#outbound-cidrs").value=network.outbound_upload_cidrs.join("\n");}catch{}
    try{const ldap=await api("/v1/admin/ldap-sync");$("#ldap-sync-enabled").checked=Boolean(ldap.enabled);$("#ldap-sync-uri").value=ldap.uri||"";$("#ldap-sync-base").value=ldap.base_dn||"";$("#ldap-sync-bind-dn").value=ldap.bind_dn||"";$("#ldap-sync-password").value="";$("#ldap-sync-password").placeholder=ldap.bind_password_set?"已配置，留空保持不变":"";$("#ldap-sync-filter").value=ldap.user_filter||"";$("#ldap-sync-attr").value=ldap.username_attribute||"";$("#ldap-sync-group").value=ldap.approver_group_dn||"";$("#ldap-sync-deprovision").checked=Boolean(ldap.deprovision_missing);renderLdapSyncStatus(ldap.last_run);}catch{}
    const summary=$("#state-summary");summary.replaceChildren();Object.entries(statusNames).forEach(([key,label])=>{const item=document.createElement("div");item.className="state-item";const name=document.createElement("span");name.textContent=`入站 · ${label}`;const count=document.createElement("strong");count.textContent=data.states[key]||0;item.append(name,count);summary.append(item);});Object.entries(outboundStatusNames).forEach(([key,label])=>{const countValue=data.outbound_states?.[key]||0;if(!countValue)return;const item=document.createElement("div");item.className="state-item";const name=document.createElement("span");name.textContent=`外发 · ${label}`;const count=document.createElement("strong");count.textContent=countValue;item.append(name,count);summary.append(item);});
    const users=$("#admin-user-rows");users.replaceChildren();data.users.forEach(user=>{const tr=document.createElement("tr");const actions=document.createElement("td");if(user.principal_type==="service"){actions.append(actionButton(user.enabled?"停用":"启用",()=>updateServiceIdentity(user.username,!user.enabled),user.enabled));}else{actions.append(actionButton("重置密码",()=>resetUserPassword(user.username)));if(user.username!==state.user){actions.append(actionButton(user.enabled?"停用":"启用",()=>updateUser(user.username,{enabled:!user.enabled}),user.enabled));actions.append(actionButton(user.global_admin?"取消平台管理":"设为平台管理",()=>updateUser(user.username,{global_admin:!user.global_admin})));actions.append(actionButton(user.approver?"取消审批员":"设为审批员",()=>updateApprover(user.username,!user.approver)));}}const roleCell=document.createElement("td");const badges=[];if(user.global_admin)badges.push("平台管理员");if(user.approver)badges.push("审批员");roleCell.textContent=badges.length?badges.join(" · "):"—";tr.append(cell(user.username),cell(user.principal_type==="service"?"服务身份":"人员账号"),cell(user.enabled?"启用":"停用",user.enabled?"status-enabled":"status-disabled"),roleCell,cell(String(user.object_count||0)),actions);users.append(tr);});
    const tokenRows=$("#service-token-rows");tokenRows.replaceChildren();serviceTokens.tokens.forEach(token=>{const tr=document.createElement("tr");const status=token.revoked?"已撤销":token.expires_at<=Date.now()/1000?"已过期":"有效";const actions=document.createElement("td");if(!token.revoked&&token.expires_at>Date.now()/1000)actions.append(actionButton("撤销",()=>revokeServiceToken(token),true));else actions.textContent="—";tr.append(cell(token.label),cell(token.username),cell(`${token.zone} · ${token.permissions.join(", ")}`),cell(new Date(token.expires_at*1000).toLocaleString()),cell(token.last_used_at?new Date(token.last_used_at*1000).toLocaleString():"从未"),cell(status,status==="有效"?"status-enabled":"status-disabled"),actions);tokenRows.append(tr);});
    $("#session-policy-summary").textContent=`绝对 ${Math.floor(humanSessions.absolute_ttl_seconds/60)} 分钟 · 空闲 ${Math.floor(humanSessions.idle_ttl_seconds/60)} 分钟 · 每用户最多 ${humanSessions.max_per_user} 个`;
    const sessionRows=$("#admin-session-rows");sessionRows.replaceChildren();humanSessions.sessions.forEach(session=>{const tr=document.createElement("tr");const actions=document.createElement("td");actions.append(actionButton("撤销该用户全部会话",()=>revokeUserSessions(session.username),true));tr.append(cell(session.username),cell(session.auth_backend),cell(session.zone),cell(new Date(session.created_at*1000).toLocaleString()),cell(new Date(session.last_seen_at*1000).toLocaleString()),cell(new Date(session.expires_at*1000).toLocaleString()),actions);sessionRows.append(tr);});
    const objects=$("#admin-object-rows");objects.replaceChildren();const managedObjects=[...data.objects.map(item=>({...item,direction:"objects"})),...(data.outbound_objects||[]).map(item=>({...item,direction:"outbound"}))];managedObjects.forEach(object=>{const tr=document.createElement("tr");const status=document.createElement("td");const badge=document.createElement("span");badge.className=`badge ${object.state}`;badge.textContent=(object.direction==="outbound"?outboundStatusNames:statusNames)[object.state]||object.state;status.append(badge);const actions=document.createElement("td");if(object.state==="quarantined")actions.append(actionButton("重新扫描",()=>objectAction(object,"rescan")));const expirable=object.direction==="outbound"?["pending_scan","quarantined","pending_approval","approval_rejected","released_to_green"]:["released","quarantined","rejected"];if(expirable.includes(object.state))actions.append(actionButton("立即过期",()=>objectAction(object,"expire"),true));actions.append(detailButton(object,"文件扫描报告"));if(!actions.childNodes.length)actions.textContent="—";tr.append(cell(object.filename),cell(object.uploader),cell(`${object.direction==="outbound"?"外发":"入站"} · ${object.media_type}`),status,cell(formatSize(object.size)),actions);objects.append(tr);});
    const approvals=$("#admin-approval-rows");approvals.replaceChildren();(data.pending_approvals||[]).forEach(transfer=>{const tr=document.createElement("tr");const actions=document.createElement("td");actions.append(actionButton("批准",()=>decideOutboundTransfer(transfer,true)));actions.append(actionButton("拒绝",()=>decideOutboundTransfer(transfer,false),true));tr.append(cell(transfer.filename),cell(transfer.classification||"—"),cell(transfer.uploader),cell(transfer.approval_expires_at?new Date(transfer.approval_expires_at*1000).toLocaleString():"—"),actions);approvals.append(tr);});
    const renderEvents=(rowsSelector,list)=>{const rows=$(rowsSelector);rows.replaceChildren();list.forEach(event=>{const tr=document.createElement("tr");tr.append(cell(new Date(event.timestamp*1000).toLocaleString()),cell(event.actor),cell(actionNames[event.action]||event.action),cell(event.outcome),cell(event.source_zone),cell(event.object_id?event.object_id.slice(0,8):"—"));rows.append(tr);});};
    renderEvents("#admin-event-rows",data.events||[]);
    try{const audit=await api("/v1/admin/audit");renderEvents("#admin-audit-rows",audit.events||[]);}catch{}
  }catch(err){toast(err.message);}
}
function actionButton(label,handler,danger=false){const button=document.createElement("button");button.type="button";button.className=`secondary small-action${danger?" danger":""}`;button.textContent=label;button.onclick=handler;return button;}
$("#security-config-form").addEventListener("submit",async event=>{event.preventDefault();try{const result=await api("/v1/admin/config",{method:"PUT",json:{retention_hours:Number($("#config-retention").value),max_upload_mb:Number($("#config-upload").value),multipart_chunk_mb:Number($("#config-chunk").value),upload_session_hours:Number($("#config-upload-session").value),max_active_uploads_per_user:Number($("#config-active-uploads").value),max_staged_gb_per_user:Number($("#config-staged-gb").value),min_free_gb:Number($("#config-min-free-gb").value),upload_speed_mbps:Number($("#config-speed-limit").value),scanners:$("#config-scanners").value,clamav_host:$("#config-clam-host").value,clamav_port:Number($("#config-clam-port").value),yara_rules:$("#config-yara").value}});toast(result.restart_required?"生产配置已暂存：数据面已关闭，请完成变更审批、指纹、预检和重启":"安全与传输配置已保存并生效");await loadAdmin();}catch(err){toast(err.message);}});
$("#admin-user-form").addEventListener("submit",async event=>{event.preventDefault();try{await api("/v1/admin/users",{method:"POST",json:{username:$("#admin-new-user").value,password:$("#admin-new-password").value,global_admin:$("#admin-new-global").checked}});event.target.reset();toast("本地账号已创建");await loadAdmin();}catch(err){toast(err.message);}});
$("#service-identity-form").addEventListener("submit",async event=>{event.preventDefault();try{await api("/v1/admin/service-identities",{method:"POST",json:{username:$("#service-identity-user").value}});event.target.reset();toast("非交互服务身份已创建");await loadAdmin();}catch(err){toast(err.message);}});
async function updateServiceIdentity(username,enabled){try{await api(`/v1/admin/service-identities/${encodeURIComponent(username)}`,{method:"PUT",json:{enabled}});toast("服务身份状态已更新");await loadAdmin();}catch(err){toast(err.message);}}
$("#service-token-form").addEventListener("submit",async event=>{event.preventDefault();const permissions=[...document.querySelectorAll(".service-token-permission:checked")].map(input=>input.value);try{const result=await api("/v1/admin/service-tokens",{method:"POST",json:{label:$("#service-token-label").value,username:$("#service-token-user").value,zone:$("#service-token-zone").value,permissions,expires_hours:Number($("#service-token-hours").value)}});window.prompt("服务令牌仅显示一次，请立即复制到目标区域的秘密管理器：",result.token);event.target.reset();$("#service-token-hours").value=$("#service-token-hours").max;toast("服务令牌已签发");await loadAdmin();}catch(err){toast(err.message);}});
async function revokeServiceToken(token){if(!window.confirm(`撤销服务令牌“${token.label}”？`))return;try{await api(`/v1/admin/service-tokens/${token.id}`,{method:"DELETE"});toast("服务令牌已撤销");await loadAdmin();}catch(err){toast(err.message);}}
async function resetUserPassword(username){const password=window.prompt(`为 ${username} 设置新密码（至少 8 位）`);if(!password)return;try{await api(`/v1/admin/users/${encodeURIComponent(username)}`,{method:"PUT",json:{password}});toast("密码已重置");}catch(err){toast(err.message);}}
async function updateUser(username,changes){try{await api(`/v1/admin/users/${encodeURIComponent(username)}`,{method:"PUT",json:changes});toast("账号配置已更新");await loadAdmin();}catch(err){toast(err.message);}}
async function updateApprover(username,approver){try{await api(`/v1/admin/users/${encodeURIComponent(username)}/approver`,{method:"PUT",json:{approver}});toast(approver?"已授予平台审批员身份":"已取消审批员身份");await loadAdmin();}catch(err){toast(err.message);}}
$("#outbound-policy-form").addEventListener("submit",async event=>{event.preventDefault();const allowed=[...document.querySelectorAll(".outbound-class:checked")].map(input=>input.value);try{await api("/v1/admin/outbound-policy",{method:"PUT",json:{enabled:$("#outbound-enabled").checked,approval_provider:$("#outbound-provider").value,approval_timeout_hours:Number($("#outbound-approval-hours").value),download_ttl_hours:Number($("#outbound-download-hours").value),allowed_classifications:allowed}});toast("全局外发策略已保存");}catch(err){toast(err.message);}});
$("#network-policy-form").addEventListener("submit",async event=>{event.preventDefault();try{await api("/v1/admin/network-policy",{method:"PUT",json:{inbound_upload_cidrs:cidrLines("#inbound-cidrs"),outbound_upload_cidrs:cidrLines("#outbound-cidrs")}});toast("全局上传来源 IP 策略已保存");}catch(err){toast(err.message);}});
function renderLdapSyncStatus(lastRun){
  const box=$("#ldap-sync-status");
  if(!lastRun){box.hidden=true;return;}
  box.hidden=false;
  const when=new Date(lastRun.at*1000).toLocaleString();
  if(lastRun.status!=="ok"){$("#ldap-sync-status-text").textContent=`${when} · 失败：${lastRun.summary&&lastRun.summary.error?lastRun.summary.error:"未知错误"}`;return;}
  const s=lastRun.summary||{};
  $("#ldap-sync-status-text").textContent=`${when} · 成功：发现 ${s.users_seen||0} 个条目，同步 ${s.users_synced||0} 个用户，授予审批员 ${s.approvers_granted||0} 个，停用 ${s.disabled||0} 个，跳过非法用户名 ${s.skipped_invalid||0} 个，耗时 ${s.duration_ms||0}ms`;
}
$("#ldap-sync-form").addEventListener("submit",async event=>{event.preventDefault();try{
  const body={enabled:$("#ldap-sync-enabled").checked,uri:$("#ldap-sync-uri").value.trim(),base_dn:$("#ldap-sync-base").value.trim(),
    bind_dn:$("#ldap-sync-bind-dn").value.trim(),user_filter:$("#ldap-sync-filter").value.trim(),
    username_attribute:$("#ldap-sync-attr").value.trim(),approver_group_dn:$("#ldap-sync-group").value.trim(),
    deprovision_missing:$("#ldap-sync-deprovision").checked};
  if($("#ldap-sync-password").value)body.bind_password=$("#ldap-sync-password").value;
  const result=await api("/v1/admin/ldap-sync",{method:"PUT",json:body});
  $("#ldap-sync-password").value="";$("#ldap-sync-password").placeholder=result.bind_password_set?"已配置，留空保持不变":"";
  toast(result.production_staged?"LDAP 同步配置已保存（生产环境：已触发配置指纹漂移，需按变更流程完成指纹与重启）":"LDAP 同步配置已保存");
}catch(err){toast(err.message);}});
$("#ldap-sync-run").addEventListener("click",async event=>{event.preventDefault();const button=event.target;button.disabled=true;
  try{const summary=await api("/v1/admin/ldap-sync/run",{method:"POST"});
    toast(`同步完成：同步 ${summary.users_synced||0} 个用户，授予审批员 ${summary.approvers_granted||0} 个，停用 ${summary.disabled||0} 个`);
    try{const ldap=await api("/v1/admin/ldap-sync");renderLdapSyncStatus(ldap.last_run);}catch{}
  }catch(err){toast(`同步失败：${err.message}`);
    try{const ldap=await api("/v1/admin/ldap-sync");renderLdapSyncStatus(ldap.last_run);}catch{}
  }finally{button.disabled=false;}});
function cidrLines(selector){return $(selector).value.split(/[\n,]/).map(value=>value.trim()).filter(Boolean);}
async function revokeUserSessions(username){if(!window.confirm(`撤销 ${username} 的全部人工会话？该用户必须重新登录。`))return;try{await api(`/v1/admin/users/${encodeURIComponent(username)}/revoke-sessions`,{method:"POST",json:{confirmation:username}});if(username===state.user){logout();return;}toast("该用户的人工会话已全部撤销");await loadAdmin();}catch(err){toast(err.message);}}
$("#revoke-all-sessions").onclick=async()=>{const phrase=window.prompt("紧急操作会让所有人员立即重新登录。请输入：REVOKE ALL HUMAN SESSIONS");if(phrase!=="REVOKE ALL HUMAN SESSIONS")return;try{await api("/v1/admin/sessions/revoke-all",{method:"POST",json:{confirmation:phrase}});logout();}catch(err){toast(err.message);}};
async function objectAction(object,action){if(action==="expire"&&!window.confirm(`让文件“${object.filename}”立即过期？`))return;try{await api(`/v1/admin/${object.direction||"objects"}/${object.id}/${action}`,{method:"POST"});toast(action==="rescan"?"重新扫描已提交":"对象已过期");await loadAdmin();}catch(err){toast(err.message);}}
async function decideOutboundTransfer(transfer,approved){const comment=window.prompt(approved?"审批意见（批准）":"拒绝原因",approved?"同意外发":"不符合外发策略");if(comment===null)return;try{await api(`/v1/outbound/${transfer.id}/decision`,{method:"POST",json:{approved,comment}});toast(approved?"外发已批准并放行至绿区":"外发已拒绝");const inAdmin=!$("#admin-view").hidden;inAdmin?await loadAdmin():await loadOutbound();}catch(err){toast(err.message);}}

async function sha256Hex(blob){const bytes=await blob.arrayBuffer();const digest=await crypto.subtle.digest("SHA-256",bytes);return [...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,"0")).join("");}
async function multipartUpload(file,direction,progress){
  const key=`sfss-upload:${direction}:${state.user}:${file.name}:${file.size}:${file.lastModified}`;const zoneHeaders={"X-SFSS-Zone":direction==="inbound"?"green":"red"};let session;
  const saved=localStorage.getItem(key);
  if(saved){try{session=await api(`/v1/uploads/${saved}`,{headers:zoneHeaders});if(session.state!=="uploading")throw new Error("closed");}catch{localStorage.removeItem(key);session=null;}}
  if(!session){session=await api("/v1/uploads",{method:"POST",headers:zoneHeaders,json:{direction,filename:file.name,total_size:file.size}});localStorage.setItem(key,session.id);}
  const completed=new Set((session.parts||[]).map(part=>part.part_number));let next=1;let uploaded=session.received_bytes||0;progress(uploaded,file.size);
  async function putPartWithRetry(number,part,attempt=0){
    const hash=await sha256Hex(part);
    try{
      await api(`/v1/uploads/${session.id}/parts/${number}`,{method:"PUT",body:part,headers:{...zoneHeaders,"Content-Type":"application/octet-stream","X-Part-SHA256":hash}});
    }catch(err){
      if(attempt<2){await new Promise(r=>setTimeout(r,1000*(attempt+1)));return putPartWithRetry(number,part,attempt+1);}
      throw err;
    }
  }
  async function worker(){while(true){const number=next++;if(number>session.part_count)return;if(completed.has(number))continue;const start=(number-1)*session.chunk_size;const part=file.slice(start,Math.min(file.size,start+session.chunk_size));await putPartWithRetry(number,part);uploaded+=part.size;progress(uploaded,file.size);}}
  await Promise.all(Array.from({length:Math.min(2,session.part_count)},()=>worker()));
  const record=await api(`/v1/uploads/${session.id}/complete`,{method:"POST",headers:zoneHeaders});localStorage.removeItem(key);return record;
}
function makeProgressUI(boxId,file){
  const box=$(boxId);if(!box)return null;
  const name=$(boxId+"-name"),pct=$(boxId+"-pct"),fill=$(boxId+"-fill"),detail=$(boxId+"-detail"),speed=$(boxId+"-speed");
  box.hidden=false;name.textContent=file.name;pct.textContent="0%";fill.style.width="0%";detail.textContent=`0 MB / ${formatSize(file.size)}`;speed.textContent="";
  const t0=performance.now();let lastBytes=0,lastTime=t0;
  return (done,total)=>{
    const percent=total?Math.floor(done*100/total):0;
    pct.textContent=percent+"%";fill.style.width=Math.min(100,percent)+"%";
    detail.textContent=`${formatSize(done)} / ${formatSize(total)}`;
    const now=performance.now();
    if(now-lastTime>=800&&done>lastBytes){
      const mbps=((done-lastBytes)/1048576)/((now-lastTime)/1000);
      speed.textContent=`${mbps>=1?mbps.toFixed(1)+" MB/s":(mbps*1024).toFixed(0)+" KB/s"}`;
      lastBytes=done;lastTime=now;
    }
  };
}
$("#upload-form").addEventListener("submit",async event=>{event.preventDefault();const file=$("#file-input").files[0];if(!file)return;const button=event.submitter||event.target.querySelector("button");button.disabled=true;const progress=makeProgressUI("#upload-progress",file);try{await multipartUpload(file,"inbound",progress);event.target.reset();toast("上传完成，扫描任务已提交");$("#upload-progress").hidden=true;await loadObjects();}catch(err){toast(`上传中断:${err.message}。进度已保留,重新选择同一文件点上传即可断点续传`);$("#upload-progress").hidden=true;}finally{button.disabled=false;}});
$("#outbound-upload-form").addEventListener("submit",async event=>{event.preventDefault();const file=$("#outbound-file").files[0];if(!file)return;const button=event.submitter||event.target.querySelector("button");button.disabled=true;const progress=makeProgressUI("#outbound-progress",file);try{await multipartUpload(file,"outbound",progress);event.target.reset();toast("外发申请已提交");$("#outbound-progress").hidden=true;await loadOutbound();}catch(err){toast(`上传中断:${err.message}。进度已保留,重新选择同一文件点上传即可断点续传`);$("#outbound-progress").hidden=true;}finally{button.disabled=false;}});

async function loadOutbound(){
  const gen=state.generation;
  try{const data=await api("/v1/outbound");if(gen!==state.generation)return;const rows=$("#outbound-rows");rows.replaceChildren();
  data.transfers.filter(transfer=>portal!=="green"||transfer.state==="released_to_green").forEach(transfer=>{
    const tr=document.createElement("tr");const file=document.createElement("td");file.className="file-cell";
    const strong=document.createElement("strong");strong.textContent=transfer.filename;
    const small=document.createElement("small");small.textContent=transfer.sha256.slice(0,12)+"…";file.append(strong,small);
    const status=document.createElement("td");const badge=document.createElement("span");badge.className=`badge ${transfer.state}`;badge.textContent=outboundStatusNames[transfer.state]||transfer.state;status.append(badge);
    const actions=document.createElement("td");
    const canDecide=(portal==="combined"||portal==="admin")&&transfer.state==="pending_approval"&&(state.approver||state.globalAdmin);
    if(canDecide){actions.append(actionButton("批准",()=>decideOutboundTransfer(transfer,true)));actions.append(actionButton("拒绝",()=>decideOutboundTransfer(transfer,false),true));}
    if(portal!=="red"&&transfer.state==="released_to_green"&&transfer.uploader===state.user)actions.append(actionButton("绿区下载",()=>downloadOutbound(transfer)));
    actions.append(detailButton(transfer,"外发扫描报告"));
    if(!actions.childNodes.length)actions.textContent="—";
    const expiry=transfer.download_expires_at||transfer.approval_expires_at;
    tr.append(file,cell(transfer.classification||"—"),status,cell(transfer.uploader),cell(transfer.approval_actor||"—"),cell(expiry?new Date(expiry*1000).toLocaleString():"—"),actions);rows.append(tr);});
  }catch(err){toast(err.message);}
}
$("#outbound-refresh").onclick=loadOutbound;

function formatSize(bytes){if(bytes<1024)return `${bytes} B`;if(bytes<1048576)return `${(bytes/1024).toFixed(1)} KB`;return `${(bytes/1048576).toFixed(1)} MB`;}
function cell(text,className){const td=document.createElement("td");td.textContent=text;if(className)td.className=className;return td;}
const scannerNames={clamav:"ClamAV 病毒扫描",mock:"开发模拟扫描器",yara:"YARA 规则",integrity:"完整性校验","post-scan-integrity":"扫描后完整性",pipeline:"扫描管线","runtime-policy":"运行时策略",classifier:"内容分类"};
function formatScanDetail(raw){
  let results=[];try{results=typeof raw==="string"?JSON.parse(raw):(raw||[])}catch{return String(raw||"—")}
  if(!results.length)return "暂无扫描记录";
  return results.map(r=>`${scannerNames[r.scanner]||r.scanner}:${r.status}${r.detail?`(${r.detail})`:""}`).join("\n");
}
function showScanDetail(title,record){
  const lines=[`文件:${record.filename}`,`状态:${(statusNames[record.state]||outboundStatusNames[record.state]||record.state)}`,
    `SHA-256:${record.sha256}`,`大小:${formatSize(record.size)}`,"",formatScanDetail(record.scan_detail)];
  window.alert(`${title}\n\n${lines.join("\n")}`);
}
function detailButton(record,title){
  const button=document.createElement("button");button.type="button";button.className="secondary small-action";
  button.textContent="报告";button.title="查看扫描报告";button.onclick=()=>showScanDetail(title||"扫描报告",record);return button;
}
async function loadObjects(){ const gen=state.generation; try{const data=await api("/v1/objects");if(gen!==state.generation)return;const visible=data.objects.filter(obj=>portal!=="red"||obj.state==="released");$("#object-count").textContent=`${visible.length} 个对象`;const rows=$("#object-rows");rows.replaceChildren();visible.forEach(obj=>{const tr=document.createElement("tr");const fileTd=document.createElement("td");fileTd.className="file-cell";const strong=document.createElement("strong");strong.textContent=obj.filename;const small=document.createElement("small");small.textContent=new Date(obj.created_at*1000).toLocaleString();fileTd.append(strong,small);tr.append(fileTd,cell(obj.media_type),cell(obj.sha256.slice(0,12)+"…","hash"));const statusTd=document.createElement("td");const badge=document.createElement("span");badge.className=`badge ${obj.state}`;badge.textContent=statusNames[obj.state]||obj.state;statusTd.append(badge);tr.append(statusTd,cell(formatSize(obj.size)));const action=document.createElement("td");action.append(detailButton(obj,"文件扫描报告"));if(portal==="red"&&obj.state==="released"){const button=document.createElement("button");button.className="secondary download";button.textContent="下载";button.onclick=()=>downloadObject(obj);action.append(button);}tr.append(action);rows.append(tr);});}catch(err){toast(err.message);} }
async function downloadObject(obj){try{await downloadFile(`/v1/objects/${obj.id}/download`,obj,"red");toast("红区下载完成");}catch(err){if(err.name!=="AbortError")toast(err.message);}}
async function downloadOutbound(transfer){try{await downloadFile(`/v1/outbound/${transfer.id}/download`,transfer,"green");toast("绿区下载完成");}catch(err){if(err.name!=="AbortError")toast(err.message);}}

document.querySelectorAll(".tab").forEach(button=>button.onclick=async()=>{document.querySelectorAll(".tab").forEach(b=>b.classList.toggle("active",b===button));document.querySelectorAll(".tab-panel").forEach(panel=>panel.hidden=panel.id!==`tab-${button.dataset.tab}`);if(button.dataset.tab==="outbound")await loadOutbound();if(button.dataset.tab==="files")await loadObjects();});
$("#refresh").onclick=async()=>{if(!$("#tab-outbound").hidden)await loadOutbound();else await loadObjects();toast("状态已刷新");};

window.addEventListener("storage",event=>{
  if(event.key==="sfss_session_epoch"&&state.token){
    // 另一标签页发生了新登录:本页旧身份作废,防止多身份并存/来回显示
    logout();
  }
});
(async()=>{
  // 显式登出墓碑优先于任何残留 token(浏览器缓存恢复防御)
  try{ if(sessionStorage.getItem("sfss_logged_out")==="1"){ state.token=""; sessionStorage.removeItem("sfss_token"); } }catch{}
  if(!state.token){ showLogin(); return; }
  try{
    const me=await api("/v1/me");   // development 会话全门户通用,无需任何入口探测
    sessionStorage.removeItem("sfss_logged_out");
    state.cookieSession=false; state.generation++;
    state.user=me.username; state.globalAdmin=me.global_admin;
    state.approver=Boolean(me.approver); state.deploymentMode=me.deployment_mode||"combined";
    showApp(); await loadHealth(); await renderWorkspace();
  }catch{ showLogin(); }
})();
