"use strict";
const base = location.origin + "/auth/realms/course/protocol/openid-connect";
const redirect = location.origin + "/";
let accessToken = null, editId = null, offset = 0, canWrite = false;
const $ = id => document.getElementById(id);
const message = text => { $("status").textContent = text; };
const b64url = bytes => btoa(String.fromCharCode(...bytes)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const random = () => b64url(crypto.getRandomValues(new Uint8Array(32)));

$("login").onclick = async () => {
  const verifier=random(), state=random();
  sessionStorage.setItem("pkce",verifier); sessionStorage.setItem("oauth_state",state);
  const challenge=b64url(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier))));
  location.assign(base+"/auth?"+new URLSearchParams({client_id:"account-ui",redirect_uri:redirect,response_type:"code",scope:"openid profile",state,code_challenge:challenge,code_challenge_method:"S256"}));
};
$("logout").onclick = () => {accessToken=null;location.assign(base+"/logout?"+new URLSearchParams({client_id:"account-ui",post_logout_redirect_uri:redirect}));};

async function api(path,method="GET",data){
  const res=await fetch(path,{method,headers:{Authorization:"Bearer "+accessToken,...(data?{"Content-Type":"application/json"}:{})},body:data?JSON.stringify(data):undefined,cache:"no-store"});
  const body=await res.json();
  if(!res.ok)throw new Error(`${res.status}: ${body.error || "Ошибка"}${body.operation_id?" (операция "+body.operation_id+")":""}`);
  return body;
}
function cell(row,value){const td=document.createElement("td");td.textContent=String(value??"");row.append(td);return td;}
function action(parent,label,fn,danger=false){const b=document.createElement("button");b.textContent=label;if(danger)b.className="danger";b.onclick=()=>Promise.resolve().then(fn).catch(e=>message(e.message));parent.append(b);}
function reset(){editId=null;$("account").reset();$("account").elements.username.disabled=false;$("form-title").textContent="Создание учетной записи";}
async function load(){
  const data=await api("/api/users?first="+offset); $("users").replaceChildren();
  for(const user of data.items){
    const tr=document.createElement("tr");cell(tr,user.username);cell(tr,[user.firstName,user.lastName].filter(Boolean).join(" "));cell(tr,user.email);cell(tr,user.enabled?"Активна":"Заблокирована");
    if (canWrite) {
    const buttons=cell(tr,"");action(buttons,"Изменить",()=>{editId=user.id;const f=$("account");for(const key of ["username","firstName","lastName","email"])f.elements[key].value=user[key];f.elements.enabled.checked=user.enabled;f.elements.username.disabled=true;$("form-title").textContent="Изменение "+user.username;f.scrollIntoView({behavior:"smooth"});});
    action(buttons,user.enabled?"Заблокировать":"Активировать",async()=>{await api("/api/users/"+user.id,"PUT",{enabled:!user.enabled});await load();message("Состояние учетной записи изменено. Ранее выданный токен может действовать до 120 секунд.");});
    action(buttons,"Удалить",async()=>{if(!confirm("Безвозвратно удалить учебную учетную запись "+user.username+"?"))return;await api("/api/users/"+user.id,"DELETE");await load();message("Учетная запись удалена.");},true);
    }
    $("users").append(tr);
  }
  $("previous").disabled=offset===0;$("next").disabled=data.items.length<50;
}
$("account").onsubmit=async event=>{event.preventDefault();const f=event.currentTarget;const body={firstName:f.elements.firstName.value,lastName:f.elements.lastName.value,email:f.elements.email.value,enabled:f.elements.enabled.checked};if(!editId)body.username=f.elements.username.value;
  try{await api("/api/users"+(editId?"/"+editId:""),editId?"PUT":"POST",body);reset();await load();message("Изменение выполнено и записано в журнал.");}catch(e){message(e.message);}};
$("cancel").onclick=reset;$("reload").onclick=()=>load().catch(e=>message(e.message));
$("next").onclick=()=>{offset+=50;load().catch(e=>message(e.message));};$("previous").onclick=()=>{offset=Math.max(0,offset-50);load().catch(e=>message(e.message));};
$("audit").onclick=async()=>{try{const data=await api("/api/operations");$("operations").replaceChildren();for(const op of data.items){const tr=document.createElement("tr");cell(tr,op.created_at);cell(tr,op.action);cell(tr,op.target);cell(tr,op.status);$("operations").append(tr);}}catch(e){message(e.message);}};

(async()=>{
  const p=new URLSearchParams(location.search);if(!p.has("code")&&!p.has("error"))return;
  history.replaceState({},"",redirect);
  const expected=sessionStorage.getItem("oauth_state"), verifier=sessionStorage.getItem("pkce");sessionStorage.removeItem("oauth_state");sessionStorage.removeItem("pkce");
  if(p.get("error")){message("Вход отменен или отклонен.");return;}
  if(!expected||p.get("state")!==expected||!verifier){message("Проверка state не пройдена. Повторите вход.");return;}
  try{
    const response=await fetch(base+"/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"authorization_code",client_id:"account-ui",code:p.get("code"),redirect_uri:redirect,code_verifier:verifier})});
    if(!response.ok)throw new Error("Обмен кода отклонен");
    const tokens=await response.json();accessToken=tokens.access_token;
    const who=await api("/api/me");canWrite=who.can_write === true;$("account").hidden=!canWrite;$("form-title").hidden=!canWrite;document.querySelector("#workspace th:last-child").hidden=!canWrite;$("identity").textContent=who.username;$("workspace").hidden=false;$("login").hidden=true;$("logout").hidden=false;
    message("Вход выполнен. Токен действует 120 секунд; после истечения потребуется новый вход.");await load();
    setTimeout(()=>{accessToken=null;$("workspace").hidden=true;$("login").hidden=false;message("Срок токена истек. Войдите снова.");},Math.max(0,(tokens.expires_in-5)*1000));
  }catch(e){message(e.message);}
})();
