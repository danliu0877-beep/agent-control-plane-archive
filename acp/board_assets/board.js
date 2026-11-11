'use strict';
let state=null,csrf=null,pending=null,busy=false;
const $=id=>document.getElementById(id);
function node(tag,text,cls){const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(cls)e.className=cls;return e;}
function detail(title,value){
 const d=node('details');d.append(node('summary',title));
 if(title==='Immutable activity timeline'){
  const list=node('ol');
  const names={STATE:'WorkItem state changed',PLAN_STATE:'Execution state changed',RETRY_AUTHORIZED:'Fresh retry authorized',VM_FENCED:'VM fenced; prior output quarantined',REVIEW_PREPARED:'Independent review prepared',REVIEW_ACCEPTED:'ACP accepted exact criteria',REVIEW_REWORK_REQUIRED:'Independent review requires bounded repair',SLOT_RELEASED_FENCED:'Fenced worker capacity released',HUMAN_GATE:'Principal decision required',HUMAN_RESOLVED:'Named human gate resolved'};
  for(const event of value){
   const label=event.kind==='OPERATION_COMPLETED'?'VM '+(event.detail?.operation||'operation')+' independently observed':names[event.kind]||event.kind.replaceAll('_',' ').toLowerCase();
   list.append(node('li',new Date(event.at).toLocaleString()+' · '+label+' '+(event.detail?.reason||'')));
  }
  d.append(list);
 }else if(title==='Independent review / full criteria coverage'){
  d.append(node('p','Generation '+value.generation+' · reviewer '+(value.reviewer_verdict||value.state)+' · ACP '+value.acp_decision));
  for(const criterion of value.criteria){
   const coverage=value.coverage?.[criterion.id];
   const label=criterion.criterion.description||criterion.criterion.observable||criterion.validator;
   const sources=value.manifest.filter(m=>coverage?.evidence?.includes(m.id));
   d.append(node('p',criterion.level+' · '+(coverage?.result||'NOT VERIFIED')+' — '+label));
   d.append(node('small','Evidence: '+(sources.map(m=>m.class+' / '+m.trust).join('; ')||'none independently mapped')));
  }
  const raw=node('details');raw.append(node('summary','Exact canonical identities / criterion mapping'),node('pre',JSON.stringify(value,null,2)));d.append(raw);
 }else d.append(node('pre',JSON.stringify(value,null,2)));
 return d;
}
function card(title,text,cls=''){const e=node('article',undefined,'card '+cls);e.append(node('h3',title==='NEEDS_HUMAN'?'Needs Human':title));if(text)e.append(node('p',text));return e;}
async function api(url,value){const res=await fetch(url,{method:value?'POST':'GET',headers:value?{'Content-Type':'application/json','X-ACP-CSRF':csrf}:{},body:value?JSON.stringify(value):undefined,cache:'no-store'});const data=await res.json();if(!res.ok)throw Error(data.error||'Control-plane unavailable');return data;}
const names={intake:'送入新目標',load_context:'載入 primary project 的 bounded context',prepare_plan:'選擇 context 並準備 planning',accept_plan:'Principal 明確接受 Plan',resolve_gate:'Resolve named gate',reject_work:'拒絕此 WorkItem',cancel_work:'取消此 WorkItem disposition',revoke_review:'撤銷 bounded review/retry delegation',supplement:'補充既有 bounded evidence',enroll_review:'授權 exact review mapping'};
async function confirmAction(action,payload){if(busy||!state)return;busy=true;try{pending=await api('/api/confirm',{action,payload,version:state.version});$('packet').textContent=JSON.stringify(pending.packet,null,2);$('confirm').showModal();}catch(e){$('notice').textContent='未套用：'+e.message;busy=false;await refresh();}}
function actionForm(c){
 const e=card(names[c.action]||c.action,c.effect);
 e.append(node('small',c.label||c.target));
 const form=node('form'),fields={},choices=[];
 for(const [k,v] of Object.entries(c.payload||{})){
  if(['reason','budget','expires_at'].includes(k)){
   const l=node('label',k),inp=node('input');inp.value=String(v);
   if(k==='budget'){inp.type='number';inp.min=0;inp.max=2;}
   if(k==='expires_at')inp.placeholder='2099-01-01T00:00:00+00:00';
   l.append(inp);form.append(l);fields[k]=inp;
  }
 }
 for(const choice of c.evidence_choices||[]){
  const label=node('label',choice.class+' · '+choice.trust+' · '+choice.collector);
  const box=node('input');box.type='checkbox';label.prepend(box);form.append(label);choices.push({box,id:choice.id});
 }
 const button=node('button','檢視 exact action 摘要');
 if(c.action==='supplement'&&!choices.length){button.disabled=true;form.append(node('p','目前沒有新增的 bounded persisted evidence；請使用既有 controller 收集流程，不會讀任意檔案。'));}
 form.append(button);
 form.addEventListener('submit',ev=>{
  ev.preventDefault();const p=structuredClone(c.payload);
  for(const [k,i]of Object.entries(fields))p[k]=k==='budget'?Number(i.value):i.value;
  if(c.action==='supplement')p.evidence.push(...choices.filter(x=>x.box.checked).map(x=>x.id));
  confirmAction(c.action,p);
 });
 e.append(form);
 if(c.payload?.mapping)e.append(detail('Exact full criteria mapping',c.payload.mapping));
 return e;
}
function render(){for(const id of ['counts','inbox','projects','plans','actions','providers','resolutions','proposals','tasks'])$(id).replaceChildren();$('capability').textContent=state.capability;
 for(const t of state.tasks){const e=card(t.project_id+' · '+t.state,t.title,t.unknown?'blocked':t.state==='NEEDS_HUMAN'?'human':'');e.append(node('p',t.meaning));if(t.reason)e.append(node('p',t.reason));if(t.attempt_state)e.append(node('p','Attempt: '+t.attempt_state));e.append(detail('Exact task identity',t));$('tasks').append(e);}
 for(const label of ['NEEDS_HUMAN','BLOCKED','RUNNING','REVIEW','READY / QUEUED','DONE / ACCEPTED','WAITING']){const e=card(label,null,label==='NEEDS_HUMAN'?'human':label==='BLOCKED'?'blocked':'');e.append(node('strong',state.counts[label]||0,'metric'));$('counts').append(e);}
 if(!state.needs_human.length)$('inbox').append(node('p','目前沒有需要 Principal 判斷的 gate；這不代表 plan 已被明確接受。'));
 for(const i of state.needs_human){const e=card(i.state+' · '+(i.project||'Project resolution'),i.summary,i.unknown?'blocked':'human');e.append(node('p','Reason: '+JSON.stringify(i.reason||i.candidates)));e.append(node('p','Retry '+(i.retry_count||0)+' / '+(i.retry_budget||0)+' · Blocked descendants: '+JSON.stringify(i.remaining_blocked||[])));e.append(detail('Decision packet / affected objects',i));const acts=state.actions.filter(c=>c.target===i.work||c.target===i.task);if(!acts.length)e.append(node('p','沒有可安全套用的網頁操作。需 exact reconciliation / 新 contract 或 CLI；不提供強制通過。'));for(const c of acts)e.append(actionForm(c));$('inbox').append(e);}
 const selected=$('project').value;$('project').replaceChildren(node('option','自動 resolver；ambiguous 時不猜測'));$('project').firstChild.value='';for(const p of state.projects){const opt=node('option',p.name+' · '+p.id);opt.value=p.id;$('project').append(opt);const e=card(p.name,p.resolution_status+' · '+p.health);e.append(node('p','Active '+p.active_work+' · Human gates '+p.human_gates));e.append(detail('Registry identity / latest execution',p));$('projects').append(e);}$('project').value=selected;
 for(const p of state.plans){const e=card(p.project+' · '+p.state,null,p.state==='COMPLETE'?'complete':'');e.append(node('p',p.plan_id+' revision '+p.revision+' · concurrency '+p.capacity+' · available '+p.available_capacity));e.append(node('p','Plan explicit acceptance: '+(p.plan_accepted?'ACCEPTED':'NOT ACCEPTED')+' — '+p.plan_acceptance));const dag=node('div',undefined,'dag');const ordinal=Object.fromEntries(p.nodes.map(n=>[n.id,n.ordinal]));for(const n of p.nodes){const w=card('#'+n.ordinal+' · '+n.display_state,n.objective,n.unknown?'blocked':n.state==='NEEDS_HUMAN'?'human':n.state==='ACCEPTED'?'complete':'');w.append(node('p','Depends on: '+(n.dependencies.map(d=>'#'+ordinal[d]).join(', ')||'none / root')));w.append(node('p','Retry '+n.retry_count+'/'+n.retry_budget+' · worker capacity '+(n.capacity_reserved?'RESERVED':'not held')));if(n.unknown)w.append(node('p',n.explanation));for(const g of n.generations){w.append(node('p','Generation '+g.generation+' → '+g.state+' · VM '+(g.vm?.slice(0,16)||'not allocated')+' · '+(g.quarantined?'QUARANTINED':'current receipt')));w.append(detail('Attempt / fencing / bounded evidence',g));}for(const r of n.reviews){w.append(node('p','Reviewer '+(r.reviewer_verdict||r.state)+' ≠ ACP '+r.acp_decision));w.append(detail('Independent review / full criteria coverage',r));}w.append(detail('Blocking / human assessment',{reason:n.reason,human_assessment:n.human_assessment}));dag.append(w);}e.append(dag,detail('Policy / provenance',{created:p.created,provenance:p.provenance,review:p.review_policy,retry:p.retry_policy}),detail('Retry lineage — prior generations retained',p.retries),detail('Immutable activity timeline',p.timeline));$('plans').append(e);}
 for(const r of state.resolutions)$('resolutions').append(detail(r.outcome+' · '+r.request,r));
 for(const p of state.proposals){const e=card(p.primary_project+' · '+p.status,'PlanRevision '+p.plan_id+' / '+p.plan_revision);for(const w of p.work_items||[])e.append(node('p',w.objective+' · risk '+w.execution_risk+' · proposed (unauthorized) write scope '+JSON.stringify(w.proposed_write_scope)));e.append(detail('DAG / human assessment / source acceptance',p));$('proposals').append(e);}
 for(const c of state.actions.filter(c=>c.action!=='intake'))$('actions').append(actionForm(c));$('providers').append(detail('Provider readiness / UNKNOWN outcomes',state.provider_status));$('providers').append(node('p','Validated worker: VMware · headless · synthetic · no NIC · bounded transport · M08 isolation/fencing. Real project/production workers NOT AVAILABLE.'));
}
async function refresh(){if(busy)return;try{state=await api('/api/state');render();$('status').className='';$('status').textContent='已讀取 canonical SQLite · '+new Date().toLocaleTimeString();}catch(e){state=null;for(const id of ['counts','inbox','projects','plans','actions','providers','proposals','tasks','resolutions'])$(id).replaceChildren();$('status').className='error';$('status').textContent='Control-plane unavailable：'+e.message;}}
$('refresh').onclick=refresh;$('intake').onsubmit=e=>{e.preventDefault();if(state)confirmAction('intake',{request:$('goal').value,project:$('project').value});};$('dismiss').onclick=()=>{$('confirm').close();pending=null;busy=false;refresh();};$('confirm').addEventListener('cancel',()=>{pending=null;busy=false;});$('apply').onclick=async()=>{if(!pending)return;$('apply').disabled=true;try{const result=await api('/api/command',{confirmation:pending.confirmation});$('notice').textContent=JSON.stringify(result);}catch(e){$('notice').textContent='未確認套用：'+e.message;}finally{pending=null;busy=false;$('apply').disabled=false;$('confirm').close();await refresh();}};
api('/api/session').then(s=>{csrf=s.csrf;return refresh();}).catch(e=>{$('status').textContent=e.message;});setInterval(()=>{if($('poll').checked&&!busy)refresh();},10000);
