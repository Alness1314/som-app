import { app, BrowserWindow, ipcMain, shell, dialog, session, type WebFrameMain } from 'electron';
import { spawn, ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
let backend: ChildProcess | undefined; let port=0; let runtimeDataDir=''; const token=randomBytes(32).toString('hex');
const deviceConsoleWindows=new Map<number,{window:BrowserWindow;origin:string}>();
const firewallBackupRuns=new Set<number>();
app.setName('SOM');
if(!app.isPackaged){const envFile=path.resolve(process.cwd(),'.env');if(fs.existsSync(envFile))process.loadEnvFile(envFile);}
async function freePort():Promise<number>{return new Promise((resolve,reject)=>{const s=createServer();s.once('error',reject);s.listen(0,'127.0.0.1',()=>{const p=(s.address() as {port:number}).port;s.close(()=>resolve(p));});});}
async function startBackend(){
 port=await freePort();
 const exe=app.isPackaged?path.join(process.resourcesPath,'backend','som-backend.exe'):path.resolve('backend/.venv/Scripts/python.exe');
 const py=app.isPackaged?exe:process.env.SOM_PYTHON||exe;
 const args=app.isPackaged?[]:['-m','uvicorn','som_api.main:app','--host','127.0.0.1','--port',String(port)];
 runtimeDataDir=process.env.SOM_DATA_DIR?path.resolve(process.env.SOM_DATA_DIR):path.join(app.getPath('userData'),'data');
 backend=spawn(py,args,{cwd:app.isPackaged?path.dirname(exe):path.resolve('backend'),windowsHide:true,stdio:app.isPackaged?'ignore':'inherit',env:{...process.env,SOM_PORT:String(port),SOM_TOKEN:token,SOM_DATA_DIR:runtimeDataDir}});
 backend.on('exit',()=>{backend=undefined;});
 await new Promise<void>((resolve,reject)=>{const timeout=setTimeout(()=>reject(new Error('El proceso backend no inició a tiempo.')),10000);backend!.once('spawn',()=>{clearTimeout(timeout);resolve()});backend!.once('error',error=>{clearTimeout(timeout);reject(error)})});
 const deadline=Date.now()+15000;
 while(Date.now()<deadline){
  if(!backend||backend.exitCode!==null)throw new Error('El backend terminó durante el arranque. Revisa la instalación Python y sus dependencias.');
  try{const response=await fetch(`http://127.0.0.1:${port}/api/health`,{signal:AbortSignal.timeout(700)});if(response.ok)return}catch{}
  await new Promise(resolve=>setTimeout(resolve,200));
 }
 throw new Error('FastAPI no respondió dentro del tiempo de inicio.');
}
function makeWindow(){const win=new BrowserWindow({width:1440,height:920,minWidth:1000,minHeight:680,backgroundColor:'#0b1118',webPreferences:{preload:path.join(__dirname,'preload.js'),contextIsolation:true,nodeIntegration:false,sandbox:true}});win.webContents.setWindowOpenHandler(({url})=>{if(url.startsWith('https://')) void shell.openExternal(url);return {action:'deny'};});win.webContents.on('will-navigate',(e,url)=>{const allowed=app.isPackaged?url.startsWith('file://'):url.startsWith('http://127.0.0.1:5173');if(!allowed)e.preventDefault();});if(process.env.SOM_DEV)void win.loadURL('http://127.0.0.1:5173');else void win.loadFile(path.resolve('dist/index.html'));}
const allowedApiPath=/^\/api\/(health|dashboard|checks|audit|devices(?:\/\d+(?:\/(?:check|credentials)?)?)?|backups(?:\/(?:import|manifest|\d+(?:\/(?:contents|archives\/\d+(?:\.\d+)*|entries\/\d+(?:\.\d+)*|analysis))?))?|activities|settings\/(?:storage|backup-schedule(?:\/claim)?))$/;
async function fillSavedDeviceLogin(win:BrowserWindow,deviceId:number){
 try{
  const response=await fetch(`http://127.0.0.1:${port}/api/devices/${deviceId}/credentials/automation`,{headers:{'X-SOM-Token':token}});
  if(response.status===404)return;
  if(!response.ok)throw new Error(`El almacén respondió HTTP ${response.status}`);
  const credentials=await response.json() as {username:string;password:string};
  const serialized=JSON.stringify(credentials);
  let result='no_login_form';
  for(let attempt=0;attempt<5&&result==='no_login_form';attempt++){
   if(attempt>0)await new Promise(resolve=>setTimeout(resolve,700));
   result=await win.webContents.executeJavaScript(`(()=>new Promise(resolve=>{
   const data=${serialized};
   const visible=element=>!!(element.offsetWidth||element.offsetHeight||element.getClientRects().length)&&getComputedStyle(element).visibility!=='hidden';
   const inputs=Array.from(document.querySelectorAll('input')).filter(input=>visible(input)&&!['hidden','submit','button','checkbox','radio'].includes((input.type||'text').toLowerCase()));
   const passwords=inputs.filter(input=>(input.type||'').toLowerCase()==='password');
   if(passwords.length===0)return resolve('no_login_form');
   if(passwords.length!==1)return resolve('login_form_not_recognized');
   const password=passwords[0];
   const candidates=inputs.filter(input=>input!==password&&(input.type||'text').toLowerCase()!=='password'&&/user|account|login|email|username|usuario|cuenta/i.test([input.name,input.id,input.placeholder,input.getAttribute('aria-label'),input.autocomplete].join(' ')));
   const fallback=inputs.filter(input=>input!==password&&(input.type||'text').toLowerCase()!=='password');
   const username=candidates.length===1?candidates[0]:(candidates.length===0&&fallback.length===1?fallback[0]:null);
   if(!username)return resolve('login_form_not_recognized');
   const setValue=(element,value)=>{const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;setter.call(element,value);element.dispatchEvent(new Event('input',{bubbles:true}));element.dispatchEvent(new Event('change',{bubbles:true}))};
   setValue(username,data.username);setValue(password,data.password);
   const form=password.form||username.form;
   const buttons=Array.from((form||document).querySelectorAll('button,input[type="submit"]')).filter(visible);
   const loginButtons=buttons.filter(button=>{const label=('innerText' in button?button.innerText:button.value||button.getAttribute('aria-label')||'').trim();return /^(log\s*in|login|sign\s*in|iniciar sesión|entrar|登录)$/i.test(label)});
   if(loginButtons.length===1){loginButtons[0].click();return resolve('submitted')}
   if(form&&typeof form.requestSubmit==='function'){form.requestSubmit();return resolve('submitted')}
   return resolve('filled_no_submit');
   }))()`,true) as string;
  }
  if(result==='login_form_not_recognized'||result==='filled_no_submit')console.warn(`[SOM] No se pudo enviar el inicio de sesión guardado para el dispositivo ${deviceId}: formulario no reconocido.`);
 }catch(error){
  const message=error instanceof Error?error.message:String(error);
  console.warn(`[SOM] No se pudo usar el inicio de sesión guardado para el dispositivo ${deviceId}: ${message}`);
 }
}
ipcMain.handle('som:api-request',async(_event,route:string,options:{method?:string;body?:string}={})=>{
 if(typeof route!=='string'||route.includes('..')||!allowedApiPath.test(route))throw new Error('Ruta API no permitida');
 const method=options?.method??'GET';
 if(!['GET','POST','PUT','DELETE'].includes(method))throw new Error('Método API no permitido');
 const body=options?.body;
 if(body!==undefined&&(typeof body!=='string'||body.length>1_048_576))throw new Error('Cuerpo de solicitud inválido o demasiado grande');
 if(body!==undefined){try{JSON.parse(body)}catch{throw new Error('El cuerpo debe ser JSON válido')}}
 const target=new URL(route,`http://127.0.0.1:${port}`);
 const response=await fetch(target,{method,headers:{'X-SOM-Token':token,...(body!==undefined?{'Content-Type':'application/json'}:{})},...(body!==undefined?{body}:{})});
 return {status:response.status,body:await response.text()};
});
ipcMain.handle('som:health',async()=>{try{const response=await fetch(`http://127.0.0.1:${port}/api/health`);return response.ok}catch{return false}});
ipcMain.handle('som:select-files',async()=>{const r=await dialog.showOpenDialog({properties:['openFile','multiSelections']});return r.canceled?[]:r.filePaths;});
ipcMain.handle('som:select-directory',async()=>{const r=await dialog.showOpenDialog({properties:['openDirectory','createDirectory']});return r.canceled?null:r.filePaths[0]??null;});
ipcMain.handle('som:download-backup',async(_event,backupId:number)=>{
 if(!Number.isSafeInteger(backupId)||backupId<1)throw new Error('Identificador de respaldo inválido');
 const response=await fetch(`http://127.0.0.1:${port}/api/backups/${backupId}/internal-file`,{headers:{'X-SOM-Token':token}});
 const result=await response.json() as {path?:string;filename?:string;detail?:string};
 if(!response.ok||!result.path||!result.filename)throw new Error(result.detail||'No se pudo localizar el ZIP registrado');
 const filename=path.basename(result.filename);
 const selected=await dialog.showSaveDialog({defaultPath:filename,filters:[{name:'Archivo ZIP',extensions:['zip']}]});
 if(selected.canceled||!selected.filePath)return {canceled:true};
 const stat=await fs.promises.lstat(result.path);
 if(!stat.isFile()||stat.isSymbolicLink())throw new Error('El ZIP registrado ya no está disponible como archivo seguro');
 await fs.promises.copyFile(result.path,selected.filePath);
 return {canceled:false,path:selected.filePath};
});
ipcMain.handle('som:open-external',async(_e,url:string)=>{if(typeof url!=='string'||!/^https:\/\//i.test(url))throw new Error('Solo se permiten URLs HTTPS');await shell.openExternal(url);});
async function openDeviceConsole(deviceId:number):Promise<BrowserWindow>{
 if(!Number.isSafeInteger(deviceId)||deviceId<1)throw new Error('Identificador de dispositivo inválido');
 const response=await fetch(`http://127.0.0.1:${port}/api/devices`,{headers:{'X-SOM-Token':token}});
 if(!response.ok)throw new Error('No se pudieron cargar los dispositivos configurados');
 const devices=await response.json() as Array<{id:number;name:string;url:string;allow_untrusted_tls:boolean}>;
 const device=devices.find(item=>item.id===deviceId);
 if(!device)throw new Error('El dispositivo ya no está registrado');
 let target:URL;
 try{target=new URL(device.url)}catch{throw new Error('La URL de la consola no es válida')}
 if(target.protocol!=='https:'||target.username||target.password)throw new Error('La consola debe usar HTTPS y no incluir credenciales en la URL');
 const partition=`persist:som-device-${device.id}`;
 const deviceSession=session.fromPartition(partition);
 if(device.allow_untrusted_tls){
  const configuredHost=target.hostname.toLowerCase();
  deviceSession.setCertificateVerifyProc((request,callback)=>{
   if(request.hostname.toLowerCase()===configuredHost)callback(0);
   else callback(-3);
  });
 }else deviceSession.setCertificateVerifyProc(null);
 deviceSession.setPermissionRequestHandler((_contents,_permission,callback)=>callback(false));
 const current=deviceConsoleWindows.get(device.id);
 if(current&&!current.window.isDestroyed()){
  if(current.origin===target.origin){
   if(current.window.isMinimized())current.window.restore();
   current.window.show();current.window.focus();await fillSavedDeviceLogin(current.window,device.id);return current.window;
  }
  current.window.close();
 }
 const win=new BrowserWindow({width:1280,height:900,minWidth:900,minHeight:650,title:`SOM · ${device.name}${device.allow_untrusted_tls?' · TLS no verificado':''}`,autoHideMenuBar:true,webPreferences:{partition,contextIsolation:true,nodeIntegration:false,sandbox:true}});
 deviceConsoleWindows.set(device.id,{window:win,origin:target.origin});
 win.on('closed',()=>{if(deviceConsoleWindows.get(device.id)?.window===win)deviceConsoleWindows.delete(device.id)});
 const isAllowedOrigin=(url:string)=>{try{return new URL(url).origin===target.origin&&new URL(url).protocol==='https:'}catch{return false}};
 win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
 win.webContents.on('will-navigate',(event,url)=>{if(!isAllowedOrigin(url))event.preventDefault()});
 win.webContents.on('will-redirect',(event,url)=>{if(!isAllowedOrigin(url))event.preventDefault()});
 await win.loadURL(target.toString());
 await fillSavedDeviceLogin(win,device.id);
 return win;
}
ipcMain.handle('som:open-device-console',async(_event,deviceId:number)=>{
 if(!Number.isSafeInteger(deviceId)||deviceId<1)throw new Error('Identificador de dispositivo inválido');
 await openDeviceConsole(deviceId);
});
const firewallLogCategories=[
 {label:'Event Log',key:'EVENTLOG'},
 {label:'Network Log',key:'NETWORKLOG'},
 {label:'Configuration Log',key:'CONFIGURATIONLOG'},
 {label:'Threat Log',key:'THREATLOG'},
 {label:'Session Log',key:'SESSIONLOG'},
 {label:'NAT Log',key:'NATLOG'},
 {label:'URL Log',key:'URLLOG'}
] as const;
const delay=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
async function dismissConsoleDropdowns(win:BrowserWindow){
 if(win.isDestroyed())return;
 for(let attempt=0;attempt<2;attempt++){win.webContents.sendInputEvent({type:'keyDown',keyCode:'ESC'});win.webContents.sendInputEvent({type:'keyUp',keyCode:'ESC'});await delay(100)}
 await win.webContents.executeJavaScript(`document.activeElement?.blur()`,true).catch(()=>{});
}
async function clickConsoleText(win:BrowserWindow,label:string){
 const result=await win.webContents.executeJavaScript(`(()=>{
  const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();
  const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};
  const normEl=el=>norm(el.innerText||el.value||el.getAttribute('aria-label'));
  const matches=Array.from(document.querySelectorAll('*')).filter(el=>visible(el)&&norm(el.innerText)===norm(${JSON.stringify(label)})&&!Array.from(el.children).some(child=>norm(child.innerText)===norm(${JSON.stringify(label)})));
  const clickable=new Set(matches.map(el=>el.closest('button,a,[role="button"],[role="menuitem"],.x-btn,.x-menu-item')).filter(Boolean).filter(visible));
  if(clickable.size!==1)return {ok:false,count:clickable.size};
  clickable.values().next().value.click();return {ok:true};
 })()`,true) as {ok:boolean;count:number};
 if(!result.ok)throw new Error(`No se pudo identificar un control único «${label}» en la consola (coincidencias: ${result.count}).`);
}
async function clickConsoleTextIfPresent(win:BrowserWindow,label:string):Promise<boolean>{
 const result=await win.webContents.executeJavaScript(`(()=>{
  const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();
  const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};
  const wanted=norm(${JSON.stringify(label)});
  const leaves=Array.from(document.querySelectorAll('button,a,[role="button"],[role="menuitem"],.x-btn,.x-menu-item,[data-qtip]')).filter(el=>visible(el)&&norm(el.innerText||el.value||el.getAttribute('aria-label')||el.getAttribute('data-qtip'))===wanted);
  const candidates=Array.from(new Set(leaves.map(el=>el.closest('button,a,[role="button"],[role="menuitem"],.x-btn,.x-menu-item')||el)));
  if(candidates.length!==1)return {clicked:false,count:candidates.length};candidates[0].click();return {clicked:true,count:1};
 })()`,true) as {clicked:boolean;count:number};
 return result.clicked;
}
async function clickBdsConsoleText(win:BrowserWindow,label:string){
 const result=await win.webContents.executeJavaScript(`(()=>{
  const norm=value=>(value||'').replace(/[\\u200B-\\u200D\\uFEFF]/g,'').replace(/\\s+/g,' ').trim().toLowerCase();
  const wanted=norm(${JSON.stringify(label)});
  const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};
  const matches=Array.from(document.querySelectorAll('a,button,[role="tab"],[role="button"],li,span,div'))
   .filter(el=>visible(el)&&norm(el.innerText||el.textContent)===wanted)
   .filter(el=>!Array.from(el.children).some(child=>norm(child.innerText||child.textContent)===wanted));
  if(matches.length!==1)return {ok:false,count:matches.length};
  matches[0].click();return {ok:true,count:1};
 })()`,true) as {ok:boolean;count:number};
 if(!result.ok)throw new Error(`BDS: no se pudo activar «${label}» (coincidencias: ${result.count}).`);
}
async function applyWafFilterIfAvailable(win:BrowserWindow,category:string){
 if(await clickConsoleTextIfPresent(win,'Filter')){await delay(2200);await dismissConsoleDropdowns(win);return}
 // Several W620S log pages refresh as soon as the period is selected and
 // expose no Filter action. Let that request settle so an empty grid reaches
 // the normal evidence-screenshot path instead of aborting the backup.
 console.info(`[SOM] ${category}: la vista no expone Filter; espero la consulta automática del periodo.`);
 await delay(2600);
}
async function clickWafTopMenu(win:BrowserWindow,label:string){
 const result=await win.webContents.executeJavaScript(`(()=>{const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const matches=Array.from(document.querySelectorAll('a,button,[role="tab"],[role="button"],li,span,div')).filter(el=>visible(el)&&norm(el.innerText||el.textContent)===norm(${JSON.stringify(label)}));const top=matches.filter(el=>el.getBoundingClientRect().top<180);const candidates=top.length?top:matches;if(!candidates.length)return {ok:false,count:0};candidates.sort((a,b)=>{const ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();return ar.width*ar.height-br.width*br.height});candidates[0].click();return {ok:true,count:candidates.length}})()`,true) as {ok:boolean;count:number};
 if(!result.ok)throw new Error(`No se encontró el menú superior «${label}» del WAF.`);
}
async function clickWafSidebarText(win:BrowserWindow,label:string){
 const result=await win.webContents.executeJavaScript(`(()=>{const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const matches=Array.from(document.querySelectorAll('a,button,[role="button"],[role="menuitem"],li,span,div')).filter(el=>visible(el)&&norm(el.innerText||el.textContent)===norm(${JSON.stringify(label)})&&el.getBoundingClientRect().left<245);if(!matches.length)return {ok:false,count:0};matches.sort((a,b)=>{const ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();return ar.width*ar.height-br.width*br.height});matches[0].click();return {ok:true,count:matches.length}})()`,true) as {ok:boolean;count:number};
 if(!result.ok)throw new Error(`No se pudo identificar «${label}» en el menú Log del WAF (coincidencias: 0).`);
}
async function clickWafVisibleText(win:BrowserWindow,label:string){
 return await win.webContents.executeJavaScript(`(()=>{const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const controls=Array.from(document.querySelectorAll('input,button,[role="combobox"],[aria-haspopup="listbox"],.x-form-field,.x-btn')).filter(el=>visible(el)&&norm(el.value||el.innerText||el.getAttribute('aria-label'))===norm(${JSON.stringify(label)}));const matches=Array.from(document.querySelectorAll('body *')).filter(el=>visible(el)&&norm(el.innerText||el.textContent)===norm(${JSON.stringify(label)})&&!Array.from(el.children).some(child=>norm(child.innerText||child.textContent)===norm(${JSON.stringify(label)})));const candidates=controls.length?controls:matches;if(!candidates.length)return false;candidates.sort((a,b)=>{const ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();return ar.width*ar.height-br.width*br.height});candidates[0].click();return true})()`,true) as boolean;
}
async function clickWafMenuChoice(win:BrowserWindow,label:string|string[]){
 const labels=Array.isArray(label)?label:[label];
 const frames=win.webContents.mainFrame.framesInSubtree;
 for(const frame of frames){
  if(frame.detached)continue;
  const clicked=await frame.executeJavaScript(`(()=>{
   const labels=${JSON.stringify(labels)}.map(value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase());
   const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();
   const visible=el=>{const r=el.getBoundingClientRect();const style=getComputedStyle(el);return r.width>0&&r.height>0&&style.visibility!=='hidden'&&style.display!=='none'};
   const matches=Array.from(document.querySelectorAll('button[id^="logexportbutton-"],.x-menu-item button,[role="menuitem"],button,a'))
    .filter(el=>visible(el)&&labels.includes(norm(el.innerText||el.textContent||el.getAttribute('aria-label'))));
   if(matches.length!==1)return {clicked:false,count:matches.length};
   // ExtJS binds the export action to the actual generated button; clicking
   // the surrounding menu row can leave the menu open without invoking it.
   matches[0].click();return {clicked:true,count:1};
  })()`,true).catch(()=>({clicked:false,count:0})) as {clicked:boolean;count:number};
  if(clicked.clicked)return true;
 }
 return false;
}
async function detectLogRows(win:BrowserWindow):Promise<'has_rows'|'empty'|'unknown'>{
 for(let attempt=0;attempt<12;attempt++){
  const state=await win.webContents.executeJavaScript(`(()=>{
   const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};
   const rows=Array.from(document.querySelectorAll('.x-grid-item,.x-grid-row,tbody tr')).filter(el=>{if(!visible(el)||!el.innerText.trim()||el.getAttribute('aria-rowindex')==='1'||el.querySelector('[role="columnheader"],th,.x-column-header')||el.closest('thead,.x-grid-header-ct,.x-grid-header-row,[class*="header"]'))return false;const className=typeof el.className==='string'?el.className:el.className?.baseVal||'';if(/header|column/i.test(className))return false;return /\\b(?:20\\d{2}[/-]\\d{1,2}[/-]\\d{1,2}|\\d{1,2}[/-]\\d{1,2}[/-]20\\d{2})\\s+\\d{1,2}:\\d{2}/.test(el.innerText)});
   const text=(document.body?.innerText||'').toLowerCase().replace(/\\s+/g,' ');
   const loading=Array.from(document.querySelectorAll('.x-mask-msg,.x-loading,[aria-busy="true"]')).some(visible);
   const grid=Array.from(document.querySelectorAll('.x-grid-view,[role="grid"],table')).some(visible);
   const hasHeaders=Array.from(document.querySelectorAll('th,[role="columnheader"],.x-column-header,thead')).some(visible);
   const exportButtons=Array.from(document.querySelectorAll('button,a,[role="button"],.x-btn')).filter(el=>visible(el)&&/^export$/i.test((el.innerText||el.getAttribute('aria-label')||'').trim()));
   const exportDisabled=exportButtons.length>0&&exportButtons.every(el=>el.disabled===true||el.hasAttribute('disabled')||el.getAttribute('aria-disabled')==='true'||/disabled/i.test(typeof el.className==='string'?el.className:el.className?.baseVal||''));
   const pager=Array.from(document.querySelectorAll('.x-paging-info,.x-toolbar,[class*="paging"],[class*="pagination"]')).filter(visible).map(el=>el.innerText||'').join(' ').toLowerCase();
   const saysEmpty=/no\\s+(data|records|logs|entries|results)|no data to display|no matching|0\\s+(records|results|logs|entries)|no log entries|displaying\\s+0\\s*(?:-|to)\\s*0\\s+of\\s+0|total\\s*:?\\s*0|暂无数据|无记录/.test(text+' '+pager);
   return {rows:rows.length,loading,grid,hasHeaders,exportDisabled,pager:!!pager.trim(),saysEmpty};
  })()`,true) as {rows:number;loading:boolean;grid:boolean;hasHeaders:boolean;exportDisabled:boolean;pager:boolean;saysEmpty:boolean};
  if(state.rows>0)return 'has_rows';
  // Empty text is considered only after excluding data rows and grid headers.
  if(state.saysEmpty)return 'empty';
  // Hillstone sometimes renders an empty table first and updates its pager a
  // few seconds later. Wait for any loading mask to disappear before calling
  // a visible, rowless grid an empty result.
  if(!state.loading&&(state.grid||state.pager||(state.hasHeaders&&state.exportDisabled)))return 'empty';
  await delay(750);
 }
 return 'unknown';
}
function waitForHillstoneDownload(win:BrowserWindow,filepath:string,allowTextFormat?:'TXT'|'CSV'):{promise:Promise<string>;cancel:()=>void}{
 let rejectPromise:(reason:Error)=>void=()=>{};let timeout:NodeJS.Timeout;let onDownload:((_event:Electron.Event,item:Electron.DownloadItem,contents:Electron.WebContents)=>void)|undefined;
 const ses=win.webContents.session;
 const promise=new Promise<string>((resolve,reject)=>{
  rejectPromise=reject;
  timeout=setTimeout(()=>{if(onDownload)ses.removeListener('will-download',onDownload!);reject(new Error('La consola no inició la descarga dentro de 180 segundos.'))},180000);
  onDownload=(_event:Electron.Event,item:Electron.DownloadItem,contents:Electron.WebContents)=>{
   // Hillstone sometimes starts downloads from a child WebContents or an
   // internal frame. The listener is attached to this device's isolated
   // session, so filtering by the top-level WebContents ID drops valid files.
   ses.removeListener('will-download',onDownload!);item.setSavePath(filepath);
   item.once('done',(_doneEvent,state)=>{
    clearTimeout(timeout);
    if(state!=='completed'){reject(new Error(`La descarga terminó con estado ${state}.`));return}
    try{
     const stat=fs.statSync(filepath);const fd=fs.openSync(filepath,'r');const signature=Buffer.alloc(8);try{fs.readSync(fd,signature,0,signature.length,0)}finally{fs.closeSync(fd)}
     if(!stat.isFile()||stat.size<4)throw new Error(`La descarga está vacía o no es un archivo regular (tamaño: ${stat.size} bytes).`);
     if(signature.subarray(0,2).toString('ascii')==='PK'){
      // WAF firmware commonly returns its selected CSV/TXT directly, while
      // other Hillstone exports arrive as ZIPs. Keep the real container type.
      const zipPath=filepath.replace(/\.download$/i,'.zip');if(filepath!==zipPath)fs.renameSync(filepath,zipPath);resolve(zipPath);return;
     }
     if(signature[0]===0x1f&&signature[1]===0x8b){
      // BDS exports some log categories as a gzip-compressed tar containing
      // the actual TXT file (for example uhg.tar.gz -> uhg.txt).
      const tarPath=filepath.replace(/\.download$/i,'.tar.gz');if(filepath!==tarPath)fs.renameSync(filepath,tarPath);resolve(tarPath);return;
     }
     if(!allowTextFormat)throw new Error(`El archivo descargado no parece un ZIP válido (tamaño: ${stat.size} bytes; tipo: ${item.getMimeType()||'desconocido'}; firma: ${signature.subarray(0,8).toString('hex')||'vacía'}).`);
     const sampleBuffer=Buffer.alloc(Math.min(8192,stat.size));const sampleFd=fs.openSync(filepath,'r');try{fs.readSync(sampleFd,sampleBuffer,0,sampleBuffer.length,0)}finally{fs.closeSync(sampleFd)}const text=sampleBuffer.toString('utf8').replace(/^\uFEFF/,'');
     const printable=[...text].filter(char=>char==='\n'||char==='\r'||char==='\t'||char>=' ').length;
     if(printable<Math.min(16,text.length)*0.9||/^\s*<(?:!doctype|html|head|body)\b/i.test(text)||/login time out|please login again|access denied|internal server error/i.test(text.slice(0,2000)))throw new Error(`Hillstone respondió con contenido que no parece un log ${allowTextFormat} (tamaño: ${stat.size} bytes; tipo: ${item.getMimeType()||'desconocido'}; inicio: ${text.slice(0,100).replace(/\s+/g,' ')}).`);
     if(allowTextFormat==='CSV'&&!/[\t,;]/.test(text.slice(0,2000)))throw new Error(`Hillstone no devolvió una tabla CSV válida (tamaño: ${stat.size} bytes; tipo: ${item.getMimeType()||'desconocido'}; inicio: ${text.slice(0,100).replace(/\s+/g,' ')}).`);
     const textPath=filepath.replace(/\.download$/i,`.${allowTextFormat.toLowerCase()}`);if(filepath!==textPath)fs.renameSync(filepath,textPath);resolve(textPath)
    }catch(error){reject(error)}
   });
  };
  ses.on('will-download',onDownload!);
 });
 return {promise,cancel:()=>{if(onDownload)ses.removeListener('will-download',onDownload!);clearTimeout(timeout);rejectPromise(new Error('Descarga cancelada porque no se pudo confirmar el diálogo.'))}};
}
async function confirmWafSavePrompt(win:BrowserWindow){
 for(let attempt=0;attempt<20;attempt++){
  const state=await win.webContents.executeJavaScript(`(()=>{const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const prompt=Array.from(document.querySelectorAll('body *')).filter(el=>visible(el)&&norm(el.innerText||el.textContent).includes('whether or not to save')&&!Array.from(el.children).some(child=>norm(child.innerText||child.textContent).includes('whether or not to save'))).sort((a,b)=>{const ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();return ar.width*ar.height-br.width*br.height})[0];if(!prompt)return {shown:false,clicked:false};let root=prompt;while(root&&root!==document.body){const controls=Array.from(root.querySelectorAll('button,a,[role="button"],input[type="button"],input[type="submit"],.x-btn'));const buttons=controls.filter(el=>visible(el));const ok=buttons.filter(el=>norm(el.innerText||el.value||el.getAttribute('aria-label'))==='ok');const cancel=buttons.filter(el=>norm(el.innerText||el.value||el.getAttribute('aria-label'))==='cancel');if(ok.length===1&&cancel.length===1){ok[0].click();return {shown:true,clicked:true}}root=root.parentElement}return {shown:true,clicked:false}})()`,true) as {shown:boolean;clicked:boolean};
  if(state.clicked){await delay(300);return}
  if(state.shown)throw new Error('WAF: apareció «Whether or not to save», pero no pude identificar el botón OK de ese diálogo.');
  await delay(300);
 }
}
async function exportNamedFirewallFormat(win:BrowserWindow,stageDir:string,date:string,category:{label:string;key:string},format:'TXT'|'CSV',prefix='FW',confirmSavePrompt=false,dialogAlreadyOpen=false){
 if(!dialogAlreadyOpen){await clickConsoleText(win,'Export');await delay(1000)}
 const usesDirectTextDownload=prefix==='WAF'||prefix==='BDS';
 const name=`${prefix}_${category.key}_${date}_${format}${usesDirectTextDownload?'.download':'.zip'}`;const filepath=path.join(stageDir,name);
 const pendingDownload=waitForHillstoneDownload(win,filepath,usesDirectTextDownload?format:undefined);
 try{
 const fixedWafCsv=prefix==='WAF'&&category.key==='WEBSECURITYLOG';
 const exportScript=`(async()=>{
  const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();
  const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};
  const sessionExpired=Array.from(document.querySelectorAll('[role="dialog"],.x-window,.x-message-box,[class*="message-box"]')).filter(visible).some(root=>/login time out[.!]?\\s*please login again/i.test(root.innerText||''));
  if(sessionExpired)return {ok:false,error:'La sesión del WAF expiró (Login time out). Inicia sesión nuevamente en la consola y vuelve a ejecutar el respaldo.'};
  const buttons='button,a,[role="button"],input[type="button"],input[type="submit"],.x-btn';
  const normEl=el=>norm(el.innerText||el.value||el.getAttribute('aria-label'));
  const textLeaves=(root,label)=>Array.from(root.querySelectorAll('*')).filter(el=>visible(el)&&norm(el.innerText)===norm(label)&&!Array.from(el.children).some(child=>norm(child.innerText)===norm(label)));
  const targets=(root,label)=>Array.from(new Set(textLeaves(root,label).map(leaf=>leaf.closest(buttons)||leaf.parentElement||leaf)));
  const hasAction=(root,label)=>targets(root,label).length===1;
  const fixedWafCsv=${JSON.stringify(fixedWafCsv)};
  const titles=Array.from(document.querySelectorAll('*')).filter(el=>visible(el)&&['export','export log'].includes(norm(el.innerText))&&!Array.from(el.children).some(child=>['export','export log'].includes(norm(child.innerText))));
  const drawers=Array.from(document.querySelectorAll('[id*="mhsdrawer"],[role="dialog"],.x-window,.x-panel')).filter(visible).filter(root=>/\\bexport\\b/i.test(root.innerText||'')&&root.querySelector('input,textarea,[role="textbox"]')&&hasAction(root,'ok')&&hasAction(root,'cancel'));
  const dialogs=Array.from(document.querySelectorAll('[role="dialog"],.x-window')).filter(visible).filter(root=>titles.some(title=>root.contains(title))&&hasAction(root,'ok'));
  let dialog=drawers[0]||dialogs.sort((a,b)=>a.getBoundingClientRect().width*a.getBoundingClientRect().height-b.getBoundingClientRect().width*b.getBoundingClientRect().height)[0];
  if(!dialog){for(const title of titles){let parent=title.parentElement;while(parent&&parent!==document.body&&parent!==document.documentElement){if(hasAction(parent,'ok')&&hasAction(parent,'cancel')){dialog=parent;break}parent=parent.parentElement}if(dialog)break}}
  if(!dialog)return {ok:false,error:'No apareció el diálogo de exportación (Export / Export Log).'};
  const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
   const nameLabels=Array.from(dialog.querySelectorAll('label,[class*="form-item-label"],[class*="field-label"],[class*="form-label"]')).filter(el=>visible(el)&&/^name\\s*\\*?$/i.test((el.innerText||el.textContent||'').replace(/\\s+/g,' ').trim()));
   let nameInput=null,nameField=null,expectedName='';
  const editableInputs=Array.from(dialog.querySelectorAll('input,textarea,[role="textbox"]')).filter(input=>visible(input)&&!input.disabled&&!input.readOnly&&!['hidden','password','button','submit','reset','checkbox','radio','file','image'].includes((input.type||'').toLowerCase()));
  if(fixedWafCsv){
   // ExtJS regenerates the numeric input id, but keeps name="name" stable.
   // The export field lives in a drawer whose id also changes between opens.
   const stableNameInputs=Array.from(document.querySelectorAll('input[name="name"]')).filter(input=>!input.disabled&&!input.readOnly);
   const drawerNameInputs=stableNameInputs.filter(input=>{
    const drawer=input.closest('[id*="mhsdrawer"]');
    return drawer&&/\bexport\b/i.test(drawer.innerText||'')&&dialog.contains(input);
   });
   if(drawerNameInputs.length===1)nameInput=drawerNameInputs[0];
   else if(stableNameInputs.length===1)nameInput=stableNameInputs[0];
  }
   // ExtJS generates a fresh numeric input id on each render, but this form
   // exposes the stable name="name" attribute. Resolve that first, scoped to
   // the visible Export dialog; use label association and the generated ID as
   // fallbacks for firmware versions that render a different form.
   if(!nameInput)for(const label of nameLabels){
    const forId=label.getAttribute('for');const byFor=forId?document.getElementById(forId):null;
    if(byFor&&dialog.contains(byFor)&&!byFor.disabled&&!byFor.readOnly){nameInput=byFor;break}
    let parent=label;
    while(parent&&parent!==dialog){
     const fields=Array.from(parent.querySelectorAll('input,textarea,[role="textbox"]')).filter(input=>visible(input)&&!input.disabled&&!input.readOnly&&!['hidden','password','button','submit','reset','checkbox','radio','file','image'].includes((input.type||'').toLowerCase()));
     if(fields.length===1){nameInput=fields[0];break}
     parent=parent.parentElement;
    }
    if(nameInput)break;
   }
   if(!nameInput&&fixedWafCsv){const dynamicIdInputs=Array.from(document.querySelectorAll('input[id^="textfield-"][id$="-inputEl"]')).filter(input=>!input.disabled&&!input.readOnly);const inDialog=dynamicIdInputs.filter(input=>dialog.contains(input));if(inDialog.length===1)nameInput=inDialog[0];else if(dynamicIdInputs.length===1)nameInput=dynamicIdInputs[0]}
   if(nameInput&&fixedWafCsv){
    const componentId=nameInput.id?.replace(/-inputEl$/,'');
    const extFields=window.Ext?.ComponentQuery?.query?.('textfield')||[];
    nameField=window.Ext?.getCmp?.(componentId)||extFields.find(field=>field.inputEl?.dom===nameInput&&!field.disabled)||null;
   }
   if(!nameInput&&!fixedWafCsv&&nameLabels.length){for(const label of nameLabels){let parent=label;while(parent&&parent!==dialog){const fields=Array.from(parent.querySelectorAll('input')).filter(input=>visible(input)&&['text',''].includes((input.type||'').toLowerCase()));if(fields.length===1){nameInput=fields[0];break}parent=parent.parentElement}if(nameInput)break}}
   if(!nameInput&&!fixedWafCsv)nameInput=editableInputs.find(input=>['text',''].includes((input.type||'').toLowerCase()))||editableInputs[0]||null;
  if(fixedWafCsv||nameLabels.length){
     if(!nameInput){const candidates=Array.from(document.querySelectorAll('input[name="name"]')).map(input=>input.id+' ['+input.className+'] '+(input.disabled?'disabled':'enabled')+'/'+(input.readOnly?'readonly':'editable')).join(', ')||'ninguno';return {ok:false,error:'Encontré el diálogo Export, pero no pude resolver input[name="name"] (en el documento: '+candidates+'; diálogo: '+(dialog.id||dialog.className||dialog.tagName)+').'}}
   const value=${JSON.stringify(`${prefix}_${category.key}_${date}`)};expectedName=value;nameInput.focus();
    const componentId=nameInput.id?.replace(/-inputEl$/,'');const field=nameField||window.Ext?.getCmp?.(componentId)||null;
   if(fixedWafCsv){
     if(field?.setValue){field.setValue(value);field.setRawValue?.(value);field.checkChange?.();field.validate?.()}
     else {setter.call(nameInput,value);nameInput.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));nameInput.dispatchEvent(new Event('change',{bubbles:true}))}
    await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
     if(nameInput.value!==value||(field?.getValue&&field.getValue()!==value))return {ok:false,error:'No se sincronizó Name (campo asociado a etiqueta; input: «'+nameInput.value+'»; formulario: «'+(field?.getValue?.()||'')+'»).'};
   }else if(field?.setValue){
    // ExtJS owns this field. Updating its component value first and then
    // overwriting the DOM input with synthetic input events can make ExtJS
    // restore the old (empty) value during its next layout/validation pass.
    field.setValue(value);field.setRawValue?.(value);field.checkChange?.();field.validate?.();
   }else{
    setter.call(nameInput,value);nameInput.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));nameInput.dispatchEvent(new Event('change',{bubbles:true}));
   }
   const componentValue=field?.getValue?.();
   if(nameInput.value!==value&&componentValue!==value)return {ok:false,error:'No se pudo escribir el nombre en el campo Name.'};
   await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
   if(nameInput.value!==value)return {ok:false,error:'El campo Name no conservó el nombre después de actualizarse.'};
   nameInput.blur();if(nameInput.value!==value)return {ok:false,error:'El control Name quedó vacío al salir del campo.'}
  }
  const inputs=Array.from(dialog.querySelectorAll('input')).filter(visible);
  if(!fixedWafCsv){
   const formatLeaves=textLeaves(dialog,${JSON.stringify(format)});
   const formatTargets=Array.from(new Set(formatLeaves.map(leaf=>leaf.closest(buttons)||leaf.parentElement||leaf)));
   if(formatTargets.length!==1)return {ok:false,error:formatTargets.length?'Hay más de un control de formato '+${JSON.stringify(format)}+' en el diálogo.':'No se encontró el formato '+${JSON.stringify(format)}+' en el diálogo.'};
   formatTargets[0].click();
  }
  if(nameInput&&nameInput.value!==expectedName)return {ok:false,error:'El campo Name quedó vacío al actualizar el formato.'};
  const passwordInputs=inputs.filter(input=>(input.type||'').toLowerCase()==='password');for(const input of passwordInputs){setter.call(input,'');input.dispatchEvent(new Event('input',{bubbles:true}))}
  const okButtons=targets(dialog,'ok');if(okButtons.length!==1)return {ok:false,error:'No se encontró el botón OK dentro del diálogo de exportación.'};okButtons[0].click();
  return {ok:true};
 })()`;
 let result:{ok:boolean;error?:string}|undefined;
 if(fixedWafCsv){
  const mainFrame=win.webContents.mainFrame;
  const frames=[mainFrame,...win.webContents.mainFrame.framesInSubtree.filter(frame=>frame!==mainFrame)];
  const frameDiagnostics:string[]=[];
  for(const frame of frames){
   if(frame.detached)continue;
   try{
    const attempt=await frame.executeJavaScript(exportScript,true) as {ok:boolean;error?:string};
     const noDialog=attempt.error==='No apareció el diálogo de exportación (Export / Export Log).';
     const fieldNotInThisFrame=attempt.error?.startsWith('Encontré el diálogo Export, pero no pude resolver input[name="name"]');
     if(attempt.ok||(!noDialog&&!fieldNotInThisFrame)){result=attempt;break;}
     frameDiagnostics.push(`${new URL(frame.url).pathname||'/'}: ${noDialog?'sin diálogo Export':attempt.error}`);
   }catch(error){frameDiagnostics.push(`${frame.url}: ${error instanceof Error?error.message:String(error)}`)}
  }
   if(!result)throw new Error(`WAF Web Security Log: no encontré el campo input[name="name"] en el mismo frame del diálogo Export (${frameDiagnostics.join(' | ')||'ninguno'}).`);
 }else result=await win.webContents.executeJavaScript(exportScript,true) as {ok:boolean;error?:string};
 if(!result.ok)throw new Error(result.error||'No se pudo configurar la exportación.');
 if(confirmSavePrompt)await confirmWafSavePrompt(win);
 return await pendingDownload.promise;
 }catch(error){pendingDownload.cancel();await pendingDownload.promise.catch(()=>{});throw error}
}
async function exportQuickFirewallFormat(win:BrowserWindow,stageDir:string,date:string,category:{label:string;key:string},format:'TXT'|'CSV',prefix='FW',dialogAlreadyOpen=false){
 if(!dialogAlreadyOpen){await clickConsoleText(win,'Export');await delay(1000)}
 const filepath=path.join(stageDir,`${prefix}_${category.key}_${date}_${format}.zip`);
 const pendingDownload=waitForHillstoneDownload(win,filepath);
 try{
  const result=await win.webContents.executeJavaScript(`(()=>{
   const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();
   const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};
   const controls='button,a,[role="button"],input[type="button"],input[type="submit"],.x-btn';
   const leaves=(root,label)=>Array.from(root.querySelectorAll('*')).filter(el=>visible(el)&&norm(el.innerText)===norm(label)&&!Array.from(el.children).some(child=>norm(child.innerText)===norm(label)));
   const targets=(root,label)=>Array.from(new Set(leaves(root,label).map(leaf=>leaf.closest(controls)||leaf.parentElement||leaf)));
   const titles=Array.from(document.querySelectorAll('*')).filter(el=>visible(el)&&norm(el.innerText)==='export'&&!Array.from(el.children).some(child=>norm(child.innerText)==='export'));
   const dialogs=Array.from(document.querySelectorAll('[role="dialog"],.x-window')).filter(visible).filter(root=>titles.some(title=>root.contains(title))&&targets(root,'ok').length===1);
   let dialog=dialogs.sort((a,b)=>a.getBoundingClientRect().width*a.getBoundingClientRect().height-b.getBoundingClientRect().width*b.getBoundingClientRect().height)[0];
   if(!dialog){for(const title of titles){let parent=title.parentElement;while(parent&&parent!==document.body&&parent!==document.documentElement){if(targets(parent,'ok').length===1&&targets(parent,'cancel').length===1){dialog=parent;break}parent=parent.parentElement}if(dialog)break}}
   if(!dialog)return {ok:false,error:'No apareció el diálogo Export de '+${JSON.stringify(category.label)}+'.'};
   const formatTargets=targets(dialog,${JSON.stringify(format)});if(formatTargets.length!==1)return {ok:false,error:'No se encontró la opción '+${JSON.stringify(format)}+' dentro del diálogo Export de '+${JSON.stringify(category.label)}+'.'};
   formatTargets[0].click();
   const okTargets=targets(dialog,'ok');if(okTargets.length!==1)return {ok:false,error:'No se encontró OK dentro del diálogo Export de '+${JSON.stringify(category.label)}+'.'};
   okTargets[0].click();return {ok:true};
  })()`,true) as {ok:boolean;error?:string};
  if(!result.ok)throw new Error(result.error||'No se pudo configurar la exportación rápida.');
  await pendingDownload.promise;return filepath;
 }catch(error){pendingDownload.cancel();await pendingDownload.promise.catch(()=>{});throw error}
}
async function exportFirewallFormat(win:BrowserWindow,stageDir:string,date:string,category:{label:string;key:string},format:'TXT'|'CSV',dialogAlreadyOpen=false){
 const namedDialogCategories=['EVENTLOG','NETWORKLOG','CONFIGURATIONLOG'];
 if(namedDialogCategories.includes(category.key))return exportNamedFirewallFormat(win,stageDir,date,category,format,'FW',false,dialogAlreadyOpen);
 return exportQuickFirewallFormat(win,stageDir,date,category,format,'FW',dialogAlreadyOpen);
}
async function exportPreferredFirewallFormat(win:BrowserWindow,stageDir:string,date:string,category:{label:string;key:string},prefix:'FW'|'WAF'|'BDS',confirmSavePrompt=false):Promise<{path:string;format:'TXT'|'CSV'}>{
 const exportFormat=(format:'TXT'|'CSV',dialogAlreadyOpen=false)=>prefix==='WAF'
  ?exportNamedFirewallFormat(win,stageDir,date,category,format,'WAF',confirmSavePrompt,dialogAlreadyOpen)
  :prefix==='BDS'
   ?exportNamedFirewallFormat(win,stageDir,date,category,format,'BDS',confirmSavePrompt,dialogAlreadyOpen)
   :exportFirewallFormat(win,stageDir,date,category,format,dialogAlreadyOpen);
 try{return {path:await exportFormat('TXT'),format:'TXT'}}catch(error){
  const message=error instanceof Error?error.message:String(error);
  if(!/no se encontr[oó] (?:el formato|la opci[oó]n) TXT/i.test(message))throw error;
  // The format lookup failed before the export was submitted; reuse the still
  // open dialog and select the device's CSV export instead.
  return {path:await exportFormat('CSV',true),format:'CSV'};
 }
}
async function runFirewallBackup(deviceId:number):Promise<{filename:string;file_count:number;path:string}>{
 const win=await openDeviceConsole(deviceId);
 if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');
 win.show();win.focus();
 const notify=(message:string)=>{for(const appWindow of BrowserWindow.getAllWindows())if(!appWindow.isDestroyed())appWindow.webContents.send('som:backup-progress',message)};
 notify('Esperando a que Hillstone termine de iniciar sesión…');
 let loginResolved=false;
 for(let attempt=0;attempt<40;attempt++){
  if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');
  const state=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};return {loaded:document.readyState!=='loading'&&!!document.body,login:Array.from(document.querySelectorAll('input[type="password"]')).some(visible)}})()`,true) as {loaded:boolean;login:boolean};
  if(state.loaded&&!state.login){loginResolved=true;break}
  await delay(750);
 }
 if(!loginResolved){const diagnostics=await win.webContents.executeJavaScript(`(()=>({url:location.href,title:document.title,readyState:document.readyState,loginForm:Array.from(document.querySelectorAll('input[type="password"]')).some(el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0})}))()`,true) as {url:string;title:string;readyState:string;loginForm:boolean};console.error('[SOM] No se pudo confirmar el inicio de sesión Hillstone.',diagnostics);throw new Error(diagnostics.loginForm?'Hillstone sigue mostrando el formulario de inicio de sesión. Completa el acceso en su ventana y vuelve a intentar.':'La consola Hillstone no terminó de cargar. Revisa su ventana e inténtalo de nuevo.')}
 notify('Abriendo Monitor → Log → Event Log…');
 await win.webContents.executeJavaScript(`location.hash='#equipmentSystemLogger/eventTab'`,true);
 let eventLogReady=false;
 for(let attempt=0;attempt<40;attempt++){
  if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');
  eventLogReady=await win.webContents.executeJavaScript(`(document.body?.innerText||'').toLowerCase().includes('event log')`,true) as boolean;
  if(eventLogReady)break;
  await delay(500);
 }
 if(!eventLogReady){const diagnostics=await win.webContents.executeJavaScript(`(()=>({url:location.href,title:document.title,readyState:document.readyState}))()`,true) as {url:string;title:string;readyState:string};console.error('[SOM] Hillstone no mostró Event Log después de navegar a la ruta conocida.',diagnostics);throw new Error('La sesión está abierta, pero no se pudo abrir Monitor → Log → Event Log. Revisa la consola Hillstone.')}
 const stageDir=path.join(runtimeDataDir,'automation-staging',randomBytes(12).toString('hex'));
 fs.mkdirSync(stageDir,{recursive:true});
 const now=new Date();const date=`${String(now.getDate()).padStart(2,'0')}_${String(now.getMonth()+1).padStart(2,'0')}_${now.getFullYear()}`;
 const files:Array<{path:string;category:string;format:string}>=[];
 try{
  for(let index=0;index<firewallLogCategories.length;index++){
   const category=firewallLogCategories[index];notify(`Consultando ${category.label} (${index+1}/${firewallLogCategories.length})`);
   await dismissConsoleDropdowns(win);await clickConsoleText(win,category.label);await delay(1600);await dismissConsoleDropdowns(win);
   const periodState=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};const re=/last\\s*24\\s*hours/i;const selects=Array.from(document.querySelectorAll('select')).filter(visible).map(el=>({value:el.options[el.selectedIndex]?.text||el.value,options:Array.from(el.options).map(option=>option.text)}));const fields=Array.from(document.querySelectorAll('input,textarea,[role="combobox"],[aria-haspopup="listbox"]')).filter(visible).map(el=>({value:el.value||el.innerText||el.getAttribute('aria-label')||'',label:el.getAttribute('aria-label')||el.getAttribute('placeholder')||el.name||el.id||''}));const selected=selects.some(item=>re.test(item.value))||fields.some(item=>re.test(item.value));const pageText=document.body?.innerText||'';return {selected,visibleText:re.test(pageText),selects,fields:fields.filter(item=>/time|period|date/i.test(item.label)||re.test(item.value)),url:location.href}})()`,true) as {selected:boolean;visibleText:boolean;selects:Array<{value:string;options:string[]}>;fields:Array<{value:string;label:string}>;url:string};
   const hasExplicitPeriod=periodState.selected||periodState.visibleText;
   if(!hasExplicitPeriod)console.warn(`[SOM] ${category.label} no expone «Last 24 Hours» en la vista. Se conserva el resultado predeterminado de Hillstone y no se abre el menú de filtros.`,periodState);
   if(hasExplicitPeriod){await clickConsoleText(win,'Filter');await delay(2200);await dismissConsoleDropdowns(win)}
   const rows=await detectLogRows(win);
   if(rows==='unknown')throw new Error(`${category.label}: no pude confirmar si hay registros. Se detuvo sin marcarlo como vacío.`);
   if(rows==='empty'){
    const evidencePath=path.join(stageDir,`FW_${category.key}_${date}_SIN_LOGS.png`);
    const image=await win.webContents.capturePage();fs.writeFileSync(evidencePath,image.toPNG());
    files.push({path:evidencePath,category:category.key,format:'PNG'});continue;
   }
   notify(`Exportando ${category.label} · TXT preferido (CSV alternativo)…`);
   const exported=await exportPreferredFirewallFormat(win,stageDir,date,category,'FW');
   files.push({path:exported.path,category:category.key,format:exported.format});await delay(1500)
  }
  if(files.length===0)throw new Error('No hay archivos ni evidencia que empaquetar.');
  notify('Verificando y empaquetando los archivos…');
  const response=await fetch(`http://127.0.0.1:${port}/api/backups/internal/firewall-bundle`,{method:'POST',headers:{'X-SOM-Token':token,'Content-Type':'application/json'},body:JSON.stringify({device_id:deviceId,report_date:date,files})});
  const payload=await response.json() as {detail?:string;backup?:{filename:string};file_count?:number;path?:string};
  if(!response.ok||!payload.backup)throw new Error(payload.detail||'No se pudo registrar y verificar el paquete.');
  fs.rmSync(stageDir,{recursive:true,force:true});notify('Respaldo del firewall completado.');
  return {filename:payload.backup.filename,file_count:payload.file_count??files.length,path:payload.path??''};
 }catch(error){
  notify('Respaldo detenido; revisa el mensaje de error.');
  throw error;
 }
}
const wafLogCategories=[
 {label:'Event Log',key:'EVENTLOG'},
 {label:'Network Log',key:'NETWORKLOG'},
 {label:'Configuration Log',key:'CONFIGURATIONLOG'},
 {label:'NAT Log',key:'NATLOG'},
 {label:'Web Access Log',key:'WEBACCESSLOG'},
 {label:'Network Security Log',key:'NETWORKSECURITYLOG'},
 {label:'Web Security Log',key:'WEBSECURITYLOG'}
] as const;
async function selectWafLast24Hours(win:BrowserWindow){
 const state=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const selects=Array.from(document.querySelectorAll('select')).filter(visible).map(el=>({value:el.options[el.selectedIndex]?.text||el.value,has24:Array.from(el.options).some(option=>/last\\s*24\\s*hours/i.test(option.text))}));const fields=Array.from(document.querySelectorAll('input,button,[role="combobox"],[aria-haspopup="listbox"],.x-form-field,.x-btn')).filter(visible).map(el=>(el.value||el.innerText||el.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim()).filter(value=>/last\\s*\\d+\\s*(minutes?|hours?)|today/i.test(value));const text=Array.from(document.querySelectorAll('body *')).filter(el=>visible(el)&&!Array.from(el.children).some(child=>(child.innerText||child.textContent||'').trim()===(el.innerText||el.textContent||'').trim())).map(el=>(el.innerText||el.textContent||'').replace(/\\s+/g,' ').trim()).filter(value=>/^(last\\s*\\d+\\s*(minutes?|hours?)|today)$/i.test(value));return {selects,fields,text}})()`,true) as {selects:Array<{value:string;has24:boolean}>;fields:string[];text:string[]};
 const current=state.selects.find(item=>item.has24)?.value||state.fields[0]||state.text[0]||'';
 if(!/last\\s*24\\s*hours/i.test(current)){
  const nativeSelected=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0};const select=Array.from(document.querySelectorAll('select')).find(el=>visible(el)&&Array.from(el.options).some(option=>/last\\s*24\\s*hours/i.test(option.text)));if(!select)return false;const option=Array.from(select.options).find(item=>/last\\s*24\\s*hours/i.test(item.text));const setter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set;setter.call(select,option.value);select.dispatchEvent(new Event('input',{bubbles:true}));select.dispatchEvent(new Event('change',{bubbles:true}));return true})()`,true) as boolean;
  if(!nativeSelected){
   if(!current)throw new Error('WAF: no encontré el valor actual del periodo; no aplicaré un filtro distinto de 24 horas.');
   if(!await clickWafVisibleText(win,current))throw new Error(`WAF: no pude abrir el selector de periodo «${current}».`);
   await delay(250);
   if(!await clickWafVisibleText(win,'Last 24 Hours')){
    const nowSelected=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};return Array.from(document.querySelectorAll('input,[role="combobox"],.x-form-field')).filter(visible).some(el=>/last\\s*24\\s*hours/i.test(el.value||el.innerText||''))})()`,true) as boolean;
    if(!nowSelected)throw new Error('WAF: el desplegable del periodo no mostró Last 24 Hours.');
   }
  }
 }
 await delay(300);await applyWafFilterIfAvailable(win,'WAF');
 const confirmed=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};const select=Array.from(document.querySelectorAll('select')).find(visible);const fields=Array.from(document.querySelectorAll('input,[role="combobox"],.x-form-field')).filter(visible).map(el=>el.value||el.innerText||'');const text=(document.body?.innerText||'').replace(/\\s+/g,' ');return /last\\s*24\\s*hours/i.test(select?.options[select.selectedIndex]?.text||'')||fields.some(value=>/last\\s*24\\s*hours/i.test(value))||/last\\s*24\\s*hours/i.test(text)})()`,true) as boolean;
 if(!confirmed)throw new Error('WAF: no pude confirmar el periodo Last 24 Hours.');
}
async function selectWafNatBoth(win:BrowserWindow){
 const state=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const select=Array.from(document.querySelectorAll('select')).filter(visible).find(el=>Array.from(el.options).some(option=>/^both$/i.test(option.text.trim())));if(select)return {native:true,value:select.options[select.selectedIndex]?.text||'',hasBoth:true};const fields=Array.from(document.querySelectorAll('input,button,[role="combobox"],[aria-haspopup="listbox"],.x-form-field,.x-btn')).filter(visible).map(el=>(el.value||el.innerText||el.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim()).filter(Boolean);const current=fields.find(value=>/^both$/i.test(value))||'';return {native:false,value:current,hasBoth:fields.some(value=>/^both$/i.test(value))}})()`,true) as {native:boolean;value:string;hasBoth:boolean};
 if(state.native){
  await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0};const select=Array.from(document.querySelectorAll('select')).find(el=>visible(el)&&Array.from(el.options).some(option=>/^both$/i.test(option.text.trim())));if(!select)return false;const option=Array.from(select.options).find(item=>/^both$/i.test(item.text.trim()));const setter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set;setter.call(select,option.value);select.dispatchEvent(new Event('input',{bubbles:true}));select.dispatchEvent(new Event('change',{bubbles:true}));return true})()`,true);
 }else if(!state.hasBoth){
  throw new Error('WAF NAT Log: no pude confirmar que NAT type esté en Both.');
 }
 await applyWafFilterIfAvailable(win,'WAF NAT Log');
}
async function selectWafCurrentHour(win:BrowserWindow){
 const current=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const values=Array.from(document.querySelectorAll('input,button,[role="combobox"],[aria-haspopup="listbox"],.x-form-field,.x-btn')).filter(visible).map(el=>(el.value||el.innerText||el.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim());return values.find(value=>/^(current hour|last\\s*\\d+\\s*(minutes?|hours?)|today)$/i.test(value))||''})()`,true) as string;
 if(!/current\\s*hour/i.test(current)){
  if(!current)throw new Error('WAF Web Access Log: no encontré el selector del periodo.');
  if(!await clickWafVisibleText(win,current))throw new Error(`WAF Web Access Log: no pude abrir el periodo «${current}».`);
  await delay(250);
  if(!await clickWafVisibleText(win,'Current Hour'))throw new Error('WAF Web Access Log: el desplegable no mostró Current Hour.');
 }
 await delay(300);await applyWafFilterIfAvailable(win,'WAF Web Access Log');
 const confirmed=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};const select=Array.from(document.querySelectorAll('select')).find(visible);const fields=Array.from(document.querySelectorAll('input,[role="combobox"],.x-form-field')).filter(visible).map(el=>el.value||el.innerText||'');const text=(document.body?.innerText||'').replace(/\\s+/g,' ');return /current\\s*hour/i.test(select?.options[select.selectedIndex]?.text||'')||fields.some(value=>/current\\s*hour/i.test(value))||/current\\s*hour/i.test(text)})()`,true) as boolean;
 if(!confirmed)throw new Error('WAF Web Access Log: no pude confirmar Current Hour.');
}
async function selectWafToday(win:BrowserWindow){
 const current=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'&&getComputedStyle(el).display!=='none'};const values=Array.from(document.querySelectorAll('input,button,[role="combobox"],[aria-haspopup="listbox"],.x-form-field,.x-btn')).filter(visible).map(el=>(el.value||el.innerText||el.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim());return values.find(value=>/^(real-time|last\\s*\\d+\\s*(minutes?|hours?)|today)$/i.test(value))||''})()`,true) as string;
 if(!/^today$/i.test(current)){
  if(!current)throw new Error('WAF Web Security Log: no encontré el selector del periodo.');
  if(!await clickWafVisibleText(win,current))throw new Error(`WAF Web Security Log: no pude abrir el periodo «${current}».`);
  await delay(250);
  if(!await clickWafVisibleText(win,'Today'))throw new Error('WAF Web Security Log: el desplegable no mostró Today.');
 }
 await delay(300);await applyWafFilterIfAvailable(win,'WAF Web Security Log');
 const confirmed=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};const select=Array.from(document.querySelectorAll('select')).find(visible);const fields=Array.from(document.querySelectorAll('input,[role="combobox"],.x-form-field')).filter(visible).map(el=>el.value||el.innerText||'');const text=(document.body?.innerText||'').replace(/\\s+/g,' ');return /^today$/i.test(select?.options[select.selectedIndex]?.text||'')||fields.some(value=>/^today$/i.test(value))||/(^|\\s)today(\\s|$)/i.test(text)})()`,true) as boolean;
 if(!confirmed)throw new Error('WAF Web Security Log: no pude confirmar Today.');
}
async function exportWafWebSecurityLog(win:BrowserWindow,stageDir:string,date:string,category:{label:string;key:string}){
 await clickConsoleText(win,'Export');await delay(350);
 // This menu choice opens the named export dialog. Only CSV is offered for
 // Web Security Log, and attack content must remain excluded.
 if(!await clickWafMenuChoice(win,['Without Attack Content','Widthout Attack Content']))throw new Error('WAF Web Security Log: no encontré «Without Attack Content» en Export.');
 // The WAF drawer can take longer to render than the menu animation. Wait
 // for its Name/OK controls before handing it to the shared export routine.
 let dialogReady=false;
 for(let attempt=0;attempt<20;attempt++){
  dialogReady=await win.webContents.executeJavaScript(`(()=>{
   const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};
   const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();
   const roots=Array.from(document.querySelectorAll('[role="dialog"],.x-window,[id*="mhsdrawer"]')).filter(visible);
   return roots.some(root=>/\\bexport\\b/.test(norm(root.innerText))
    &&Array.from(root.querySelectorAll('button,a,[role="button"],.x-btn')).some(el=>visible(el)&&norm(el.innerText||el.value)==='ok')
    &&Array.from(root.querySelectorAll('input[name="name"]')).some(input=>!input.disabled&&!input.readOnly&&visible(input)));
  })()`,true).catch(()=>false);
  if(dialogReady)break;
  await delay(250);
 }
 if(!dialogReady)throw new Error('WAF Web Security Log: seleccioné «Without Attack Content», pero no apareció el formulario Export con Name y OK.');
 return exportNamedFirewallFormat(win,stageDir,date,category,'CSV','WAF',false,true);
}
async function runWafBackup(deviceId:number):Promise<{filename:string;file_count:number;path:string}>{
 const win=await openDeviceConsole(deviceId);if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');win.show();win.focus();
 const notify=(message:string)=>{for(const appWindow of BrowserWindow.getAllWindows())if(!appWindow.isDestroyed())appWindow.webContents.send('som:backup-progress',message)};
 notify('Esperando a que Hillstone WAF termine de iniciar sesión…');
 let loggedIn=false;
 for(let attempt=0;attempt<40;attempt++){
  if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');
  const state=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};return {loaded:document.readyState!=='loading'&&!!document.body,login:Array.from(document.querySelectorAll('input[type="password"]')).some(visible)}})()`,true) as {loaded:boolean;login:boolean};
  if(state.loaded&&!state.login){loggedIn=true;break}await delay(750);
 }
 if(!loggedIn)throw new Error('No pude confirmar la sesión del W620S. Inicia sesión en la ventana Hillstone y vuelve a intentar.');
 notify('Abriendo Monitor → Log → Event Log en el W620S…');await clickWafTopMenu(win,'Monitor');await delay(800);
 const stageDir=path.join(runtimeDataDir,'automation-staging',randomBytes(12).toString('hex'));fs.mkdirSync(stageDir,{recursive:true});
 const now=new Date();const date=`${String(now.getDate()).padStart(2,'0')}_${String(now.getMonth()+1).padStart(2,'0')}_${now.getFullYear()}`;const files:Array<{path:string;category:string;format:string}>=[];
 try{
  for(let index=0;index<wafLogCategories.length;index++){
   const category=wafLogCategories[index];notify(`Consultando WAF · ${category.label} (${index+1}/${wafLogCategories.length})`);
   await dismissConsoleDropdowns(win);
   if(category.key==='WEBSECURITYLOG')await win.webContents.executeJavaScript(`location.hash='#waflogwebsec/webseclogbasiclogtab'`,true);
   else await clickWafSidebarText(win,category.label);
   await delay(2200);
   if(category.key==='NATLOG')await selectWafNatBoth(win);else if(category.key==='WEBACCESSLOG')await selectWafCurrentHour(win);else if(category.key==='WEBSECURITYLOG')await selectWafToday(win);else await selectWafLast24Hours(win);
   const rows=await detectLogRows(win);
   if(rows==='unknown')throw new Error(`WAF ${category.label}: no pude confirmar si hay registros; se detuvo sin marcarlo como vacío.`);
   if(rows==='empty'){
    const evidencePath=path.join(stageDir,`WAF_${category.key}_${date}_SIN_LOGS.png`);const image=await win.webContents.capturePage();fs.writeFileSync(evidencePath,image.toPNG());files.push({path:evidencePath,category:category.key,format:'PNG'});continue;
   }
   if(category.key==='WEBSECURITYLOG'){
    notify('Exportando WAF · Web Security Log · CSV sin contenido de ataque…');const file=await exportWafWebSecurityLog(win,stageDir,date,category);files.push({path:file,category:category.key,format:path.extname(file).toLowerCase()==='.zip'?'ZIP':'CSV'});
   }else{
    notify(`Exportando WAF · ${category.label} · TXT preferido (CSV alternativo)…`);
    const exported=await exportPreferredFirewallFormat(win,stageDir,date,category,'WAF',true);
    files.push({path:exported.path,category:category.key,format:exported.format});await delay(1200)
   }
  }
  notify('Verificando y empaquetando el respaldo WAF…');
  const response=await fetch(`http://127.0.0.1:${port}/api/backups/internal/firewall-bundle`,{method:'POST',headers:{'X-SOM-Token':token,'Content-Type':'application/json'},body:JSON.stringify({device_id:deviceId,report_date:date,files})});
  const payload=await response.json() as {detail?:string;backup?:{filename:string};file_count?:number;path?:string};if(!response.ok||!payload.backup)throw new Error(payload.detail||'No se pudo registrar el respaldo WAF.');
  fs.rmSync(stageDir,{recursive:true,force:true});notify('Respaldo WAF completado.');return {filename:payload.backup.filename,file_count:payload.file_count??files.length,path:payload.path??''};
 }catch(error){fs.rmSync(stageDir,{recursive:true,force:true});notify('Respaldo WAF detenido; revisa el mensaje de error.');throw error}
}
const bdsLogCategories=[
 {label:'Threat Log',key:'THREATLOG'},
 {label:'Event Log',key:'EVENTLOG'},
 {label:'Network Log',key:'NETWORKLOG'},
 {label:'Configuration Log',key:'CONFIGURATIONLOG'},
 {label:'Session Log',key:'SESSIONLOG'}
] as const;
async function selectBdsLast24Hours(win:BrowserWindow,category:string){
 const state=await win.webContents.executeJavaScript(`(()=>{
  const norm=value=>(value||'').replace(/[\\u200B-\\u200D\\uFEFF]/g,'').replace(/\\s+/g,' ').trim();
  const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};
  // I1870 renders Detection Period as an ExtJS DateTimeSelector. Its generated
  // number changes, but the input id prefix/suffix and its value are stable.
  const periodInputs=Array.from(document.querySelectorAll('input[id^="datetimeselector-"][id$="-inputEl"]'));
  const periodInput=periodInputs.find(el=>visible(el)&&norm(el.value))||periodInputs.find(el=>norm(el.value));
  const selects=Array.from(document.querySelectorAll('select')).filter(visible);
  const periodSelect=selects.find(el=>Array.from(el.options).some(option=>/last\\s*24\\s*hours/i.test(option.text)));
  const fields=Array.from(document.querySelectorAll('input,button,[role="combobox"],[aria-haspopup="listbox"],.x-form-field')).filter(visible).map(el=>norm(el.value||el.innerText||el.getAttribute('aria-label')));
  const text=Array.from(document.querySelectorAll('body *')).filter(el=>visible(el)&&!Array.from(el.children).some(child=>norm(child.innerText||child.textContent)===norm(el.innerText||el.textContent))).map(el=>norm(el.innerText||el.textContent)).filter(value=>/^last\\s*24\\s*hours$/i.test(value));
  const body=norm(document.body?.innerText||'');
  const labeledPeriod=body.match(/detection\\s*period\\s*(last\\s*24\\s*hours|last\\s*\\d+\\s*(?:minutes?|hours?|days?)|today)/i)?.[1]||'';
  return {input:periodInput?{id:periodInput.id,value:norm(periodInput.value),visible:visible(periodInput)}:null,select:periodSelect?{value:norm(periodSelect.options[periodSelect.selectedIndex]?.text),option:periodSelect.options[periodSelect.selectedIndex]?.value||''}:null,fields,text,labeledPeriod};
 })()`,true) as {input:{id:string;value:string;visible:boolean}|null;select:{value:string;option:string}|null;fields:string[];text:string[];labeledPeriod:string};
 let current=state.input?.value||state.select?.value||state.fields.find(value=>/^last\\s*\\d+\\s*(minutes?|hours?|days?)|today$/i.test(value))||state.text[0]||state.labeledPeriod||'';
 if(!/last\\s*24\\s*hours/i.test(current)){
  if(state.select){
   const changed=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0};const select=Array.from(document.querySelectorAll('select')).find(el=>visible(el)&&Array.from(el.options).some(option=>/last\\s*24\\s*hours/i.test(option.text)));if(!select)return false;const option=Array.from(select.options).find(item=>/last\\s*24\\s*hours/i.test(item.text));const setter=Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set;setter.call(select,option.value);select.dispatchEvent(new Event('input',{bubbles:true}));select.dispatchEvent(new Event('change',{bubbles:true}));return true})()`,true) as boolean;
   if(!changed)throw new Error(`BDS ${category}: no pude elegir Last 24 Hours.`);
  }else{
   if(state.input?.id){const opened=await win.webContents.executeJavaScript(`(()=>{const input=document.getElementById(${JSON.stringify(state.input.id)});if(!input)return false;input.click();return true})()`,true) as boolean;if(!opened)throw new Error(`BDS ${category}: no pude abrir el control de periodo ${state.input.id}.`)}
   else if(current){if(!await clickConsoleTextIfPresent(win,current))throw new Error(`BDS ${category}: no pude abrir el periodo «${current}».`)}
   else throw new Error(`BDS ${category}: no pude leer el campo Detection Period; la página visible dice «${state.labeledPeriod||'sin valor reconocido'}».`);
   await delay(250);
   // ExtJS renders options as bound-list rows, not buttons/menu items, so use
   // the BDS text matcher which also resolves visible span/div option rows.
   try{await clickBdsConsoleText(win,'Last 24 Hours')}catch{throw new Error(`BDS ${category}: el desplegable no mostró Last 24 Hours.`)}
  }
 }
 await delay(350);
 if(await clickConsoleTextIfPresent(win,'Filter'))await delay(1800);else await delay(1200);
 await dismissConsoleDropdowns(win);
 const confirmed=await win.webContents.executeJavaScript(`(()=>{const norm=value=>(value||'').replace(/[\\u200B-\\u200D\\uFEFF]/g,'').replace(/\\s+/g,' ').trim();const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};const periodInputs=Array.from(document.querySelectorAll('input[id^="datetimeselector-"][id$="-inputEl"]'));const periodInput=periodInputs.find(el=>visible(el)&&norm(el.value))||periodInputs.find(el=>norm(el.value));const select=Array.from(document.querySelectorAll('select')).find(visible);const fields=Array.from(document.querySelectorAll('input,button,[role="combobox"],.x-form-field')).filter(visible).map(el=>norm(el.value||el.innerText||''));const body=norm(document.body?.innerText||'');return /^last\\s*24\\s*hours$/i.test(periodInput?.value||'')||/last\\s*24\\s*hours/i.test(select?.options[select.selectedIndex]?.text||'')||fields.some(value=>/^last\\s*24\\s*hours$/i.test(value))||Array.from(document.querySelectorAll('body *')).some(el=>visible(el)&&/^last\\s*24\\s*hours$/i.test(norm(el.innerText)))||/detection\\s*period\\s*last\\s*24\\s*hours/i.test(body)})()`,true) as boolean;
 if(!confirmed)throw new Error(`BDS ${category}: no pude confirmar Last 24 Hours.`);
}
async function exportBdsSessionLog(win:BrowserWindow,stageDir:string,date:string,category:{label:string;key:string}){
 await clickConsoleText(win,'Export');
 const filepath=path.join(stageDir,`BDS_${category.key}_${date}.download`);
 const pendingDownload=waitForHillstoneDownload(win,filepath,'TXT');
 try{
  let dialogReady=false;
  for(let attempt=0;attempt<40;attempt++){
   dialogReady=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();const roots=Array.from(document.querySelectorAll('[role="dialog"],.x-window,.x-panel,[id*="export"]')).filter(visible).filter(root=>/export/.test(norm(root.innerText)));return roots.some(root=>/separator/.test(norm(root.innerText))&&Array.from(root.querySelectorAll('button,a,[role="button"],.x-btn')).some(button=>visible(button)&&norm(button.innerText||button.value)==='ok'))})()`,true).catch(()=>false);
   if(dialogReady)break;await delay(250);
  }
  if(!dialogReady)throw new Error('BDS Session Log: no apareció el diálogo Export con el campo Separator.');
  const configured=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&s.visibility!=='hidden'&&s.display!=='none'};const norm=value=>(value||'').replace(/\\s+/g,' ').trim().toLowerCase();const buttons='button,a,[role="button"],input[type="button"],input[type="submit"],.x-btn';const leaves=(root,label)=>Array.from(root.querySelectorAll('*')).filter(el=>visible(el)&&norm(el.innerText||el.textContent)===label&&!Array.from(el.children).some(child=>norm(child.innerText||child.textContent)===label));const roots=Array.from(document.querySelectorAll('[role="dialog"],.x-window,.x-panel,[id*="export"]')).filter(visible).filter(root=>/export/.test(norm(root.innerText))&&/separator/.test(norm(root.innerText)));const matches=roots.filter(root=>Array.from(root.querySelectorAll(buttons)).some(button=>visible(button)&&norm(button.innerText||button.value)==='ok'));if(!matches.length)return {ok:false,error:'no encontré el panel Export'};matches.sort((a,b)=>{const ar=a.getBoundingClientRect(),br=b.getBoundingClientRect();return ar.width*ar.height-br.width*br.height});const root=matches[0];const labels=leaves(root,'separator');let field=null;for(const label of labels){let parent=label;while(parent&&parent!==root){const inputs=Array.from(parent.querySelectorAll('input:not([type="hidden"]),textarea,[role="textbox"]')).filter(input=>visible(input)&&!input.disabled&&!input.readOnly);if(inputs.length===1){field=inputs[0];break}parent=parent.parentElement}if(field)break}if(!field){const inputs=Array.from(root.querySelectorAll('input:not([type="hidden"]),textarea,[role="textbox"]')).filter(input=>visible(input)&&!input.disabled&&!input.readOnly);if(inputs.length===1)field=inputs[0]}if(!field)return {ok:false,error:'no encontré el campo Separator'};const value='';const setter=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')?.set;if(setter)setter.call(field,value);else field.value=value;field.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'deleteContent'}));field.dispatchEvent(new Event('change',{bubbles:true}));const componentId=field.id?.replace(/-inputEl$/,'');const component=window.Ext?.getCmp?.(componentId)||null;if(component?.setValue){component.setValue(value);component.setRawValue?.(value)}if(field.value!==value&&component?.getValue?.()!==value)return {ok:false,error:'no quedó vacío Separator'};const ok=Array.from(root.querySelectorAll(buttons)).filter(button=>visible(button)&&norm(button.innerText||button.value)==='ok');if(!ok.length)return {ok:false,error:'no encontré el botón OK'};ok[0].click();return {ok:true}})()`,true) as {ok:boolean;error?:string};
  if(!configured.ok)throw new Error(`BDS Session Log: ${configured.error||'no pude configurar Separator.'}`);
  await confirmWafSavePrompt(win);
  return await pendingDownload.promise;
 }catch(error){pendingDownload.cancel();await pendingDownload.promise.catch(()=>{});throw error}
}
async function runBdsBackup(deviceId:number):Promise<{filename:string;file_count:number;path:string}>{
 const win=await openDeviceConsole(deviceId);if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');if(win.isMinimized())win.restore();win.maximize();win.show();win.focus();await delay(350);
 const notify=(message:string)=>{for(const appWindow of BrowserWindow.getAllWindows())if(!appWindow.isDestroyed())appWindow.webContents.send('som:backup-progress',message)};
 notify('Esperando a que Hillstone BDS termine de iniciar sesión…');
 let loggedIn=false;
 for(let attempt=0;attempt<40;attempt++){
  if(win.isDestroyed())throw new Error('La ventana de la consola se cerró.');
  const state=await win.webContents.executeJavaScript(`(()=>{const visible=el=>{const r=el.getBoundingClientRect();return r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden'};return {loaded:document.readyState!=='loading'&&!!document.body,login:Array.from(document.querySelectorAll('input[type="password"]')).some(visible)}})()`,true) as {loaded:boolean;login:boolean};
  if(state.loaded&&!state.login){loggedIn=true;break}await delay(750);
 }
 if(!loggedIn)throw new Error('No pude confirmar la sesión del I1870. Inicia sesión en la ventana Hillstone y vuelve a intentar.');
 const stageDir=path.join(runtimeDataDir,'automation-staging',randomBytes(12).toString('hex'));fs.mkdirSync(stageDir,{recursive:true});
 const now=new Date();const date=`${String(now.getDate()).padStart(2,'0')}_${String(now.getMonth()+1).padStart(2,'0')}_${now.getFullYear()}`;const files:Array<{path:string;category:string;format:string}>=[];
 try{
  notify('Abriendo Log & Report en el I1870…');await clickBdsConsoleText(win,'Log & Report');await delay(1200);
  for(let index=0;index<bdsLogCategories.length;index++){
   const category=bdsLogCategories[index];notify(`Consultando BDS · ${category.label} (${index+1}/${bdsLogCategories.length})`);await dismissConsoleDropdowns(win);await clickBdsConsoleText(win,category.label);await delay(1800);await dismissConsoleDropdowns(win);
   if(category.key!=='SESSIONLOG')await selectBdsLast24Hours(win,category.label);
   const rows=await detectLogRows(win);
   if(rows==='unknown')throw new Error(`BDS ${category.label}: no pude confirmar si hay registros; se detuvo sin marcarlo como vacío.`);
   if(rows==='empty'){
    const evidencePath=path.join(stageDir,`BDS_${category.key}_${date}_SIN_LOGS.png`);const image=await win.webContents.capturePage();fs.writeFileSync(evidencePath,image.toPNG());files.push({path:evidencePath,category:category.key,format:'PNG'});continue;
   }
   if(category.key==='SESSIONLOG'){
    notify('Exportando BDS · Session Log…');const file=await exportBdsSessionLog(win,stageDir,date,category);files.push({path:file,category:category.key,format:path.extname(file).toLowerCase()==='.zip'?'ZIP':path.extname(file).toLowerCase()==='.txt'?'TXT':'CSV'});
   }else{
    notify(`Exportando BDS · ${category.label} · TXT preferido (CSV alternativo)…`);const exported=await exportPreferredFirewallFormat(win,stageDir,date,category,'BDS',true);const exportedPath=exported.path.toLowerCase();files.push({path:exported.path,category:category.key,format:exportedPath.endsWith('.tar.gz')?'TAR_GZ':path.extname(exported.path).toLowerCase()==='.zip'?'ZIP':exported.format});await delay(1200);
   }
  }
  notify('Verificando y empaquetando el respaldo BDS…');
  const response=await fetch(`http://127.0.0.1:${port}/api/backups/internal/firewall-bundle`,{method:'POST',headers:{'X-SOM-Token':token,'Content-Type':'application/json'},body:JSON.stringify({device_id:deviceId,report_date:date,files})});
  const payload=await response.json() as {detail?:string;backup?:{filename:string};file_count?:number;path?:string};if(!response.ok||!payload.backup)throw new Error(payload.detail||'No se pudo registrar el respaldo BDS.');
  fs.rmSync(stageDir,{recursive:true,force:true});notify('Respaldo BDS completado.');return {filename:payload.backup.filename,file_count:payload.file_count??files.length,path:payload.path??''};
 }catch(error){fs.rmSync(stageDir,{recursive:true,force:true});notify('Respaldo BDS detenido; revisa el mensaje de error.');throw error}
}
ipcMain.handle('som:run-firewall-backup',async(_event,deviceId:number)=>{
 if(!Number.isSafeInteger(deviceId)||deviceId<1)throw new Error('Identificador de dispositivo inválido');
 if(firewallBackupRuns.has(deviceId))throw new Error('Ya hay una ejecución de respaldo activa para este firewall.');
 firewallBackupRuns.add(deviceId);
 try{
  const response=await fetch(`http://127.0.0.1:${port}/api/devices`,{headers:{'X-SOM-Token':token}});
  if(!response.ok)throw new Error('No se pudieron cargar los dispositivos configurados');
  const devices=await response.json() as Array<{id:number;kind:string}>;const device=devices.find(item=>item.id===deviceId);
  if(!device||device.kind!=='FIREWALL')throw new Error('El respaldo automático inicial solo admite el firewall A2700.');
  return await runFirewallBackup(deviceId);
 }finally{firewallBackupRuns.delete(deviceId)}
});
ipcMain.handle('som:run-waf-backup',async(_event,deviceId:number)=>{
 if(!Number.isSafeInteger(deviceId)||deviceId<1)throw new Error('Identificador de dispositivo inválido');
 if(firewallBackupRuns.has(deviceId))throw new Error('Ya hay un respaldo activo para este dispositivo.');firewallBackupRuns.add(deviceId);
 try{
  const response=await fetch(`http://127.0.0.1:${port}/api/devices`,{headers:{'X-SOM-Token':token}});if(!response.ok)throw new Error('No se pudieron cargar los dispositivos configurados');
  const devices=await response.json() as Array<{id:number;kind:string}>;const device=devices.find(item=>item.id===deviceId);if(!device||device.kind!=='WAF')throw new Error('Selecciona el WAF W620S para iniciar este respaldo.');
  return await runWafBackup(deviceId);
 }finally{firewallBackupRuns.delete(deviceId)}
});
ipcMain.handle('som:run-bds-backup',async(_event,deviceId:number)=>{
 if(!Number.isSafeInteger(deviceId)||deviceId<1)throw new Error('Identificador de dispositivo inválido');
 if(firewallBackupRuns.has(deviceId))throw new Error('Ya hay un respaldo activo para este dispositivo.');firewallBackupRuns.add(deviceId);
 try{
  const response=await fetch(`http://127.0.0.1:${port}/api/devices`,{headers:{'X-SOM-Token':token}});if(!response.ok)throw new Error('No se pudieron cargar los dispositivos configurados');
  const devices=await response.json() as Array<{id:number;kind:string}>;const device=devices.find(item=>item.id===deviceId);if(!device||device.kind!=='BDS')throw new Error('Selecciona el BDS I1870 para iniciar este respaldo.');
  return await runBdsBackup(deviceId);
 }finally{firewallBackupRuns.delete(deviceId)}
});
type BackupScheduleKind='FIREWALL'|'WAF'|'BDS';
const backupScheduleTimers=new Map<BackupScheduleKind,NodeJS.Timeout>();
const scheduledBackupQueue=new Set<BackupScheduleKind>();
let scheduledBackupQueueRunning=false;
const backupScheduleOrder:BackupScheduleKind[]=['FIREWALL','WAF','BDS'];
async function scheduleApi(route:string,method='GET',body?:unknown){
 const response=await fetch(`http://127.0.0.1:${port}${route}`,{method,headers:{'X-SOM-Token':token,...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});
 if(!response.ok)throw new Error(`HTTP ${response.status} al consultar la programación`);
 return await response.json() as any;
}
function localScheduleDate(date:Date){return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}`}
function notifyScheduledBackup(message:string){for(const window of BrowserWindow.getAllWindows())if(!window.isDestroyed())window.webContents.send('som:backup-progress',message)}
async function runOneScheduledBackup(kind:BackupScheduleKind){
 const schedule=await scheduleApi('/api/settings/backup-schedule') as {jobs:Array<{kind:BackupScheduleKind;enabled:boolean;time:string;device_id:number|null;device_name:string|null;last_run_date:string|null;last_attempt_date:string|null}>};
 const now=new Date();const date=localScheduleDate(now);
 const currentTime=`${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
 const job=schedule.jobs.find(candidate=>candidate.kind===kind);
 if(!job?.enabled||job.last_run_date===date||currentTime<job.time)return 'idle' as const;
 // Keep each device's schedule/claim independent, but start due work in a
 // deterministic Firewall → WAF → BDS order. A failed predecessor counts as
 // attempted for sequencing; its own timer can retry it after the backoff.
 for(const earlierKind of backupScheduleOrder.slice(0,backupScheduleOrder.indexOf(kind))){
  const earlier=schedule.jobs.find(candidate=>candidate.kind===earlierKind);
  if(!earlier?.enabled||earlier.last_run_date===date||earlier.last_attempt_date===date)continue;
  if(currentTime<earlier.time)return 'waiting' as const;
  // Do not recurse into the predecessor: enqueue it as its own scheduled job
  // so failures and timeouts are isolated and the drain always resumes in order.
  scheduledBackupQueue.add(earlierKind);
  return 'waiting' as const;
 }
 if(job.device_id&&firewallBackupRuns.has(job.device_id))return 'waiting' as const;
 const claim=await scheduleApi('/api/settings/backup-schedule/claim','POST',{kind,run_date:date}) as {claimed:boolean;reason?:string};
 if(!claim.claimed)return claim.reason==='retry-backoff'?'backoff' as const:claim.reason==='already-completed'?'idle' as const:'waiting' as const;
 // Treat stale/missing device configuration as a failed attempt, not an idle
 // job. Otherwise the next task waits forever for this predecessor's attempt.
 if(!job.device_id){
  const message=`Respaldo ${kind}: falta seleccionar un dispositivo habilitado.`;
  try{await scheduleApi('/api/settings/backup-schedule/finish','POST',{kind,run_date:date,success:false,message})}
  catch(error){console.error(`[SOM] No se pudo registrar el fallo de configuración ${kind}: ${error instanceof Error?error.message:String(error)}`)}
  notifyScheduledBackup(`${message} Se registra el fallo y continúa la siguiente tarea.`);
  return 'failed' as const;
 }
 firewallBackupRuns.add(job.device_id);
 try{
  notifyScheduledBackup(`Respaldo ${kind} programado iniciado a las ${job.time} (hora local de esta PC)…`);
  const run=kind==='WAF'?runWafBackup:kind==='BDS'?runBdsBackup:runFirewallBackup;
  const result=await run(job.device_id);
  try{
   await scheduleApi('/api/settings/backup-schedule/finish','POST',{kind,run_date:date,success:true,message:result.filename});
   notifyScheduledBackup(`Respaldo ${kind} completado y guardado como tarea independiente: ${result.filename}`);
   console.info(`[SOM] Respaldo automático ${kind} completado y guardado: ${result.path}`);
  }catch(error){
   const message=error instanceof Error?error.message:String(error);
   console.error(`[SOM] Respaldo ${kind} quedó guardado (${result.path}), pero no se pudo actualizar su estado programado: ${message}`);
   notifyScheduledBackup(`Respaldo ${kind} guardado (${result.filename}), pero no se actualizó el estado del horario. Las demás tareas continúan.`);
  }
  return 'completed' as const;
 }catch(error){
  const message=error instanceof Error?error.message:String(error);
  console.error(`[SOM] Falló respaldo automático ${kind}: ${message}`);
  try{await scheduleApi('/api/settings/backup-schedule/finish','POST',{kind,run_date:date,success:false,message})}
  catch(finishError){console.error(`[SOM] No se pudo liberar el trabajo ${kind}: ${finishError instanceof Error?finishError.message:String(finishError)}`)}
  notifyScheduledBackup(`Falló respaldo ${kind}: ${message}. Quedó registrado; continúa la siguiente tarea y se reintentará en 5 minutos.`);
  return 'failed' as const;
 }finally{firewallBackupRuns.delete(job.device_id)}
}
async function drainScheduledBackupQueue(){
 if(scheduledBackupQueueRunning)return;
 scheduledBackupQueueRunning=true;
 try{
  while(scheduledBackupQueue.size){
   const kind=backupScheduleOrder.find(candidate=>scheduledBackupQueue.has(candidate));
   if(!kind)break;
   scheduledBackupQueue.delete(kind);
   let outcome:'idle'|'waiting'|'backoff'|'completed'|'failed'|'error';
   try{outcome=await runOneScheduledBackup(kind)}
   catch(error){
    const message=error instanceof Error?error.message:String(error);
    console.error(`[SOM] Error aislado en el trabajo programado ${kind}: ${message}`);
    notifyScheduledBackup(`No se pudo revisar o iniciar el respaldo ${kind}: ${message}. Se volverá a revisar en el siguiente ciclo.`);
    outcome='error';
   }
   if(outcome==='completed'||outcome==='failed'){
    // Re-read state after each distinct task, then run the next due job.
    for(const next of backupScheduleOrder)scheduledBackupQueue.add(next);
   }
  }
 }catch(error){
  const message=error instanceof Error?error.message:String(error);
  console.error(`[SOM] Falló la cola de respaldos programados: ${message}`);
  notifyScheduledBackup(`Falló la programación de respaldos: ${message}`);
 }finally{scheduledBackupQueueRunning=false}
}
function enqueueScheduledBackup(kind:BackupScheduleKind){scheduledBackupQueue.add(kind);void drainScheduledBackupQueue()}
function startBackupSchedule(){
 for(const timer of backupScheduleTimers.values())clearInterval(timer);
 backupScheduleTimers.clear();
 // Three independent clock ticks and persisted claims feed a serial queue.
 // Each queued item has its own backup call, success/failure audit, and bundle.
 for(const kind of ['FIREWALL','WAF','BDS'] as const){
  backupScheduleTimers.set(kind,setInterval(()=>enqueueScheduledBackup(kind),20000));
 }
 for(const kind of backupScheduleOrder)enqueueScheduledBackup(kind);
}
ipcMain.handle('som:open-sophos-policies',async()=>{await shell.openExternal('https://fusion.sophos.com/manage/endpoint/policies/list');});
app.whenReady().then(async()=>{try{await startBackend();makeWindow();startBackupSchedule()}catch(error){const message=error instanceof Error?`${error.message}${error.stack?`\n${error.stack}`:''}`:String(error);console.error(`[SOM] Error durante el arranque: ${message}`);dialog.showErrorBox('No se pudo iniciar SOM',message);app.exit(1)}});
app.on('before-quit',()=>{for(const timer of backupScheduleTimers.values())clearInterval(timer);backupScheduleTimers.clear();if(backend&&!backend.killed)backend.kill();});
app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit();});
