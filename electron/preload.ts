import { contextBridge, ipcRenderer } from 'electron';
async function request(path:string,options:Pick<RequestInit,'method'|'body'>={}){
 const result=await ipcRenderer.invoke('som:api-request',path,options) as {status:number;body:string};
 if(result.status<200||result.status>=300){let message=result.body||`HTTP ${result.status}`;try{const parsed=JSON.parse(result.body);message=parsed.detail||message}catch{}throw new Error(message)}
 return result.body?JSON.parse(result.body):null;
}
contextBridge.exposeInMainWorld('som',{
 api:request,
 health:async()=>Boolean(await ipcRenderer.invoke('som:health')),
 importBackup:(deviceId:number,filePath:string)=>request('/api/backups/import',{method:'POST',body:JSON.stringify({device_id:deviceId,path:filePath})}),
 openExternal:(url:string)=>ipcRenderer.invoke('som:open-external',url),
 openDeviceConsole:(deviceId:number)=>ipcRenderer.invoke('som:open-device-console',deviceId),
 runFirewallBackup:(deviceId:number)=>ipcRenderer.invoke('som:run-firewall-backup',deviceId),
 runWafBackup:(deviceId:number)=>ipcRenderer.invoke('som:run-waf-backup',deviceId),
 onBackupProgress:(callback:(message:string)=>void)=>{const listener=(_event:Electron.IpcRendererEvent,message:string)=>callback(message);ipcRenderer.on('som:backup-progress',listener);return()=>ipcRenderer.removeListener('som:backup-progress',listener)},
 openSophosPolicies:()=>ipcRenderer.invoke('som:open-sophos-policies'),
 selectFiles:()=>ipcRenderer.invoke('som:select-files'),
 selectDirectory:()=>ipcRenderer.invoke('som:select-directory'),
 downloadBackup:(backupId:number)=>ipcRenderer.invoke('som:download-backup',backupId)
});
