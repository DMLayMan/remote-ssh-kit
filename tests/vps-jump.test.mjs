import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),sandbox=await fs.mkdtemp(path.join(os.tmpdir(),'remote-jump-tests-'));
const source=await fs.readFile(path.join(repo,'scripts/init-vps.sh'),'utf8');
const exists=p=>fs.access(p).then(()=>true,()=>false);
const run=(file,args,env)=>new Promise((resolve,reject)=>{const child=spawn('/bin/bash',[file,...args],{env,stdio:['ignore','pipe','pipe']});let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('error',reject);const timer=setTimeout(()=>child.kill('SIGTERM'),20000);child.on('close',code=>{clearTimeout(timer);resolve({code,output});});});
async function fixture(){
  const base=await fs.mkdtemp(path.join(sandbox,'case-')),bin=path.join(base,'bin'),ssh=path.join(base,'etc/ssh'),root=path.join(base,'opt/remote-ssh-kit'),account=path.join(base,'var/lib/remote-jump');
  await fs.mkdir(bin);await fs.mkdir(path.join(ssh,'sshd_config.d'),{recursive:true});
  const key=path.join(base,'host-key');execFileSync('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',key]);
  const data=(await fs.readFile(key+'.pub','utf8')).trim().split(/\s+/)[1];
  const config=path.join(ssh,'sshd_config');await fs.writeFile(config,`HostKey ${key}\nInclude ${ssh}/sshd_config.d/*\n`);
  // Transform only the TEST COPY: no root bypass or path override is shipped.
  const guard="[[ $EUID == 0 ]] || { echo 'Run as root on the VPS.' >&2; exit 1; }";assert.ok(source.includes(guard));
  const copy=source.replace(guard,': # isolated fixture only').replaceAll('/opt/remote-ssh-kit',root).replaceAll('/var/lib/remote-jump',account).replaceAll('/etc/ssh',ssh).replaceAll('/usr/sbin/sshd',path.join(bin,'sshd'));
  const file=path.join(base,'init-vps.sh');await fs.writeFile(file,copy);
  const log=path.join(base,'events.jsonl'),record=`const fs=require('fs');fs.appendFileSync(process.env.EVENTS,JSON.stringify({name:require('path').basename(process.argv[1]),args:process.argv.slice(2)})+'\\n');`;
  const mock=(name,body)=>fs.writeFile(path.join(bin,name),`#!${process.execPath}\n${body}`,{mode:0o700});
  await mock('tailscale',record+`console.log(process.env.WRONG_IP?'100.80.0.2':'100.80.0.1');`);
  await mock('getent',`process.exit(require('fs').existsSync(process.env.ACCOUNT)?0:1);`);
  await mock('useradd',record+`fs.mkdirSync(process.env.ACCOUNT,{recursive:true});`);
  await mock('usermod',record);await mock('chown',record);
  await mock('install',record+`const a=process.argv.slice(2),p=a.at(-1);fs.mkdirSync(p,{recursive:true});fs.chmodSync(p,parseInt(a[a.indexOf('-m')+1],8));`);
  await mock('systemctl',record+`if(process.argv.includes('reload')&&process.env.RELOAD_BAD&&!fs.existsSync(process.env.RELOAD_MARK)){fs.writeFileSync(process.env.RELOAD_MARK,'');process.exit(7);}`);
  await mock('sshd',record+`if(process.env.SSHD_BAD)process.exit(8);const a=process.argv.slice(2);const r=require('child_process').spawnSync('/usr/sbin/sshd',[...a,'-f',process.env.BASE_CONFIG],{stdio:'inherit'});process.exit(r.status);`);
  const env={...process.env,PATH:bin+':'+process.env.PATH,EVENTS:log,ACCOUNT:account,BASE_CONFIG:config,RELOAD_MARK:path.join(base,'reload.failed')};
  const deploy=(host='100.90.2.3',patch={})=>run(file,[host,'22',data,'100.80.0.1'],{...env,...patch});
  return {base,root,account,config,log,deploy,conf:path.join(ssh,'sshd_config.d/60-remote-ssh-jump.conf'),auth:path.join(account,'.ssh/authorized_keys')};
}
try{
  await test('VPS setup emits restricted effective sshd policy, retains keys and repeats without duplication',async()=>{
    const f=await fixture();let r=await f.deploy();assert.equal(r.code,0,r.output);assert.match(r.output,/VPS_JUMP_READY/);
    const auth=await fs.readFile(f.auth,'utf8');assert.match(auth,/restrict,port-forwarding,permitopen="100.90.2.3:22",command="\/bin\/false"/);
    r=await f.deploy();assert.equal(r.code,0,r.output);assert.equal(await fs.readFile(f.auth,'utf8'),auth);assert.equal(await fs.readFile(path.join(f.root,'target'),'utf8'),'100.90.2.3:22\n');assert.equal(await exists(path.join(f.root,'.setup.lock')),false);
    const effective=execFileSync('/usr/sbin/sshd',['-T','-f',f.config,'-C','user=remote-jump,host=localhost,addr=127.0.0.1'],{encoding:'utf8'});
    for(const line of ['permitopen 100.90.2.3:22','forcecommand /bin/false','permittty no','passwordauthentication no','allowtcpforwarding local','allowagentforwarding no'])assert.ok(effective.split('\n').includes(line),line);
  });
  await test('different target is rejected without modifying active SSH configuration',async()=>{
    const f=await fixture();assert.equal((await f.deploy()).code,0);const before=await fs.readFile(f.conf,'utf8'),auth=await fs.readFile(f.auth,'utf8');const r=await f.deploy('100.90.2.4');assert.notEqual(r.code,0);assert.match(r.output,/TARGET_CONFLICT/);assert.equal(await fs.readFile(f.conf,'utf8'),before);assert.equal(await fs.readFile(f.auth,'utf8'),auth);
  });
  for(const flag of ['SSHD_BAD','RELOAD_BAD'])await test(`${flag} restores previous config and keys and releases lock`,async()=>{
    const f=await fixture();assert.equal((await f.deploy()).code,0);const conf=await fs.readFile(f.conf,'utf8'),auth=await fs.readFile(f.auth,'utf8');const r=await f.deploy('100.90.2.3',{[flag]:'1'});assert.notEqual(r.code,0);assert.equal(await fs.readFile(f.conf,'utf8'),conf);assert.equal(await fs.readFile(f.auth,'utf8'),auth);assert.equal(await exists(path.join(f.root,'.setup.lock')),false);
  });
  await test('wrong VPS identity is rejected before account or filesystem provisioning',async()=>{
    const f=await fixture();const r=await f.deploy('100.90.2.3',{WRONG_IP:'1'});assert.notEqual(r.code,0);assert.equal(await exists(f.root),false);assert.equal(await exists(f.account),false);
  });
}finally{await fs.rm(sandbox,{recursive:true,force:true});}
