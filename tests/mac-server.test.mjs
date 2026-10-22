import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn,execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const install=path.join(repo,'scripts/setup-mac-server.sh');
const sandbox=await fs.mkdtemp(path.join(os.tmpdir(),'remote-network-tests-'));
const exists=p=>fs.access(p).then(()=>true,()=>false);
const run=(cmd,args,env)=>new Promise((resolve,reject)=>{
  const child=spawn(cmd,args,{env,stdio:['ignore','pipe','pipe']});let output='';
  child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);
  const timer=setTimeout(()=>child.kill('SIGTERM'),20000);
  child.on('error',reject);child.on('close',code=>{clearTimeout(timer);resolve({code,output});});
});
async function fixture(){
  const base=await fs.mkdtemp(path.join(sandbox,'case-')),home=path.join(base,'home space 中文'),bin=path.join(base,'bin');
  await fs.mkdir(home);await fs.mkdir(bin);await fs.mkdir(path.join(home,'.config'));
  await fs.writeFile(path.join(home,'.config/unrelated.json'),'KEEP_USER_CONFIG');await fs.writeFile(path.join(home,'.zshrc'),'KEEP_SHELL_CONFIG');
  const key=path.join(base,'client');execFileSync('/usr/bin/ssh-keygen',['-q','-t','ed25519','-N','','-f',key]);
  const publicKey=(await fs.readFile(key+'.pub','utf8')).trim().split(' ').slice(0,2).join(' ');
  const root=path.join(home,'Library/Application Support/RemoteSSHServer'),log=path.join(base,'commands.jsonl');
  const write=async(name,body)=>fs.writeFile(path.join(bin,name),`#!${process.execPath}\n${body}`,{mode:0o700});
  const record=`const fs=require('fs');fs.appendFileSync(process.env.TEST_LOG,JSON.stringify({name:require('path').basename(process.argv[1]),args:process.argv.slice(2)})+'\\n');`;
  await write('sudo',record+`if(process.argv.includes('-getremotelogin')){if(process.env.QUERY_BAD)process.exit(2);console.log(process.env.LOGIN_BAD?'Remote Login: Off':'Remote Login: On');}if(process.argv.includes('-setremotelogin')&&process.env.LOGIN_BAD)process.exit(1);`);
  await write('tailscale',record+`const a=process.argv.slice(2);if(a[0]==='status')console.log(JSON.stringify({BackendState:process.env.TAILNET_BAD?'NeedsLogin':'Running'}));if(a[0]==='ip')console.log('100.90.2.3');if(a[0]==='whois'&&process.env.PEER_BAD)process.exit(1);`);
  await write('open',record);await write('nc',record+`process.exit(process.env.SSH_BAD||process.env.LOGIN_BAD||process.env.QUERY_BAD?1:0);`);
  await write('curl',record+`console.error('FORBIDDEN_DOWNLOAD');process.exit(97);`);
  await write('sw_vers',`console.log('26.3');`);await write('sleep',`setTimeout(()=>{},100);`);
  await write('awk',`if(process.argv.at(-1)==='/etc/ssh/ssh_host_ed25519_key.pub')console.log(process.env.TEST_PUBLIC_KEY);else{const r=require('child_process').spawnSync('/usr/bin/awk',process.argv.slice(2),{stdio:'inherit'});process.exit(r.status);}`);
  const input={schemaVersion:1,jumpHost:'203.0.113.10',jumpPort:2222,jumpTailnetIp:'100.80.0.1',jumpHostKey:publicKey,clientPublicKey:publicKey+' home client'};
  const config=path.join(base,'setup.json');await fs.writeFile(config,JSON.stringify(input));
  const env={...process.env,HOME:home,PATH:`${bin}:${process.env.PATH}`,TEST_LOG:log,TEST_PUBLIC_KEY:publicKey};
  const deploy=(flags=[],patch={})=>run('/bin/bash',[install,'--on-server','--config',config,...flags],{...env,...patch});
  return {base,home,bin,root,input,config,env,deploy,publicKey,log};
}
try{
  await test('one JSON preflight leaves no persistent files, network, or privileged effects',async()=>{
    const f=await fixture();const r=await f.deploy(['--preflight']);assert.equal(r.code,0,r.output);assert.match(r.output,/PREFLIGHT_OK/);
    assert.equal(await exists(f.root),false);assert.equal(await exists(f.log),false);
  });
  await test('network setup and rerun preserve user settings and keys; receipt is network-only',async()=>{
    const f=await fixture();await fs.mkdir(path.join(f.home,'.ssh'));await fs.writeFile(path.join(f.home,'.ssh/authorized_keys'),'# keep existing entries\n');
    const r=await f.deploy();assert.equal(r.code,0,r.output);assert.match(r.output,/SERVER_LOCAL_READY/);
    const auth=await fs.readFile(path.join(f.home,'.ssh/authorized_keys'),'utf8');assert.match(auth,/^# keep existing/m);assert.match(auth,/from="100.80.0.1",no-agent-forwarding,no-port-forwarding,no-X11-forwarding/);
    const second=await f.deploy();assert.equal(second.code,0,second.output);assert.equal(await fs.readFile(path.join(f.home,'.ssh/authorized_keys'),'utf8'),auth);
    assert.equal(await fs.readFile(path.join(f.home,'.config/unrelated.json'),'utf8'),'KEEP_USER_CONFIG');assert.equal(await fs.readFile(path.join(f.home,'.zshrc'),'utf8'),'KEEP_SHELL_CONFIG');
    const receipt=JSON.parse(await fs.readFile(path.join(f.root,'server-receipt.json'),'utf8'));
    assert.deepEqual(Object.keys(receipt).sort(),['schemaVersion','kind','serverOs','serverReady','host','port','user','hostKey','jumpHost','jumpPort','jumpTailnetIp','jumpHostKey','clientKeyFingerprint'].sort());
    assert.equal(receipt.kind,'remote-ssh');assert.equal(receipt.serverReady,true);assert.equal(receipt.host,'100.90.2.3');assert.equal(receipt.jumpPort,2222);assert.match(receipt.clientKeyFingerprint,/^SHA256:/);
    assert.equal((await fs.stat(path.join(f.home,'.ssh/authorized_keys'))).mode&0o777,0o600);
    const commands=(await fs.readFile(f.log,'utf8')).trim().split('\n').map(JSON.parse);
    assert.ok(commands.every(e=>['tailscale','nc'].includes(e.name)));assert.ok(commands.every(e=>!['up','logout','set'].includes(e.args[0])));
    assert.equal(await exists(path.join(f.root,'bin')),false);assert.equal(await exists(path.join(f.home,'Projects')),false);
  });
  await test('legacy file and inline public key share a fingerprint and do not duplicate authorization',async()=>{
    const f=await fixture();assert.equal((await f.deploy()).code,0);const auth=await fs.readFile(path.join(f.home,'.ssh/authorized_keys'),'utf8');
    const {clientPublicKey,...input}=f.input;await fs.writeFile(path.join(f.base,'client.pub'),clientPublicKey+'\n');await fs.writeFile(f.config,JSON.stringify({...input,clientPublicKeyFile:'./client.pub'}));
    const r=await f.deploy();assert.equal(r.code,0,r.output);assert.equal(await fs.readFile(path.join(f.home,'.ssh/authorized_keys'),'utf8'),auth);
  });
  for(const [name,patch] of Object.entries({bad_peer:{jumpTailnetIp:'100.80.999.1'},untrusted_host:{jumpHost:'x; touch PWNED'},bad_host_key:{jumpHostKey:'ssh-ed25519 YWJj'},secret_field:{password:'DO_NOT_ECHO'},unrelated_field:{service:'anything'},both_keys:{clientPublicKeyFile:'missing.pub'},empty_key:{clientPublicKey:''},array_key:{clientPublicKey:[]},null_key:{clientPublicKey:null},malformed_key:{clientPublicKey:'ssh-ed25519 YWJj'},multiple_keys:{clientPublicKey:'ssh-ed25519 YWJj\nssh-ed25519 YWJj'},private_key:{clientPublicKey:'-----BEGIN OPENSSH PRIVATE KEY-----\nDO_NOT_ECHO'},ssh_options:{clientPublicKey:'from="*" ssh-ed25519 YWJj'}})){
    await test(`reject ${name} before installation`,async()=>{
      const f=await fixture();await fs.writeFile(f.config,JSON.stringify({...f.input,...patch}));const r=await f.deploy();assert.notEqual(r.code,0);assert.doesNotMatch(r.output,/DO_NOT_ECHO/);assert.equal(await exists(f.root),false);assert.equal(await exists(f.log),false);
    });
  }
  await test('missing public key cannot silently authorize anything',async()=>{
    const f=await fixture();delete f.input.clientPublicKey;await fs.writeFile(f.config,JSON.stringify(f.input));assert.match((await f.deploy()).output,/MISSING_INPUT/);assert.equal(await exists(f.log),false);
  });
  await test('existing restricted authorization with a different comment is reused; wider authorization is refused',async()=>{
    const f=await fixture();await fs.mkdir(path.join(f.home,'.ssh'));const auth=path.join(f.home,'.ssh/authorized_keys');
    const original='from="100.80.0.1",no-agent-forwarding,no-port-forwarding,no-X11-forwarding '+f.publicKey+' old comment\n';await fs.writeFile(auth,original);
    assert.equal((await f.deploy()).code,0);assert.equal(await fs.readFile(auth,'utf8'),original);
    const g=await fixture();await fs.mkdir(path.join(g.home,'.ssh'));await fs.writeFile(path.join(g.home,'.ssh/authorized_keys'),g.publicKey+' unrestricted\n');assert.match((await g.deploy()).output,/KEY_POLICY_CONFLICT/);assert.equal(await exists(g.log),false);
  });
  for(const [flag,code] of [['TAILNET_BAD',20],['PEER_BAD',20],['LOGIN_BAD',21],['SSH_BAD',22],['QUERY_BAD',21]]){
    await test(`${flag} stops at the failing layer and can resume`,async()=>{
      const f=await fixture();let r=await f.deploy(['--wait-seconds','1'],{[flag]:'1'});assert.equal(r.code,code,r.output);assert.equal(await exists(path.join(f.root,'server-receipt.json')),false);
      if(flag==='QUERY_BAD'){const commands=(await fs.readFile(f.log,'utf8')).trim().split('\n').map(JSON.parse);assert.ok(commands.every(e=>!e.args.includes('-setremotelogin')));}
      r=await f.deploy();assert.equal(r.code,0,r.output);
    });
  }
  await test('rerun failure archives earlier receipt instead of leaving false current readiness',async()=>{
    const f=await fixture();assert.equal((await f.deploy()).code,0);const r=await f.deploy([],{PEER_BAD:'1'});assert.equal(r.code,20);assert.equal(await exists(path.join(f.root,'server-receipt.json')),false);assert.equal(JSON.parse(await fs.readFile(path.join(f.root,'install-status.json'),'utf8')).state,'blocked');
  });
  await test('changed inputs require an explicit migration',async()=>{
    const f=await fixture();assert.equal((await f.deploy()).code,0);const auth=await fs.readFile(path.join(f.home,'.ssh/authorized_keys'),'utf8');await fs.writeFile(f.config,JSON.stringify({...f.input,jumpPort:2223}));assert.match((await f.deploy()).output,/INPUT_CHANGED/);assert.equal(await fs.readFile(path.join(f.home,'.ssh/authorized_keys'),'utf8'),auth);
  });
  await test('client role, missing explicit server flag, unmanaged paths and symlinks fail closed',async()=>{
    const f=await fixture();const marker=path.join(f.home,'Library/Application Support/RemoteSSHClient');await fs.mkdir(marker,{recursive:true});await fs.writeFile(path.join(marker,'.managed-client'),'');assert.match((await f.deploy()).output,/CLIENT_MACHINE/);
    const g=await fixture();assert.equal((await run('/bin/bash',[install,'--config',g.config],g.env)).code,2);await fs.mkdir(g.root,{recursive:true});assert.match((await g.deploy()).output,/UNMANAGED_DIRECTORY/);
    const h=await fixture();await fs.mkdir(path.join(h.home,'.ssh'));await fs.symlink(h.config,path.join(h.home,'.ssh/authorized_keys'));assert.match((await h.deploy()).output,/UNSAFE_PATH/);assert.equal(await exists(h.log),false);
  });
  await test('active installation lock refuses parallel mutation',async()=>{
    const f=await fixture();await fs.mkdir(path.join(f.root,'.install.lock'),{recursive:true});await fs.writeFile(path.join(f.root,'.managed-server'),'');await fs.writeFile(path.join(f.root,'.install.lock/pid'),String(process.pid));assert.match((await f.deploy()).output,/INSTALL_RUNNING/);assert.equal(await exists(f.log),false);
  });
}finally{await fs.rm(sandbox,{recursive:true,force:true});}
