import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),scripts=path.join(repo,'scripts');
const run=(cmd,args,env=process.env)=>new Promise((resolve,reject)=>{
  const child=spawn(cmd,args,{env,stdio:['ignore','pipe','pipe']});let output='';
  child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);
  const timer=setTimeout(()=>child.kill('SIGTERM'),20000);child.on('error',reject);child.on('close',code=>{clearTimeout(timer);resolve({code,output});});
});
const ok=async(cmd,args,env)=>{const r=await run(cmd,args,env);assert.equal(r.code,0,r.output);return r;};
const exists=p=>fs.access(p).then(()=>true,()=>false);
const root=await fs.mkdtemp(path.join(os.tmpdir(),'remote-ssh-client-tests-')),home=path.join(root,'home with spaces 中文'),client=path.join(home,'Library/Application Support/RemoteSSHClient'),bin=path.join(root,'mock-bin'),capture=path.join(root,'ssh.jsonl'),receiptFile=path.join(root,'receipt.json');
const env={...process.env,HOME:home,PATH:`${bin}:${process.env.PATH}`,CAPTURE:capture};
await fs.mkdir(bin);await fs.mkdir(path.join(home,'.local/bin'),{recursive:true});await fs.mkdir(path.join(home,'.ssh'));
await fs.writeFile(path.join(home,'.ssh/config'),'KEEP_GLOBAL_SSH');await fs.writeFile(path.join(home,'.zshrc'),'KEEP_SHELL');
const mock=(name,body)=>fs.writeFile(path.join(bin,name),`#!${process.execPath}\n${body}`,{mode:0o700});
await mock('ssh',`require('fs').appendFileSync(process.env.CAPTURE,JSON.stringify(process.argv.slice(2))+'\\n');if(!process.env.WRONG_REPLY)console.log('REMOTE_SSH_OK');process.exit(Number(process.env.SSH_EXIT||0));`);
for(const name of ['tailscale','tailscaled'])await mock(name,`console.error('FORBIDDEN_LOCAL_NETWORK_DAEMON');process.exit(97);`);
const events=async()=>{const text=await fs.readFile(capture,'utf8');return text.trim()?text.trim().split('\n').map(JSON.parse):[];};
try{
  await test('client preparation generates only a dedicated key and launcher without VPN or connections',async()=>{
    const r=await ok('/bin/bash',[path.join(scripts,'install-mac-client.sh'),'--prepare-only'],env);assert.match(r.output,/clientPublicKey: ssh-ed25519 /);assert.equal(await exists(capture),false);
    assert.equal((await fs.stat(path.join(client,'ssh/id_ed25519'))).mode&0o777,0o600);assert.equal(await fs.readFile(path.join(home,'.ssh/config'),'utf8'),'KEEP_GLOBAL_SSH');assert.equal(await fs.readFile(path.join(home,'.zshrc'),'utf8'),'KEEP_SHELL');
  });
  const pub=(await fs.readFile(path.join(client,'client-key.pub'),'utf8')).trim().split(/\s+/).slice(0,2).join(' '),fp=(await ok('/usr/bin/ssh-keygen',['-lf',path.join(client,'client-key.pub'),'-E','sha256'])).output.trim().split(/\s+/)[1];
  const receipt={schemaVersion:1,kind:'remote-ssh',serverReady:true,jumpHost:'203.0.113.10',jumpPort:2222,jumpTailnetIp:'100.80.0.1',jumpHostKey:pub,clientKeyFingerprint:fp,serverOs:'macos',host:'100.90.2.3',user:'remote_user',port:22,hostKey:pub};
  await fs.writeFile(receiptFile,JSON.stringify(receipt));
  await test('offline config pins both hosts and disables agent forwarding',async()=>{
    const r=await ok('/bin/bash',[path.join(scripts,'install-mac-client.sh'),'--receipt',receiptFile,'--no-provision'],env);assert.match(r.output,/CLIENT_CONFIGURED_OFFLINE/);
    const result=await ok('/usr/bin/ssh',['-G','-F',path.join(client,'ssh/config'),'remote-ssh-server']);assert.match(result.output,/^proxycommand .*ssh .* -W %h:%p remote-ssh-jump$/m);assert.match(result.output,/^hostname 100\.90\.2\.3$/m);assert.match(result.output,/^stricthostkeychecking true$/m);assert.match(result.output,/^forwardagent no$/m);assert.match(result.output,/^identityagent none$/m);
    const jump=await ok('/usr/bin/ssh',['-G','-F',path.join(client,'ssh/config'),'remote-ssh-jump']);assert.match(jump.output,/^user remote-jump$/m);assert.equal(await exists(capture),false);
    for(const config of [result,jump]){assert.match(config.output,/^batchmode yes$/m);assert.match(config.output,/^preferredauthentications publickey$/m);}
  });
  await test('two real SSH processes open the dedicated config with spaces without reaching a network',async()=>{
    const file=path.join(client,'ssh/config'),original=await fs.readFile(file,'utf8');
    try{await fs.writeFile(file,original.replace('Host remote-ssh-jump\n','Host remote-ssh-jump\n    ProxyCommand /bin/sh -c "echo JUMP_CONFIG_READ >&2; exit 1"\n'));
      const r=await run('/usr/bin/ssh',['-F',file,'-T','-o','BatchMode=yes','remote-ssh-server','true'],env);assert.match(r.output,/JUMP_CONFIG_READ/);assert.doesNotMatch(r.output,/Can't open user config file/);assert.notEqual(r.code,0);
    }finally{await fs.writeFile(file,original);}
  });
  await test('default command opens a remote login shell without an application command',async()=>{
    await fs.writeFile(capture,'');await ok('/bin/bash',[path.join(home,'.local/bin/remote-ssh')],env);assert.deepEqual((await events())[0],['-F',path.join(client,'ssh/config'),'-tt','remote-ssh-server']);
  });
  await test('check uses only fixed identity commands, no TTY or password prompt',async()=>{
    await fs.writeFile(capture,'');const r=await ok('/bin/bash',[path.join(home,'.local/bin/remote-ssh'),'--check'],env);assert.match(r.output,/SSH_CHAIN_READY/);const args=(await events())[0];assert.ok(args.includes('-T'));assert.ok(args.includes('BatchMode=yes'));assert.match(args.at(-1),/^test .*\/usr\/bin\/id -un.*remote_user.*\/usr\/bin\/uname -s.*Darwin.*REMOTE_SSH_OK/);
  });
  await test('SSH errors and missing identity marker fail acceptance',async()=>{
    const args=[path.join(home,'.local/bin/remote-ssh'),'--check'];assert.equal((await run('/bin/bash',args,{...env,SSH_EXIT:'255'})).code,255);const r=await run('/bin/bash',args,{...env,WRONG_REPLY:'1'});assert.notEqual(r.code,0);assert.match(r.output,/SSH_CHECK_FAILED/);
  });
  await test('latest failed check replaces previous ready status; offline import is pending',async()=>{
    const args=[path.join(home,'.local/bin/remote-ssh'),'--check'];
    const status=async()=>JSON.parse(await fs.readFile(path.join(client,'client-acceptance.json'),'utf8'));
    await ok('/bin/bash',args,env);assert.equal((await status()).state,'ready');
    assert.equal((await run('/bin/bash',args,{...env,SSH_EXIT:'255'})).code,255);
    assert.equal((await status()).state,'failed');assert.equal((await status()).exitCode,255);
    await ok('/bin/bash',[path.join(scripts,'install-mac-client.sh'),'--receipt',receiptFile,'--no-provision'],env);
    assert.equal((await status()).state,'pending');
  });
  await test('unknown launcher options cannot become remote commands',async()=>{
    await fs.writeFile(capture,'');const r=await run('/bin/bash',[path.join(home,'.local/bin/remote-ssh'),'--service','x'],env);assert.equal(r.code,2);assert.equal((await events()).length,0);
  });
  await test('invalid or missing client inputs cannot retain an earlier ready check',async()=>{
    const args=[path.join(home,'.local/bin/remote-ssh'),'--check'];
    const localReceipt=path.join(client,'receipt.json'),config=path.join(client,'ssh/config');
    const originalConfig=await fs.readFile(config);
    for(const missing of [false,true]){
      await ok('/bin/bash',args,env);await fs.writeFile(capture,'');
      if(missing)await fs.unlink(config);else await fs.writeFile(localReceipt,'{}');
      try {
        assert.notEqual((await run('/bin/bash',args,env)).code,0);assert.equal((await events()).length,0);
        const status=JSON.parse(await fs.readFile(path.join(client,'client-acceptance.json'),'utf8'));
        assert.equal(status.state,'failed');assert.equal(status.stage,'client-preflight');
      }finally{await fs.writeFile(config,originalConfig);await fs.writeFile(localReceipt,JSON.stringify(receipt));}
    }
  });
  await test('failed root provisioning records its exit code and does not attempt daily SSH',async()=>{
    await fs.writeFile(capture,'');
    const r=await run('/bin/bash',[path.join(scripts,'install-mac-client.sh'),'--receipt',receiptFile],{...env,SSH_EXIT:'255'});
    assert.equal(r.code,255);assert.match(r.output,/VPS_SETUP_FAILED/);assert.match(r.output,/--export-vps-command/);
    assert.equal((await events()).length,1);
    const status=JSON.parse(await fs.readFile(path.join(client,'client-acceptance.json'),'utf8'));
    assert.equal(status.state,'failed');assert.equal(status.stage,'jump-setup');assert.equal(status.exitCode,255);
  });
  await test('provisioning sets the receipt target then checks only SSH identity',async()=>{
    await fs.writeFile(capture,'');const r=await ok('/bin/bash',[path.join(scripts,'install-mac-client.sh'),'--receipt',receiptFile],env);assert.match(r.output,/CLIENT_CHAIN_READY/);const e=await events();assert.equal(e.length,2);assert.equal(e[0][e[0].indexOf('-p')+1],'2222');assert.ok(e[0].includes('root@203.0.113.10'));assert.match(e[0].at(-1),/bash -s -- 100\.90\.2\.3 22 [A-Za-z0-9+/=]+ 100\.80\.0\.1$/);assert.match(e[1].at(-1),/REMOTE_SSH_OK/);
  });
  for(const [name,patch] of Object.entries({public_host:{host:'example.com'},same_target:{host:'100.80.0.1'},wrong_client:{clientKeyFingerprint:'SHA256:wrong'},bad_jump:{jumpHost:'host;evil'},bad_jump_ip:{jumpTailnetIp:'100.80.999.1'},not_ready:{serverReady:false},string_ready:{serverReady:'true'},malformed_key:{hostKey:'ssh-ed25519 YWJj'},bad_user:{user:'x\nProxyCommand evil'},key_injection:{hostKey:pub+'\nextra'},wrong_os:{serverOs:'linux'},old_receipt:{kind:'different'},unknown_field:{service:'unrelated'}})){
    await test(`receipt ${name} rejected before connections or config replacement`,async()=>{
      const config=await fs.readFile(path.join(client,'ssh/config'),'utf8');await fs.writeFile(capture,'');await fs.writeFile(receiptFile,JSON.stringify({...receipt,...patch}));const r=await run('/bin/bash',[path.join(scripts,'install-mac-client.sh'),'--receipt',receiptFile],env);assert.notEqual(r.code,0);assert.equal((await events()).length,0);assert.equal(await fs.readFile(path.join(client,'ssh/config'),'utf8'),config);
    });
  }
}finally{await fs.rm(root,{recursive:true,force:true});}
