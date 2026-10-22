import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';

const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const sandbox=await fs.mkdtemp(path.join(os.tmpdir(),'identity-migration-'));
const run=(cmd,args,env)=>spawnSync(cmd,args,{env,encoding:'utf8',timeout:20000,input:''});
const success=r=>{assert.equal(r.status,0,r.stdout+r.stderr);return r;};
const exists=p=>fs.access(p).then(()=>true,()=>false);
async function fixture({passphrase='',type='ed25519',script=''}={}) {
  const base=await fs.mkdtemp(path.join(sandbox,'case-')),home=path.join(base,'client with spaces 中文');
  await fs.mkdir(home);const bin=path.join(base,'bin');await fs.mkdir(bin);
  const events=path.join(base,'network-events');
  for(const name of ['ssh','tailscale','tailscaled'])await fs.writeFile(path.join(bin,name),`#!/bin/sh\necho forbidden >> "${events}"\nexit 97\n`,{mode:0o700});
  const identity=path.join(base,'existing identity');
  success(run('ssh-keygen',['-q','-t',type,'-N',passphrase,'-C','old-client-comment','-f',identity]));
  const pub=(await fs.readFile(identity+'.pub','utf8')).trim().split(/\s+/).slice(0,2).join(' ');
  const fingerprint=success(run('ssh-keygen',['-lf',identity+'.pub','-E','sha256'])).stdout.trim().split(/\s+/)[1];
  const receipt={schemaVersion:1,kind:'remote-ssh',serverOs:'macos',serverReady:true,host:'100.90.2.3',port:22,user:'remote_user',hostKey:pub,jumpHost:'203.0.113.10',jumpPort:22,jumpTailnetIp:'100.80.0.1',jumpHostKey:pub,clientKeyFingerprint:fingerprint};
  const receiptFile=path.join(base,'receipt.json');await fs.writeFile(receiptFile,JSON.stringify(receipt));
  let scripts=path.join(repo,'scripts');
  if(script){scripts=path.join(base,'scripts');await fs.cp(path.join(repo,'scripts'),scripts,{recursive:true});await fs.writeFile(path.join(scripts,'init-vps.sh'),script);}
  const env={...process.env,HOME:home,PATH:bin+':'+process.env.PATH};
  const install=(args)=>run('/bin/bash',[path.join(scripts,'install-mac-client.sh'),...args],env);
  return {base,home,identity,pub,fingerprint,receiptFile,receipt,events,env,install,client:path.join(home,'Library/Application Support/RemoteSSHClient')};
}
try {
  await test('explicit identity import preserves source bytes and public identity, repeats without replacement',async()=>{
    const f=await fixture(),source=await fs.readFile(f.identity),mode=(await fs.stat(f.identity)).mode;
    const args=['--prepare-only','--identity-file',f.identity];success(f.install(args));success(f.install(args));
    assert.deepEqual(await fs.readFile(f.identity),source);assert.equal((await fs.stat(f.identity)).mode,mode);
    assert.deepEqual(await fs.readFile(path.join(f.client,'ssh/id_ed25519')),source);
    assert.equal((await fs.stat(path.join(f.client,'ssh/id_ed25519'))).mode&0o777,0o600);
    assert.equal((await fs.readFile(path.join(f.client,'client-key.pub'),'utf8')).trim(),f.pub);
    assert.equal(await exists(f.events),false);
  });
  await test('receipt plus matching existing key is a single offline import command',async()=>{
    const f=await fixture();success(f.install(['--receipt',f.receiptFile,'--identity-file',f.identity,'--no-provision']));
    assert.equal(await exists(path.join(f.client,'ssh/config')),true);assert.equal(await exists(f.events),false);
    success(f.install(['--receipt',path.join(f.client,'receipt.json'),'--no-provision']));
  });
  await test('wrong imported fingerprint fails before creating client files or making connections',async()=>{
    const f=await fixture();await fs.writeFile(f.receiptFile,JSON.stringify({...f.receipt,clientKeyFingerprint:'SHA256:wrong'}));
    const r=f.install(['--receipt',f.receiptFile,'--identity-file',f.identity]);assert.notEqual(r.status,0);assert.match(r.stderr,/CLIENT_KEY_MISMATCH/);
    assert.equal(await exists(f.client),false);assert.equal(await exists(f.events),false);
  });
  await test('a different installed key is never overwritten by explicit import',async()=>{
    const f=await fixture();success(f.install(['--prepare-only']));const key=path.join(f.client,'ssh/id_ed25519'),before=await fs.readFile(key);
    const r=f.install(['--prepare-only','--identity-file',f.identity]);assert.notEqual(r.status,0);assert.match(r.stderr,/CLIENT_KEY_CONFLICT/);assert.deepEqual(await fs.readFile(key),before);
  });
  for(const kind of ['encrypted','public-only','permissions','symlink','wrong-type'])await test(`reject ${kind} identity before mutation and without a prompt`,async()=>{
    const f=await fixture({passphrase:kind==='encrypted'?'test-only-passphrase':'',type:kind==='wrong-type'?'rsa':'ed25519'});
    let identity=f.identity;
    if(kind==='public-only')identity+='.pub';
    if(kind==='permissions')await fs.chmod(identity,0o644);
    if(kind==='symlink'){identity=path.join(f.base,'link');await fs.symlink(f.identity,identity);}
    const r=f.install(['--prepare-only','--identity-file',identity]);assert.notEqual(r.status,0);assert.equal(r.signal,null);assert.equal(await exists(f.client),false);assert.equal(await exists(f.events),false);
    assert.doesNotMatch(r.stdout+r.stderr,/BEGIN OPENSSH PRIVATE KEY/);
  });
  await test('managed public key symlink cannot overwrite unrelated user data',async()=>{
    const f=await fixture();success(f.install(['--prepare-only']));const victim=path.join(f.base,'keep.txt');await fs.writeFile(victim,'KEEP');
    const publicFile=path.join(f.client,'client-key.pub');await fs.unlink(publicFile);await fs.symlink(victim,publicFile);
    assert.notEqual(f.install(['--prepare-only']).status,0);assert.equal(await fs.readFile(victim,'utf8'),'KEEP');
  });
  await test('export embeds exact bundled VPS script, public inputs and digest without credentials or network',async()=>{
    const f=await fixture(),output=path.join(f.base,'vps-init.sh');
    success(f.install(['--receipt',f.receiptFile,'--identity-file',f.identity,'--export-vps-command',output]));
    const exported=await fs.readFile(output,'utf8'),payload=exported.match(/<<'REMOTE_SSH_PAYLOAD'\n([^\n]+)\nREMOTE_SSH_PAYLOAD/)[1];
    const source=await fs.readFile(path.join(repo,'scripts/init-vps.sh'));
    assert.deepEqual(Buffer.from(payload,'base64'),source);assert.ok(exported.includes(createHash('sha256').update(source).digest('hex')));
    assert.match(exported,/100\.90\.2\.3 22 [A-Za-z0-9+/=]+ 100\.80\.0\.1/);
    assert.doesNotMatch(exported,/curl|wget|github|BEGIN OPENSSH PRIVATE KEY/);assert.equal(await exists(f.events),false);
    assert.equal((await fs.stat(output)).mode&0o777,0o600);
    assert.notEqual(f.install(['--receipt',f.receiptFile,'--export-vps-command',output]).status,0);assert.equal(await fs.readFile(output,'utf8'),exported);
  });
  await test('offline console payload executes from another directory and rejects tampering before execution',async()=>{
    const f=await fixture({script:'#!/bin/bash\nprintf "OFFLINE_FIXTURE_OK:%s:%s:%s:%s\\n" "$1" "$2" "$3" "$4"\n'}),output=path.join(f.base,'vps-init.sh');
    success(f.install(['--receipt',f.receiptFile,'--identity-file',f.identity,'--export-vps-command',output]));
    // Test-only sha256sum adapter for macOS; production VPS uses GNU coreutils.
    await fs.writeFile(path.join(f.base,'bin/sha256sum'),'#!/bin/sh\nexec shasum -a 256 "$@"\n',{mode:0o700});
    const r=success(run('/bin/bash',[output],f.env));assert.match(r.stdout,/OFFLINE_FIXTURE_OK:100.90.2.3:22:.*:100.80.0.1/);
    const exported=await fs.readFile(output,'utf8');await fs.writeFile(output,exported.replace(/printf '[0-9a-f]{64}/,"printf '"+'0'.repeat(64)));
    const bad=run('/bin/bash',[output],f.env);assert.notEqual(bad.status,0);assert.doesNotMatch(bad.stdout,/OFFLINE_FIXTURE_OK/);
  });
} finally {await fs.rm(sandbox,{recursive:true,force:true});}
