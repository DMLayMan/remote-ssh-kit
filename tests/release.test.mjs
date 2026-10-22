import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {execFileSync,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),name='remote-ssh-kit-v0.4.0-rc.3',stage=await fs.mkdtemp(path.join(os.tmpdir(),'network-kit-test-'));
try{
  await test('release contains only network kit files, public placeholders and a matching checksum',async()=>{
    execFileSync(process.execPath,['scripts/build-release.mjs'],{cwd:repo});const zip=path.join(repo,'dist',name+'.zip');execFileSync('unzip',['-q',zip,'-d',stage]);
    const files=execFileSync('unzip',['-Z1',zip],{encoding:'utf8'}).trim().split('\n').filter(f=>!f.endsWith('/')).map(f=>f.slice(name.length+1));
    assert.equal(files.length,17);assert.ok(files.every(f=>!f.includes('legacy')&&!f.includes('receipt.json')&&!f.includes('client-key.pub')));
    const root=path.join(stage,name);for(const file of files){const text=await fs.readFile(path.join(root,file),'utf8');assert.doesNotMatch(text,/BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY|\/Users\/[a-zA-Z0-9_]+\//);}
    const input=JSON.parse(await fs.readFile(path.join(root,'setup.example.json'),'utf8'));
    assert.deepEqual(Object.keys(input).sort(),['schemaVersion','jumpHost','jumpPort','jumpTailnetIp','jumpHostKey','clientPublicKey'].sort());assert.match(input.clientPublicKey,/REPLACE_WITH/);
    const checksum=createHash('sha256').update(await fs.readFile(zip)).digest('hex');assert.equal(await fs.readFile(path.join(repo,'dist/SHA256SUMS'),'utf8'),`${checksum}  ${name}.zip\n`);
  });
  await test('packaging rejects personalized inputs',()=>{
    const r=spawnSync(process.execPath,['scripts/build-release.mjs','setup.json'],{cwd:repo,encoding:'utf8'});assert.notEqual(r.status,0);assert.match(r.stderr,/Generic build takes no deployment arguments/);
  });
}finally{await fs.rm(stage,{recursive:true,force:true});}
