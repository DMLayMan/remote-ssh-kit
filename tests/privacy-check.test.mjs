import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {execFileSync, spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {inspectText, loadPrivateTerms, checkPrivacy} from '../scripts/privacy-check.mjs';

const script=fileURLToPath(new URL('../scripts/privacy-check.mjs',import.meta.url));
const stage=await fs.mkdtemp(path.join(os.tmpdir(),'privacy-test-'));
const address=['10','23','45','67'].join('.');
const personalPath=['','Users','fixture-person','private'].join('/');
let sequence=0;
async function repository(){
  const dir=path.join(stage,String(sequence++));await fs.mkdir(dir);
  const git=args=>execFileSync('git',args,{cwd:dir,encoding:'utf8',stdio:['ignore','pipe','pipe']});
  git(['init','-b','main']);git(['config','user.name','Fixture']);git(['config','user.email','fixture@example.com']);git(['config','core.hooksPath',path.join(dir,'.no-hooks')]);
  return {dir,git};
}
try {
  await test('detects deployment identities without echoing them',()=>{
    for(const content of [address,personalPath,'fixture-device'+'.local','user@'+'private-domain.invalid','ssh-ed25519 '+'A'.repeat(60),'SHA256:'+'a'.repeat(43)]) assert.ok(inspectText(content).length);
    assert.equal(inspectText('203.0.113.10 test@example.com setup.local.json').length,0);
    assert.ok(inspectText('generic',{name:address+'.txt'}).length);
  });
  await test('detects actual key material, including quoted multiline material',()=>{
    const marker=['-----BEGIN','OPENSSH','PRIVATE KEY-----'].join(' '),body='A'.repeat(90);
    assert.ok(inspectText(marker+'\n'+body).some(f=>f.rule==='private-key'));
    assert.ok(inspectText('value="'+marker+'\\n'+body+'"').some(f=>f.rule==='private-key'));
  });
  await test('index scanner checks staged data even when worktree is clean',async()=>{
    const {dir,git}=await repository();await fs.writeFile(path.join(dir,'notes.txt'),address);git(['add','notes.txt']);await fs.writeFile(path.join(dir,'notes.txt'),'generic');
    assert.equal(checkPrivacy({repo:dir,mode:'worktree',denylist:undefined}).failures.length,0);
    assert.ok(checkPrivacy({repo:dir,mode:'index'}).failures.length);
  });
  await test('full history catches deleted data and tagged side branches',async()=>{
    const {dir,git}=await repository();await fs.writeFile(path.join(dir,'notes.txt'),'generic');git(['add','notes.txt']);git(['commit','-m','base']);
    git(['checkout','-b','old']);await fs.writeFile(path.join(dir,'notes.txt'),address);git(['commit','-am','fixture']);git(['tag','old-fixture']);git(['checkout','main']);git(['branch','-D','old']);
    assert.equal(checkPrivacy({repo:dir,mode:'worktree'}).failures.length,0);
    assert.ok(checkPrivacy({repo:dir,mode:'history'}).failures.length);
  });
  await test('private denylist stays outside repo and fails closed',async()=>{
    const {dir}=await repository();const term='private-'+'fixture-marker',file=path.join(stage,'denylist.json');
    await fs.writeFile(file,JSON.stringify([term]),{mode:0o600});
    assert.deepEqual(loadPrivateTerms(file,dir),[term]);assert.ok(inspectText(term,{privateTerms:[term]}).length);
    assert.ok(inspectText('not-sensitive',{name:term+'.txt',privateTerms:[term]}).length);
    const inside=path.join(dir,'denylist.json');await fs.copyFile(file,inside);assert.throws(()=>loadPrivateTerms(inside,dir));
    await fs.chmod(file,0o644);if(process.platform!=='win32')assert.throws(()=>loadPrivateTerms(file,dir));
    await fs.chmod(file,0o600);await fs.writeFile(file,'{}');assert.throws(()=>loadPrivateTerms(file,dir));
  });
  await test('archive scan checks bytes inside ZIP rather than filename',async()=>{
    const dir=path.join(stage,'zip');await fs.mkdir(dir);await fs.writeFile(path.join(dir,'notes.txt'),address);
    const archive=path.join(stage,'fixture.zip');execFileSync('zip',['-q',archive,'notes.txt'],{cwd:dir});
    assert.ok(checkPrivacy({repo:dir,archive}).failures.length);
  });
  await test('production builder refuses personal worktree data before publishing an archive',async()=>{
    const {dir}=await repository();await fs.mkdir(path.join(dir,'scripts'));
    for(const name of ['build-release.mjs','privacy-check.mjs'])await fs.copyFile(fileURLToPath(new URL('../scripts/'+name,import.meta.url)),path.join(dir,'scripts',name));
    await fs.writeFile(path.join(dir,'notes.txt'),address);
    const r=spawnSync(process.execPath,['scripts/build-release.mjs'],{cwd:dir,encoding:'utf8'});
    assert.notEqual(r.status,0);assert.match(r.stderr,/PRIVACY_CHECK_FAILED/);assert.ok(!r.stderr.includes(address));
    await assert.rejects(fs.stat(path.join(dir,'dist')));
  });
  await test('private filenames, symlinks and binary files are rejected',async()=>{
    assert.ok(inspectText('{}',{name:'setup.json'}).length);assert.ok(inspectText('a\0b').length);
    const {dir}=await repository();await fs.symlink('/dev/null',path.join(dir,'notes.txt'));assert.throws(()=>checkPrivacy({repo:dir}));
  });
  await test('CLI redacts matching content and filenames',async()=>{
    const {dir}=await repository();await fs.writeFile(path.join(dir,address+'.txt'),personalPath+' '+address);
    const r=spawnSync(process.execPath,[script,'--worktree'],{cwd:dir,encoding:'utf8'});
    assert.equal(r.status,1);assert.match(r.stderr,/PRIVACY_CHECK_FAILED/);assert.ok(!r.stderr.includes(address));assert.ok(!r.stderr.includes(personalPath));
    const bad=spawnSync(process.execPath,[script,'--history'],{cwd:dir,encoding:'utf8'});assert.equal(bad.status,2);assert.doesNotMatch(bad.stderr,/fatal:|at /);
  });
} finally { await fs.rm(stage,{recursive:true,force:true}); }
