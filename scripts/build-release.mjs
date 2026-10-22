// Generic network kit; deployment data is never embedded.
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {checkPrivacy} from './privacy-check.mjs';
if(process.argv.length!==2)throw Error('Generic build takes no deployment arguments.');
const repo=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),dist=path.join(repo,'dist');
const name='remote-ssh-kit-v0.4.0-rc.3',stage=await fs.mkdtemp(path.join(os.tmpdir(),'network-kit-')),folder=path.join(stage,name);
const files=['README.md','PRIVACY.md','MAC-SERVER-SETUP.md','ARCHITECTURE-AND-RISKS.md','verification.md','setup.example.json','tailscale-grant.example.json',
  ...['network-common.sh','setup-mac-server.sh','deploy-mac-server.command','install-mac-client.sh','start-mac-client.sh','remote-ssh','init-vps.sh','WindowsCommon.ps1','Install-WindowsClient.ps1','Start-WindowsClient.ps1'].map(f=>'scripts/'+f)];
function requirePrivateCheck(options){const result=checkPrivacy({repo,...options});if(result.failures.length)throw Error('PRIVACY_CHECK_FAILED: build refused; run the privacy checker locally.');}
try{
  requirePrivateCheck({mode:'worktree'});
  await fs.mkdir(dist,{recursive:true});await fs.mkdir(path.join(folder,'scripts'),{recursive:true});
  for(const file of files)await fs.copyFile(path.join(repo,file),path.join(folder,file));
  const zip=name+'.zip';execFileSync('zip',['-q','-r',path.join(stage,zip),name],{cwd:stage});requirePrivateCheck({archive:path.join(stage,zip)});await fs.copyFile(path.join(stage,zip),path.join(dist,zip));
  const checksum=createHash('sha256').update(await fs.readFile(path.join(dist,zip))).digest('hex');await fs.writeFile(path.join(dist,'SHA256SUMS'),`${checksum}  ${zip}\n`);
  console.log('GENERIC_KIT '+path.join(dist,zip));
}finally{await fs.rm(stage,{recursive:true,force:true});}
