#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Release transition: published v0.7.0 (migration 16) -> candidate release,
// then fresh-host recovery from its encrypted pre-upgrade archive. The first
// attempt runs with a public URL the upgrade gate rejects (ADR-0035 D11): it
// must stay pending; fixed and rerun, it completes without a new backup. In
// between, the supervisor file changes under a running convex-backend (what a
// supervisor-only release does): doctor must flag it and the rerun recreate it.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, utimesSync, mkdtempSync, readFileSync, writeFileSync, mkdirSync, cpSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { VarlatchClient } from '../packages/sdk/dist/index.js';
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const fixtures = join(root,'scripts/fixtures/v0.7.0');
const oldManifest=JSON.parse(readFileSync(join(fixtures,'varlatch-release.json'),'utf8'));
const legacyImage=process.env.VARLATCH_TEST_LEGACY_IMAGE ?? oldManifest.images.varlatchd.digest;
const release=JSON.parse(readFileSync(join(root,'packages/backup/src/release.json'),'utf8'));
const dir=mkdtempSync(join(tmpdir(),'varlatch-upgrade-e2e-'));
const source=join(dir,'source'),target=join(dir,'target'),artifacts=join(dir,'artifacts');
const project=`vlt-upgrade-${randomBytes(5).toString('hex')}`;
const rootKey=randomBytes(32).toString('hex'),bek=randomBytes(32).toString('hex');
const imageNames={varlatchd:'varlatch-backup-test:local','varlatch-web':'varlatch-backup-web-test:local','convex-deploy':'varlatch-backup-convex-deploy-test:local'};
function docker(where,args,input) { return execFileSync('docker',['compose','--project-directory',where,...args],{input,encoding:'utf8',maxBuffer:2*1024*1024,stdio:['pipe','pipe','pipe']}).trim(); }
function base(where,service,port) { return `http://${docker(where,['port',service,String(port)])}`; }
// Every request on its own connection: this script blocks its event loop in
// execFileSync/spawnSync for longer than varlatchd's keep-alive timeout, and a
// pooled connection the server closed meanwhile fails the next request
// ("other side closed").
function fresh(url,init={}) { const headers=new Headers(init.headers);headers.set('connection','close');return fetch(url,{...init,headers}); }
async function ready(url) { for(let n=0;n<120;n++){try{if((await fresh(url)).ok)return;}catch{} await new Promise(r=>setTimeout(r,500));} throw Error('Readiness timeout'); }
function cli(where,args,success=true) {
 const result=spawnSync('node',[join(root,'apps/cli/dist/varlatch.cjs'),...args,'--dir',where,'--bek-file',join(where,'secrets/bek'),'--kek-file',join(where,'secrets/root')],{encoding:'utf8',timeout:600_000,maxBuffer:64*1024*1024});
 if(success) assert.equal(result.status,0,result.stderr || result.stdout); else assert.notEqual(result.status,0,result.stdout);
 return `${result.stdout}\n${result.stderr}`;
}
function localCompose(projectName) {
 const byDockerfile={'services/varlatchd/Dockerfile':'varlatchd','apps/web/Dockerfile':'varlatch-web','infra/compose/convex-deploy.Dockerfile':'convex-deploy'};
 return readFileSync(join(root,'infra/compose/docker-compose.yml'),'utf8').replace('name: varlatch',`name: ${projectName}`)
 .replace(/build:\n\s+context: \.\.\/\.\.\n\s+dockerfile: (\S+)\n/g,(_,file)=>`image: ${imageNames[byDockerfile[file]]}\n`)
 // Only the candidate images built in this job are local-only; postgres and
 // convex-backend pull when missing (on a lifecycle-only run no earlier step
 // has pulled postgres:17.6).
 .replace(/(    image: \S+:local\n)/g,'$1    pull_policy: never\n');
}
for(const [i,where] of [source,target].entries()) {
 mkdirSync(join(where,'secrets'),{recursive:true});
 writeFileSync(join(where,'secrets/root'),rootKey);writeFileSync(join(where,'secrets/bek'),bek);
 cpSync(join(root,'infra/compose/postgres-init'),join(where,'postgres-init'),{recursive:true});
 cpSync(join(root,'infra/compose/convex-supervisor.cjs'),join(where,'convex-supervisor.cjs'));
 writeFileSync(join(where,'.env'),`POSTGRES_SUPERUSER_PASSWORD=test-superuser\nVARLATCH_MIGRATE_PASSWORD=test-migrate\nVARLATCH_RUNTIME_PASSWORD=test-runtime\nCONVEX_DB_PASSWORD=test-convex\nCONVEX_INSTANCE_SECRET=${randomBytes(32).toString('hex')}\nVARLATCHD_PORT=0\nVARLATCH_WEB_PORT=0\nCONVEX_PORT=0\nCONVEX_SITE_PORT=0\nVARLATCH_KEK_HOST_PATH=./secrets/root\nVARLATCH_PUBLIC_URL=http://varlatchd:8686\nVARLATCH_CONVEX_URL=http://convex-backend:3210\n`);
 writeFileSync(join(where,'docker-compose.yml'),localCompose(`${project}-${i}`));
}
mkdirSync(artifacts);
writeFileSync(join(artifacts,'varlatch-release.json'),JSON.stringify({...release,images:Object.fromEntries(Object.entries(imageNames).map(([k,v])=>[k,{tag:v,digest:null}]))}));
writeFileSync(join(artifacts,'docker-compose.release.yml'),localCompose(`${project}-0`));
writeFileSync(join(artifacts,'convex-supervisor.cjs'),readFileSync(join(root,'infra/compose/convex-supervisor.cjs'),'utf8')+`// release ${release.version}\n`);
let oldCompose=readFileSync(join(fixtures,'docker-compose.release.yml'),'utf8').replace('name: varlatch',`name: ${project}-0`);
// Test override is explicit: normal CI exercises the published digest; local
// testing may use an exact-tag rebuild if GHCR read:packages is unavailable.
oldCompose=oldCompose.replace(/image: ghcr\.io\/varlatch\/varlatchd[^\n]+/g,`image: ${legacyImage}`);
writeFileSync(join(source,'docker-compose.yml'),oldCompose);
cpSync(join(fixtures,'varlatch-release.json'),join(source,'varlatch-release.json'));
try {
 console.log(`Starting v0.7.0 source (${legacyImage})`);
 docker(source,['up','-d','postgres','varlatch-migrate','varlatchd','convex-backend']);
 const sourceUrl=base(source,'varlatchd',8686),convexUrl=base(source,'convex-backend',3210);
 await ready(`${sourceUrl}/readyz`);await ready(`${convexUrl}/version`);
 const adminKey=docker(source,['exec','-T','convex-backend','./generate_admin_key.sh']);
 writeFileSync(join(source,'.env'),readFileSync(join(source,'.env'),'utf8')+`CONVEX_ADMIN_KEY=${adminKey}\n`);
 const env={...process.env,CONVEX_SELF_HOSTED_URL:convexUrl,CONVEX_SELF_HOSTED_ADMIN_KEY:adminKey};
 for(const [name,value] of [['VARLATCH_ISSUER','http://varlatchd:8686'],['VARLATCH_JWKS_URL','http://varlatchd:8686/.well-known/jwks.json']])execFileSync('pnpm',['exec','convex','env','set',name,value],{cwd:join(root,'convex'),env,stdio:'pipe'});
 execFileSync('pnpm',['exec','convex','deploy','-y'],{cwd:join(root,'convex'),env,stdio:'pipe'});
 const token=docker(source,['exec','-T','varlatchd','node','dist/cli.js','admin','bootstrap','--cli-credential']).match(/vlt_cli_\S+/)?.[0];assert(token);
 const api=new VarlatchClient({server:sourceUrl,token,fetch:fresh});
 await api.createOrganization({slug:'upgrade',name:'Upgrade'});
 await api.createProject('upgrade',{slug:'app',name:'App',contractAuthority:'managed'});
 await api.createEnvironment('upgrade','app',{name:'dev',tier:'development'});
 const revision=await api.pushContractRevision('upgrade','app',{contract:{schemaVersion:1,items:[{name:'SECRET',type:'string',sensitive:true,required:{kind:'always'}}]}});
 await api.activateContractRevision('upgrade','app',revision.id);
 await api.setValue('upgrade','app','dev','SECRET',{value:'release-transition-secret'});
 console.log(`Running the real upgrade command to ${release.version}, including offline bridge and verification`);
 const blocked=cli(source,['upgrade',release.version,'--release-dir',artifacts,'--yes'],false);
 assert.match(blocked,/Upgrade gate: BLOCKED/,blocked);
 assert.match(blocked,/Public URL: http:\/\/varlatchd:8686 is not HTTPS/,blocked);
 assert.match(blocked,/applied but not complete/);
 assert.equal(JSON.parse(readFileSync(join(source,'varlatch-release.json'),'utf8')).version,'0.7.0','not promoted');
 assert(existsSync(join(source,'varlatch-release.json.pending')),'stays pending');
 const firstReceipt=readFileSync(join(source,`backup.pre-${release.version}.json`),'utf8');
 console.log('PASS  the upgrade gate holds the release pending on a failing check');
 const supervisorStatus=()=>{const r=spawnSync('node',[join(root,'apps/cli/dist/varlatch.cjs'),'doctor','--json','--wait','0','--dir',source],{encoding:'utf8',timeout:300_000});return JSON.parse(r.stdout.slice(r.stdout.indexOf('{'))).checks.find(c=>c.id==='application-plane.supervisor')?.status;};
 assert.equal(supervisorStatus(),'pass','compose recreated convex-backend with the new supervisor mount');
 const future=new Date(Date.now()+1000);utimesSync(join(source,'convex-supervisor.cjs'),future,future);
 assert.equal(supervisorStatus(),'fail','doctor flags a supervisor file newer than its process');
 // The operator fixes the public URL (and Convex's issuer follows through reconciliation).
 writeFileSync(join(source,'.env'),readFileSync(join(source,'.env'),'utf8').replace('VARLATCH_PUBLIC_URL=http://varlatchd:8686','VARLATCH_PUBLIC_URL=http://localhost:8686'));
 const completed=cli(source,['upgrade',release.version,'--release-dir',artifacts,'--yes']);
 assert.match(completed,/Upgrade gate: PASS/,completed);
 for(const out of [blocked,completed]) console.log(out.slice(out.indexOf('Upgrade gate:')).split('\n').filter(l=>!/^ *Container /.test(l)).join('\n').trim());
 assert.match(completed,/recreating convex-backend/,'a changed supervisor recreates convex-backend');
 assert.doesNotMatch(completed,/carries no CLI with an upgrade gate/,'the target release judged itself');
 assert(!existsSync(join(source,'varlatch-release.json.pending')));
 assert.equal(readFileSync(join(source,`backup.pre-${release.version}.json`),'utf8'),firstReceipt,'resumed without a new backup');
 console.log('PASS  fixed and rerun, the upgrade completes on the same verified archive, recreating a stale convex-backend');
 const upgradedUrl=base(source,'varlatchd',8686);await ready(`${upgradedUrl}/readyz`);
 const upgraded=new VarlatchClient({server:upgradedUrl,token,fetch:fresh});
 assert.equal((await upgraded.meta()).serverVersion,release.version);
 const doctor=spawnSync('node',[join(root,'apps/cli/dist/varlatch.cjs'),'doctor','--gate','--dir',source],{encoding:'utf8',timeout:300_000});
 assert.equal(doctor.status,0,doctor.stdout);
 assert.match(doctor.stdout,/✓ Convex supervisor runs the installed file/);
 assert.equal((await upgraded.discloseSecrets('upgrade','app','dev',{items:['SECRET']})).items[0].value,'release-transition-secret');
 assert.equal(docker(source,['exec','-T','postgres','psql','-U','postgres','-d','varlatch','-Atc','SELECT max(id) FROM varlatch_migrations']),String(release.migrationVersion));
 const receipt=JSON.parse(readFileSync(join(source,`backup.pre-${release.version}.json`),'utf8'));
 docker(source,['stop']);
 cli(source,['admin','backup','verify','--in',receipt.archive]);
 console.log('Restoring the pre-upgrade migration-16 archive on a fresh candidate installation');
 cli(target,['admin','backup','restore','--in',receipt.archive]);
 const restoredUrl=base(target,'varlatchd',8686);await ready(`${restoredUrl}/readyz`);
 const restored=new VarlatchClient({server:restoredUrl,token,fetch:fresh});
 assert.equal((await restored.discloseSecrets('upgrade','app','dev',{items:['SECRET']})).items[0].value,'release-transition-secret');
 console.log('PASS: v0.7.0 offline capture, verified upgrade, migrations, preserved credentials/secrets, and fresh-host recovery of the pre-upgrade archive');
} catch(error) {
 for(const where of [source,target]){try{console.error(docker(where,['logs','--tail','30','varlatchd','varlatch-migrate']));}catch{}}
 throw error;
} finally {
 for(const where of [source,target]){try{docker(where,['down','-v','--remove-orphans']);}catch{}}
 rmSync(dir,{recursive:true,force:true});
}
