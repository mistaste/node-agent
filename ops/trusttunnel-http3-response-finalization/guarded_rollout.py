#!/usr/bin/env python3
"""Guard one reviewed runner rollout. Default is a read-only plan; never deploy all nodes."""
import argparse
import re
import hashlib
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent
OVERLAY = ROOT / 'Dockerfile.overlay'

PROGRAM = r'''
import copy,datetime,fcntl,hashlib,json,os,pathlib,shutil,stat,subprocess,time
from decimal import Decimal
os.umask(0o077)
root=pathlib.Path(REMOTE)
override=pathlib.Path(OVERRIDE)
container=PIN['runtime']['container']['name']
binary='/opt/trusttunnel/trusttunnel_endpoint'
def sha(data):return hashlib.sha256(data).hexdigest()
def call(args,timeout=30):return subprocess.check_output(args,text=True,timeout=timeout).strip()
def inspect():return json.loads(call(['docker','inspect',container]))[0]
def atomic(path,data):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 temp=path.with_name(path.name+'.new')
 with temp.open('xb')as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
 temp.chmod(0o600);os.replace(temp,path)
 directory=os.open(path.parent,os.O_DIRECTORY)
 try:os.fsync(directory)
 finally:os.close(directory)
def record(name,value):atomic(root/name,(json.dumps(value,indent=2)+'\n').encode())
def assert_files():
 for row in PIN['runtime']['compose_files']:
  path=pathlib.Path(row['path']);assert path.is_file()and not path.is_symlink(),'compose path missing/symlink'
  assert sha(path.read_bytes())==row['sha256'],'compose file changed'
 for row in PIN['runtime']['baseline_inputs']:
  assert row['matches_baseline']
  for item in row['present_candidates']:
   assert sha(pathlib.Path(item['path']).read_bytes())==row['expected_sha256'],'baseline source changed'
def process_evidence():
 lines=call(['docker','top',container,'-eo','pid,args']).splitlines()[1:];items=[]
 for line in lines:
  fields=line.strip().split(None,1)
  if len(fields)!=2 or pathlib.PurePosixPath(fields[1].split()[0]).name!='trusttunnel_endpoint':continue
  pid=int(fields[0]);env=pathlib.Path('/proc',str(pid),'environ').read_bytes().split(b'\0')
  qos=[item.split(b'=',1)[1].decode()for item in env if item.startswith(b'GUARDEX_ACCOUNT_QOS_SOCKET=')]
  sock=None
  if qos:
   assert len(qos)==1 and qos[0].startswith('/')
   sock=call(['docker','exec',container,'stat','-c','%F %a %u:%g',qos[0]])
  items.append({'pid':pid,'sha256':sha(pathlib.Path('/proc',str(pid),'exe').read_bytes()),
                'qos_active':bool(qos),'qos_socket_hash':sha(json.dumps(qos).encode()),'qos_socket_stat':sock})
 assert len(items)==1,'expected exactly one endpoint process'
 return items[0]
def canonical_env(entries):
 assert isinstance(entries,list),'malformed Env array'
 values={}
 for entry in entries:
  assert isinstance(entry,str)and '\0'not in entry,'malformed Env entry'
  key,separator,value=entry.partition('=')
  assert separator and key,'malformed Env entry'
  assert key not in values,'duplicate Env key'
  values[key]=value
 return values
def preserve_explicit_empty_dns(value,text):
 # Keep only an existing exact empty list explicit in the owned compose input.
 # Null and nonempty values stay governed by the unchanged original files.
 for field,setting in [('DnsOptions','dns_opt'),('DnsSearch','dns_search')]:
  assert field in value['HostConfig'],'missing original DNS field'
  original=value['HostConfig'][field]
  assert original is None or(isinstance(original,list)and all(isinstance(item,str)and '\0'not in item for item in original)),'malformed original DNS field'
  if original==[]:text+='    '+setting+': []\n'
 return text
def exact_cpu(value):
 nano=value['HostConfig']['NanoCpus']
 assert type(nano)is int and nano>=0,'malformed original CPU constraint'
 return format(Decimal(nano)/Decimal(1000000000),'f')
def preserve_runtime_inputs(value,text,deploy_cpu_present=False):
 text=preserve_explicit_empty_dns(value,text)
 target=exact_cpu(value)
 text+='    cpus: "'+target+'"\n'
 if deploy_cpu_present:
  text+='    deploy:\n      resources:\n        limits:\n          cpus: "'+target+'"\n'
 return text
def normalize(v,context,phase):
 cfg=copy.deepcopy(v['Config']);hostname=cfg.pop('Hostname');cfg.pop('Image')
 version=context.get('normalization_version',1)
 assert version in [1,2],'unknown fingerprint normalization version'
 if version==2:cfg['Env']=canonical_env(cfg['Env'])
 if context['default_hostname']:assert hostname==v['Id'][:12],'unexpected hostname'
 else:assert sha(hostname.encode())==context['hostname_sha256'],'custom hostname changed'
 labels=cfg.get('Labels')or{}
 for name in ['com.docker.compose.config-hash','com.docker.compose.image']:labels.pop(name,None)
 files=(labels.get('com.docker.compose.project.config_files')or'').split(',')
 expected=context['compose_files']+([str(override)]if phase!='before'else[])
 assert files==expected,'compose file list changed outside owned append'
 labels['com.docker.compose.project.config_files']=','.join(context['compose_files'])
 marker=labels.get('org.guardex.http3-response-finalization')
 wanted='1'if phase=='new'else context['old_overlay_marker']
 assert marker==wanted,'unexpected overlay label'
 if context['old_overlay_marker']is None:labels.pop('org.guardex.http3-response-finalization',None)
 cfg['Labels']=labels
 # All other Config fields (including Env/Cmd/Entrypoint/User/WorkingDir/Healthcheck),
 # every HostConfig field, and complete mount records are compared without omissions.
 mounts=sorted(v['Mounts'],key=lambda x:json.dumps(x,sort_keys=True))
 return sha(json.dumps({'Config':cfg,'HostConfig':v['HostConfig'],'Mounts':mounts},sort_keys=True).encode())
def compose(files):
 args=['docker','compose','--project-name',PIN['runtime']['compose_labels']['com.docker.compose.project']]
 for name in files:args+=['-f',name]
 return args
def recreate(files):
 call(compose(files)+['up','-d','--no-deps','--no-build','--pull','never','trusttunnel-runner'],timeout=60)
def host_snapshot(phase,value):
 path=root/('docker-inspect.'+phase+'.'+str(time.time_ns())+'.json')
 atomic(path,(json.dumps(value,indent=2)+'\n').encode())
 record('latest-inspect-'+phase+'.json',{'path':str(path),'sha256':sha(path.read_bytes()),'host_only':True})
def wait_endpoint(expected_image,expected_binary,context,phase,fingerprint,qos):
 deadline=time.monotonic()+45
 first=True
 while True:
  after=inspect()
  if first:host_snapshot(phase+'-starting',after);first=False
  try:proc=process_evidence()
  except (AssertionError,OSError,subprocess.CalledProcessError):proc=None
  if after['State']['Running']and proc and proc['sha256']==expected_binary:break
  assert time.monotonic()<deadline,'endpoint readiness deadline exceeded'
  time.sleep(1)
 host_snapshot(phase,after)
 assert after['Image']==expected_image and after['RestartCount']==0,'image/restart changed'
 assert call(['docker','exec',container,'sha256sum',binary]).split()[0]==expected_binary,'file SHA differs'
 assert normalize(after,context,phase)==fingerprint,'full runtime configuration changed'
 assert {k:proc[k]for k in ['qos_active','qos_socket_hash','qos_socket_stat']}==qos,'QoS activation changed'
 time.sleep(5);final=inspect();assert final['State']['Running']and final['RestartCount']==0
 assert process_evidence()['sha256']==expected_binary,'running process SHA changed'
 assert_files()
 return {'image':expected_image,'binary_sha256':expected_binary,'process_sha256':proc['sha256'],
         'restart_count':0,'runtime_fingerprint':fingerprint,'account_qos_active':proc['qos_active'],
         'normalization_version':context.get('normalization_version',1)}
def rollback(journal):
 assert_files()
 assert sha((root/'before.json').read_bytes())==journal['before_journal_sha256'],'before journal changed'
 before=json.loads((root/'before.json').read_text())
 assert sha((root/'docker-inspect.before.json').read_bytes())==before['full_inspect_backup']['sha256'],'full inspect backup changed'
 current=inspect();assert current['Image']in[journal['new_image'],before['image']],'third-party image active'
 assert override.read_bytes()in[journal['new_override'].encode(),journal['rollback_override'].encode()],'owned override changed'
 for row in before['backups']:assert sha((root/row['backup']).read_bytes())==row['sha256'],'backup changed'
 atomic(override,journal['rollback_override'].encode());recreate(before['context']['compose_files']+[str(override)])
 result=wait_endpoint(before['image'],before['binary'],before['context'],'rollback',before['fingerprint'],before['qos'])
 record('rollback.json',{**result,'owned_override_retained_for_exact_rollback_image':True,'original_compose_files_untouched':True})
 return result
assert os.geteuid()==0
if MODE in ['apply','rollback','retry','retry-v2']:
 assert not root.is_symlink()
 root.mkdir(mode=0o700,parents=True,exist_ok=True)
 assert root.stat().st_uid==0 and stat.S_IMODE(root.stat().st_mode)==0o700
 operation_lock=(root/'operation.lock').open('a')
 fcntl.flock(operation_lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
if MODE=='rollback':
 journal=json.loads((root/'deployment-journal.json').read_text());print(json.dumps(rollback(journal)));raise SystemExit(0)
if MODE in ['prove-v2','retry-v2']:
 journal=json.loads((root/'deployment-journal.json').read_text())
 saved_raw=(root/'before.json').read_bytes();assert sha(saved_raw)==journal['before_journal_sha256']
 saved=json.loads(saved_raw);original_raw=(root/'docker-inspect.before.json').read_bytes()
 assert sha(original_raw)==saved['full_inspect_backup']['sha256']
 original=json.loads(original_raw)
 assert normalize(original,saved['context'],'before')==saved['fingerprint'],'v1 original inspect/journal mismatch'
 context_v2=copy.deepcopy(saved['context']);context_v2['normalization_version']=2
 expected_v2=normalize(original,context_v2,'before')
 current=inspect()
 if MODE=='retry-v2':host_snapshot('before-retry-v2',current)
 assert current['Image']==saved['image']and current['RestartCount']==0
 assert normalize(current,saved['context'],'rollback')==saved['fingerprint'],'v1 old runtime not restored'
 proof={'normalization_version':2,'original_v1_before_journal_sha256':sha(saved_raw),
  'original_v1_deployment_journal_sha256':sha((root/'deployment-journal.json').read_bytes()),
  'original_inspect_sha256':sha(original_raw),'original_v1_fingerprint':saved['fingerprint'],
  'derived_v2_fingerprint':expected_v2,'derived_only_from_hash_verified_original':True}
 if MODE=='prove-v2':
  latest=json.loads((root/'latest-inspect-new.json').read_text());failed_raw=pathlib.Path(latest['path']).read_bytes()
  assert sha(failed_raw)==latest['sha256']
  proof['failed_runtime_v2_matches_original']=normalize(json.loads(failed_raw),context_v2,'new')==expected_v2
  print(json.dumps(proof));raise SystemExit(0)
 assert override.read_bytes()==journal['rollback_override'].encode()
 assert_files();proc=process_evidence();assert proc['sha256']==saved['binary']
 assert json.loads(call(['docker','image','inspect',journal['new_tag']]))[0]['Id']==journal['new_image']
 record('normalization-v2-proof.json',proof)
 try:
  atomic(override,journal['new_override'].encode());recreate(saved['context']['compose_files']+[str(override)])
  result=wait_endpoint(journal['new_image'],DIGEST,context_v2,'new',expected_v2,saved['qos'])
 except BaseException:
  rollback(journal);raise
 result['normalization_version']=2
 record('deployment-v2.json',{**result,**proof,'physical_acceptance':'PENDING'})
 print(json.dumps(result));raise SystemExit(0)
if MODE=='retry':
 journal=json.loads((root/'deployment-journal.json').read_text())
 saved=json.loads((root/'before.json').read_text())
 assert sha((root/'before.json').read_bytes())==journal['before_journal_sha256']
 assert sha((root/'docker-inspect.before.json').read_bytes())==saved['full_inspect_backup']['sha256']
 assert override.read_bytes()==journal['rollback_override'].encode(),'retry requires exact known rollback override'
 assert_files();current=inspect();host_snapshot('before-retry',current);proc=process_evidence()
 assert current['Image']==saved['image']and current['RestartCount']==0 and proc['sha256']==saved['binary']
 assert normalize(current,saved['context'],'rollback')==saved['fingerprint'],'old runtime not exactly restored'
 assert json.loads(call(['docker','image','inspect',journal['new_tag']]))[0]['Id']==journal['new_image']
 try:
  atomic(override,journal['new_override'].encode());recreate(saved['context']['compose_files']+[str(override)])
  result=wait_endpoint(journal['new_image'],DIGEST,saved['context'],'new',saved['fingerprint'],saved['qos'])
 except BaseException:
  rollback(journal);raise
 record('deployment.json',{**result,'retry':True,'physical_acceptance':'PENDING'})
 print(json.dumps(result));raise SystemExit(0)
before=inspect();assert before['Image']==PIN['runtime']['container']['image_id'],'actual base image changed'
assert before['State']['Running']and before['RestartCount']==0
assert not override.exists()and not override.is_symlink(),'unique overlay already exists'
assert_files();proc=process_evidence();old_sha=PIN['runtime']['endpoint']['file_sha256']
assert proc['sha256']==old_sha and call(['docker','exec',container,'sha256sum',binary]).split()[0]==old_sha
preserve_explicit_empty_dns(before,'') # Validate input shape before any build/recreate.
original_model=json.loads(call(compose(PIN['runtime']['compose_labels']['com.docker.compose.project.config_files'].split(','))+['config','--format','json']))['services']['trusttunnel-runner']
deploy_cpu_present='cpus'in(original_model.get('deploy',{}).get('resources',{}).get('limits',{}))
prototype=preserve_runtime_inputs(before,'services:\n  trusttunnel-runner:\n    image: '+before['Image']+'\n',deploy_cpu_present)
resolved=json.loads(subprocess.check_output(compose(PIN['runtime']['compose_labels']['com.docker.compose.project.config_files'].split(','))+['-f','-','config','--format','json'],input=prototype,text=True,timeout=30))['services']['trusttunnel-runner']
assert Decimal(str(resolved['cpus']))*Decimal(1000000000)==before['HostConfig']['NanoCpus'],'owned Compose CPU constraint not exact'
context={'default_hostname':before['Config']['Hostname']==before['Id'][:12],
 'normalization_version':2,
 'deploy_cpu_present':deploy_cpu_present,
 'hostname_sha256':sha(before['Config']['Hostname'].encode()),
 'compose_files':PIN['runtime']['compose_labels']['com.docker.compose.project.config_files'].split(','),
 'old_overlay_marker':(before['Config'].get('Labels')or{}).get('org.guardex.http3-response-finalization')}
fingerprint=normalize(before,context,'before');qos={k:proc[k]for k in ['qos_active','qos_socket_hash','qos_socket_stat']}
assert proc['qos_active']==any(x.get('account_qos_socket_env')for x in PIN['account_qos']['endpoint_processes'])
free=shutil.disk_usage('/var/lib/docker').free;assert free>1500000000,'insufficient rollback disk'
pre={'node':PIN['node']['code'],'image':before['Image'],'binary':old_sha,'fingerprint':fingerprint,
     'context':context,'qos':qos,'free_bytes':free,'source7_verified':True,'read_only':MODE=='preflight'}
pre['explicit_empty_dns_fields']=[key for key in ['DnsOptions','DnsSearch']if before['HostConfig'].get(key)==[]]
pre['original_nano_cpus']=before['HostConfig']['NanoCpus']
if MODE=='preflight':print(json.dumps(pre));raise SystemExit(0)
assert MODE=='apply'
assert (root/'trusttunnel_endpoint').is_file()and not(root/'trusttunnel_endpoint').is_symlink()
assert (root/'Dockerfile').is_file()and not(root/'Dockerfile').is_symlink()
assert sha((root/'trusttunnel_endpoint').read_bytes())==DIGEST
assert sha((root/'Dockerfile').read_bytes())==DOCKERFILE_SHA
assert not(root/'before.json').exists()and not(root/'deployment-journal.json').exists(),'previous attempt exists'
if EXPECTED_PREFLIGHT:assert fingerprint==EXPECTED_PREFLIGHT['fingerprint']and before['Image']==EXPECTED_PREFLIGHT['image']
root.mkdir(mode=0o700,parents=True,exist_ok=True);assert root.stat().st_uid==0 and stat.S_IMODE(root.stat().st_mode)==0o700
backups=[]
for index,name in enumerate(context['compose_files']):
 path=pathlib.Path(name);target=root/('compose-'+str(index)+'.backup');assert not target.exists()
 shutil.copy2(path,target);target.chmod(0o600);backups.append({'path':name,'backup':target.name,'sha256':sha(target.read_bytes()),'mode':stat.S_IMODE(path.stat().st_mode),'uid':path.stat().st_uid,'gid':path.stat().st_gid})
pre['backups']=backups
assert not(root/'docker-inspect.before.json').exists(),'full inspect backup already exists'
atomic(root/'docker-inspect.before.json',(json.dumps(before,indent=2)+'\n').encode())
pre['full_inspect_backup']={'path':str(root/'docker-inspect.before.json'),
 'sha256':sha((root/'docker-inspect.before.json').read_bytes()),'host_only':True,'mode':'0600'}
record('before.json',pre)
slug=PIN['node']['code'].lower();rollback_tag='guardex-http3-eof-rollback:'+slug+'-'+old_sha[:12]
new_tag='guardex-http3-read-eof:'+slug+'-'+DIGEST[:12]
for tag in [rollback_tag,new_tag]:assert subprocess.run(['docker','image','inspect',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0,'owned image tag exists'
call(['docker','tag',before['Image'],rollback_tag])
context_dir=root/'build-context';context_dir.mkdir(mode=0o700,exist_ok=False)
for name in ['trusttunnel_endpoint','Dockerfile']:shutil.copy2(root/name,context_dir/name)
# The host-only full inspect/compose backups never enter the Docker build context.
with (root/'image-build.log').open('w')as log:
 subprocess.run(['docker','build','--pull=false','--build-arg','BASE_IMAGE='+rollback_tag,'-t',new_tag,str(context_dir)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=90)
new_image=json.loads(call(['docker','image','inspect',new_tag]))[0]['Id']
new_override=preserve_runtime_inputs(before,'services:\n  trusttunnel-runner:\n    image: '+new_tag+'\n',deploy_cpu_present)
rollback_override=preserve_runtime_inputs(before,'services:\n  trusttunnel-runner:\n    image: '+rollback_tag+'\n',deploy_cpu_present)
journal={'new_image':new_image,'new_tag':new_tag,'rollback_tag':rollback_tag,'new_override':new_override,
         'rollback_override':rollback_override,'before_journal_sha256':sha((root/'before.json').read_bytes()),
         'dockerfile_sha256':DOCKERFILE_SHA,'binary_sha256':DIGEST}
record('deployment-journal.json',journal)
try:
 atomic(override,new_override.encode());recreate(context['compose_files']+[str(override)])
 result=wait_endpoint(new_image,DIGEST,context,'new',fingerprint,qos)
except BaseException:
 try:rollback(journal)
 except BaseException as error:record('rollback-failure.json',{'kind':type(error).__name__});raise
 raise
result['full_inspect_backup']=pre['full_inspect_backup']
record('deployment.json',{**result,'node':PIN['node']['code'],'rollback_image':rollback_tag,
                          'physical_acceptance':'PENDING per-node checks','original_compose_files_untouched':True})
print(json.dumps(result))
'''


def run(command, **kwargs):
    return subprocess.run(command, text=True, capture_output=True, timeout=600, **kwargs)


def validate_pin(pin, node):
    assert pin['node']['code'] == node and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', node)
    ipaddress.ip_address(pin['node']['host'])
    runtime = pin['runtime']
    assert runtime['container']['name'] == 'guardex-node-trusttunnel-runner-1'
    assert re.fullmatch(r'sha256:[0-9a-f]{64}', runtime['container']['image_id'])
    assert re.fullmatch(r'[0-9a-f]{64}', runtime['endpoint']['file_sha256'])
    labels = runtime['compose_labels']
    assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', labels['com.docker.compose.project'])
    files = labels['com.docker.compose.project.config_files'].split(',')
    assert files and len(files) == len(set(files))
    assert [row['path'] for row in runtime['compose_files']] == files, 'incomplete compose digests'
    inputs = runtime['baseline_inputs']
    assert len(inputs) == 7, 'exactly seven baseline input digests required'
    paths = []
    for row in runtime['compose_files']:
        assert re.fullmatch(r'[0-9a-f]{64}', row['sha256'])
        paths.append(row['path'])
    for row in inputs:
        assert row['matches_baseline'] is True and row['present_candidates'], 'missing baseline source'
        assert re.fullmatch(r'[0-9a-f]{64}', row['expected_sha256'])
        paths.extend(item['path'] for item in row['present_candidates'])
    assert all(isinstance(path, str) and Path(path).is_absolute() and
               '\0' not in path and '\n' not in path and '..' not in Path(path).parts for path in paths)
    assert len(pin['account_qos']['endpoint_processes']) == 1
    assert isinstance(pin['account_qos']['endpoint_processes'][0]['account_qos_socket_env'], list)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--node', required=True)
    parser.add_argument('--mode', choices=['plan', 'preflight', 'apply', 'rollback', 'retry', 'prove-v2', 'retry-v2'], default='plan')
    parser.add_argument('--pins', required=True, type=Path, help='Safe per-node inventory with exact deployed image, compose and seven source hashes')
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--receipt', required=True, type=Path, help='Successful Linux build receipt with build_exit and binary_sha256')
    parser.add_argument('--operation', required=True, help='Unique retained operation ID, reused for rollback')
    parser.add_argument('--reuse-uploaded', action='store_true', help='Skip copying; remote full SHA checks still run before any recreate')
    args = parser.parse_args()
    assert re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9-]{0,63}', args.operation), 'invalid operation ID'
    assert not args.reuse_uploaded or args.mode == 'apply', '--reuse-uploaded is apply-only'
    global BINARY, RECEIPT, REMOTE, OVERRIDE
    BINARY, RECEIPT = args.binary.resolve(strict=True), args.receipt.resolve(strict=True)
    REMOTE = '/var/lib/guardex-remediation/http3-rollout-' + args.operation
    OVERRIDE = '/opt/guardex-node/docker-compose.http3-rollout-' + args.operation + '.yml'
    pins = json.loads(args.pins.read_text())['nodes']
    pin = pins[args.node]
    validate_pin(pin, args.node)
    receipt = json.loads(RECEIPT.read_text())
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    assert receipt['build_exit'] == 0 and digest == receipt['binary_sha256']
    dockerfile_sha = hashlib.sha256(OVERLAY.read_bytes()).hexdigest()
    if args.mode == 'plan':
        print(json.dumps({'node': args.node, 'base_image': pin['runtime']['container']['image_id'],
                          'binary_sha256': digest, 'unique_override': OVERRIDE,
                          'only_service': 'trusttunnel-runner', 'mode': 'plan', 'mutations': False}, indent=2))
        return
    host = 'root@' + pin['node']['host']
    copy_host = 'root@' + ('[' + pin['node']['host'] + ']' if ':' in pin['node']['host'] else pin['node']['host'])
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', host]
    def execute(mode, preflight=None):
        values = {'PIN': pin, 'REMOTE': REMOTE, 'OVERRIDE': OVERRIDE, 'DIGEST': digest,
                  'DOCKERFILE_SHA': dockerfile_sha, 'MODE': mode, 'EXPECTED_PREFLIGHT': preflight}
        program = '\n'.join(name + '=' + repr(value) for name, value in values.items()) + '\n' + PROGRAM
        result = run(ssh + ['python3 -'], input=program)
        log = ROOT / (args.node + '-' + mode + '.log')
        log.write_text(result.stdout + result.stderr)
        log.chmod(0o600)
        result.check_returncode()
        return json.loads(result.stdout)
    if args.mode in ['rollback', 'retry', 'prove-v2', 'retry-v2']:
        print(json.dumps(execute(args.mode), indent=2))
        return
    preflight = execute('preflight')
    if args.mode == 'preflight':
        print(json.dumps(preflight, indent=2))
        return
    if not args.reuse_uploaded:
        run(ssh + [shlex.join(['install', '-d', '-m', '700', REMOTE])]).check_returncode()
        for source, name in [(BINARY, 'trusttunnel_endpoint'), (OVERLAY, 'Dockerfile')]:
            run(['scp', '-C', '-o', 'BatchMode=yes', str(source), copy_host + ':' + REMOTE + '/' + name]).check_returncode()
    print(json.dumps(execute('apply', preflight), indent=2))


if __name__ == '__main__':
    main()
