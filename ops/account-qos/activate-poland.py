#!/usr/bin/env python3
import pathlib,subprocess,json,re,time,shutil
root=pathlib.Path('/opt/guardex-node');save=pathlib.Path('/var/lib/guardex-remediation/account-qos-20261028');state={k:v for k,v in json.loads((save/'original.json').read_text()).items()if k in ('trusttunnel-runner','transport-bundle-runner')}
# This pilot is intentionally bound to the selected node, not a fleet selector.
assert subprocess.check_output(['hostname','-I'],text=True).split().count('212.127.91.131')==1
assert not (save/'activated.json').exists()
for service,record in state.items():
 current=json.loads(subprocess.check_output(['docker','inspect','guardex-node-'+service+'-1'],text=True))[0];assert current['Image']==record['running_original_image'],service+' changed since preflight'
env=root/'.env';raw=env.read_text();line=re.search(r'^COMPOSE_FILE=(.*)$',raw,re.M);assert line
files=[str(root/x)if not pathlib.Path(x).is_absolute()else x for x in line.group(1).strip().strip('"').strip("'").split(':')];(save/'compose-files.json').write_text(json.dumps(files));shutil.copy2(env,save/'env.before');(save/'env.before').chmod(0o600)
overlay=root/'docker-compose.account-qos.yml';assert not overlay.exists()
overlay.write_text('services:\n'+''.join('  '+service+':\n'+'    image: guardex-poland-qos-'+service+':pilot1\n    environment:\n      GUARDEX_ACCOUNT_QOS_SOCKET: /run/guardex-account-qos/broker.sock\n    volumes:\n      - /run/guardex-account-qos:/run/guardex-account-qos\n'for service in state))
cmd=['docker','compose','--project-directory',str(root),'-p','guardex-node']
for f in files+[str(overlay)]:cmd+=['-f',f]
subprocess.run(cmd+['config','--quiet'],check=True)
# Endpoint processes use gid 65532; systemd requires a resolvable group.
if subprocess.run(['getent','group','65532'],stdout=subprocess.DEVNULL).returncode:
 subprocess.run(['groupadd','--system','--gid','65532','guardex-vpn-data'],check=True)
subprocess.run(['systemctl','enable','--now','guardex-account-qos'],check=True)
try:
 for service in ['trusttunnel-runner','transport-bundle-runner']:
  subprocess.run(cmd+['up','-d','--no-deps','--no-build',service],check=True)
  time.sleep(2)

  d=json.loads(subprocess.check_output(['docker','inspect','guardex-node-'+service+'-1'],text=True))[0];assert d['State']['Running'],service+' not running'
 new=re.sub(r'^COMPOSE_FILE=.*$',lambda m:m.group(0)+':'+overlay.name,raw,flags=re.M);tmp=root/'.env.qos-next';tmp.write_text(new);tmp.chmod(0o600);tmp.replace(env)
 (save/'activated.json').write_text(json.dumps({'at':time.time(),'overlay':str(overlay),'scope':'Poland only'}))
except BaseException:
 subprocess.run(['python3',str(save/'rollback.py')],check=True);raise
print('Poland account QoS activated')
