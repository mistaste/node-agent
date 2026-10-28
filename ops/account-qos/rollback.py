#!/usr/bin/env python3
import pathlib,subprocess,json,re,time,os
root=pathlib.Path('/opt/guardex-node');save=pathlib.Path('/var/lib/guardex-remediation/account-qos-20261028')
# Stopping the broker immediately disables shaping, retaining VPN routing.
subprocess.run(['systemctl','stop','guardex-account-qos'],check=True)
state={k:v for k,v in json.loads((save/'original.json').read_text()).items()if k in ('trusttunnel-runner','transport-bundle-runner')};overlay=save/'rollback-images.yml'
overlay.write_text('services:\n'+''.join('  '+service+':\n'+'    image: '+record['image']+'\n    environment:\n      GUARDEX_ACCOUNT_QOS_SOCKET: ""\n'for service,record in state.items()))
files=json.loads((save/'compose-files.json').read_text());cmd=['docker','compose','--project-directory',str(root),'-p','guardex-node']
for f in files:cmd+=['-f',f]
cmd+=['-f',str(overlay)]
subprocess.run(cmd+['config','--quiet'],check=True)
for service in ['trusttunnel-runner','transport-bundle-runner']:
 subprocess.run(cmd+['up','-d','--no-deps','--no-build',service],check=True)

# Preserve unrelated environment changes; remove only the pilot overlay.
env=root/'.env';raw=env.read_text();line=re.search(r'^COMPOSE_FILE=(.*)$',raw,re.M)
if line:
 parts=line.group(1).strip().strip('"').strip("'").split(':');parts=[x for x in parts if pathlib.Path(x).name!='docker-compose.account-qos.yml' and x!=str(overlay)];parts.append(str(overlay));raw=re.sub(r'^COMPOSE_FILE=.*$',lambda _: 'COMPOSE_FILE='+':'.join(parts),raw,flags=re.M);tmp=root/'.env.qos-rollback';tmp.write_text(raw);tmp.chmod(0o600);tmp.replace(env)
subprocess.run(['systemctl','disable','guardex-account-qos'],check=True)
print('Poland QoS rolled back; original transport images restored')
