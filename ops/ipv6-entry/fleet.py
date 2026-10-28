#!/usr/bin/env python3
"""Maintain isolated optional IPv6 TCP entries and a short-lived public cache.

Run on the existing backend host under its root-only SSH inventory. No secrets,
credentials or application payloads are written to the capability cache.
"""
import argparse,base64,concurrent.futures,datetime,hashlib,ipaddress,json,os,pathlib,subprocess

REMOTE_SETUP = r"""
import base64,hashlib,ipaddress,json,pathlib,re,subprocess
def run(*a):return subprocess.check_output(a,text=True,timeout=25).strip()
def result(**v):print(json.dumps(v))
route=subprocess.run(['ip','-j','-6','route','get',PROBE],capture_output=True,text=True,timeout=5)
if route.returncode:result(state='no_route');raise SystemExit()
routes=json.loads(route.stdout);source=routes[0].get('prefsrc') or routes[0].get('src')
if not source or not ipaddress.IPv6Address(source).is_global:result(state='no_address');raise SystemExit()
hosts=pathlib.Path('/opt/guardex-node/data/trusttunnel/hosts.toml').read_text()
def field(k):return json.loads(re.search(r'^'+k+r'\s*=\s*(".*")\s*$',hosts,re.M).group(1))
hostname=field('hostname');cert=field('cert_chain_path')
assert cert.startswith('/data/trusttunnel/')
cert='/opt/guardex-node/data/trusttunnel/'+cert.removeprefix('/data/trusttunnel/')
pub=subprocess.run(['openssl','x509','-in',cert,'-pubkey','-noout'],capture_output=True,check=True).stdout
der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,check=True).stdout
pin=base64.b64encode(hashlib.sha256(der).digest()).decode()
root=pathlib.Path('/var/lib/guardex-ipv6-entry');root.mkdir(mode=0o700,exist_ok=True)
listeners=run('ss','-6Hln','sport','=',':443')
if not listeners and INSTALL:
 container='guardex-node-transport-bundle-runner-1'
 assert run('docker','inspect','--format','{{.State.Running}}',container)=='true'
 cfg=pathlib.Path('/opt/guardex-node/data/transport-bundle/ipv6-entry.cfg')
 content='global\n    maxconn 256\ndefaults\n    mode tcp\n    timeout connect 5s\n    timeout client 24h\n    timeout server 24h\n    option clitcpka\n    option srvtcpka\nfrontend guardex_optional_ipv6\n    bind [::]:443 v6only\n    default_backend existing_sni\nbackend existing_sni\n    server local 127.0.0.1:443\n'
 if cfg.exists():assert cfg.read_text()==content
 else:cfg.write_text(content);cfg.chmod(0o600)
 start=cfg.with_name('ipv6-entry-start.sh')
 stop=cfg.with_name('ipv6-entry-stop.sh')
 start.write_text('#!/bin/sh\nset -eu\numask 077\necho $$ > /tmp/guardex-ipv6-entry.pid\nexec /usr/sbin/haproxy -db -f /data/transport-bundle/ipv6-entry.cfg\n')
 stop.write_text('#!/bin/sh\nset -eu\ntest -f /tmp/guardex-ipv6-entry.pid || exit 0\npid=$(cat /tmp/guardex-ipv6-entry.pid)\ncase "$pid" in ""|*[!0-9]*) exit 1;; esac\ntest -f /proc/$pid/cmdline || exit 0\ncase "$(tr "\\000" " " < /proc/$pid/cmdline)" in *"/data/transport-bundle/ipv6-entry.cfg"*) kill -TERM "$pid";; *) exit 1;; esac\nrm -f /tmp/guardex-ipv6-entry.pid\n')
 start.chmod(0o700);stop.chmod(0o700)
 unit=pathlib.Path('/etc/systemd/system/guardex-ipv6-entry.service')
 expected='[Unit]\nDescription=Guardex optional IPv6 client entry\nAfter=docker.service network-online.target\nRequires=docker.service\n[Service]\nType=simple\nExecStart=/usr/bin/docker exec guardex-node-transport-bundle-runner-1 /bin/sh /data/transport-bundle/ipv6-entry-start.sh\nExecStop=/usr/bin/docker exec guardex-node-transport-bundle-runner-1 /bin/sh /data/transport-bundle/ipv6-entry-stop.sh\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=20\n[Install]\nWantedBy=multi-user.target\n'
 if unit.exists():assert unit.read_text()==expected
 else:
  run('docker','exec',container,'/usr/sbin/haproxy','-c','-f','/data/transport-bundle/ipv6-entry.cfg')
  unit.write_text(expected);run('systemctl','daemon-reload')
 run('systemctl','enable','--now',unit.name)
listeners=run('ss','-6Hln','sport','=',':443')
result(state='ready' if listeners else 'listener_failed',address=source,hostname=hostname,spki_sha256=pin)
"""

REMOTE_PROBE = r"""
import base64,hashlib,json,socket,ssl,subprocess
result={'state':'probe_failed'}
try:
 context=ssl.create_default_context();context.set_alpn_protocols(['h2'])
 with socket.create_connection((ADDRESS,443),timeout=4) as raw:
  with context.wrap_socket(raw,server_hostname=HOSTNAME) as connection:
   assert ':' in connection.getpeername()[0] and not connection.getpeername()[0].startswith('::ffff:')
   assert connection.selected_alpn_protocol()=='h2'
   cert=connection.getpeercert(binary_form=True)
 pub=subprocess.run(['openssl','x509','-inform','DER','-pubkey','-noout'],input=cert,capture_output=True,check=True,timeout=5).stdout
 der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,check=True,timeout=5).stdout
 assert base64.b64encode(hashlib.sha256(der).digest()).decode()==PIN
 result={'state':'verified'}
except Exception as error:result['probe_error']=type(error).__name__
print(json.dumps(result))
"""

def command(args,**kwargs):
    return subprocess.run(args,capture_output=True,text=True,timeout=45,check=True,**kwargs).stdout

def ssh(host,request):
    ip=ipaddress.ip_address(host)
    if ip.version!=4 or not ip.is_global:raise ValueError('invalid inventory host')
    return json.loads(command(['ssh','-i','/etc/guardex-ipv6-entry/id_ed25519','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/etc/guardex-ipv6-entry/known_hosts','-o','ConnectTimeout=5','root@'+str(ip)],input=json.dumps(request)+'\n'))

def inventory(path=None):
    if path:
        rows=json.loads(pathlib.Path(path).read_text())
        if not isinstance(rows,list) or len(rows)>128:raise ValueError('invalid inventory')
        if len({r['server_id'] for r in rows})!=len(rows):raise ValueError('duplicate server')
        for row in rows:
            if ipaddress.ip_address(row['host']).version!=4 or not ipaddress.ip_address(row['host']).is_global:raise ValueError('invalid inventory host')
        return rows
    query="""SELECT json_agg(x) FROM (SELECT DISTINCT s.id server_id,s.host FROM servers s JOIN node_inbound_deployments d ON d.server_id=s.id JOIN inbounds i ON i.id=d.inbound_id WHERE s.is_active AND d.status='active' AND i.engine='trusttunnel')x"""
    return json.loads(command(['docker','exec','guardex-postgres-1','psql','-X','-U','postgres','-d','guardex','-Atc',query]) or '[]') or []

def check(node,install):
    now=datetime.datetime.now(datetime.timezone.utc)
    record={'server_id':node['server_id'],'state':'probe_failed','verified_at':now.isoformat(),'expires_at':(now+datetime.timedelta(minutes=3)).isoformat()}
    try:
        setup=ssh(node['host'],{'action':'setup','install':install})
        record.update({k:v for k,v in setup.items() if k in ('state','address','hostname')})
        if setup['state']=='ready':
            # Independent external IPv6 vantage, never self-connect as proof.
            vantage='212.127.91.131' if node['host']!='212.127.91.131' else '207.241.172.230'
            record.update(ssh(vantage,{'action':'probe','address':setup['address'],'hostname':setup['hostname'],'pin':setup['spki_sha256']}))
    except subprocess.CalledProcessError:record.update(state='verifier_unavailable',error_code='ipv6_verifier_access_failed')
    except Exception:record.update(state='verifier_unavailable',error_code='ipv6_verifier_failed')
    return record

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install',action='store_true',help='Install only the separate optional IPv6 listener when absent')
    parser.add_argument('--output',default='/var/lib/guardex-ipv6-entry/capabilities.json')
    parser.add_argument('--inventory',help='Root-owned, provisioned server ID/public IPv4 inventory')
    args=parser.parse_args()
    nodes=inventory(args.inventory)
    if len(nodes)>128:raise ValueError('unbounded inventory')
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        rows=list(pool.map(lambda node:check(node,args.install),nodes))
    output=pathlib.Path(args.output);output.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
    temporary=output.with_suffix('.next');temporary.write_text(json.dumps({'schema':1,'entries':rows},indent=2)+'\n');temporary.chmod(0o644);os.replace(temporary,output)
    print(json.dumps({'servers':len(rows),'states':{row['server_id']:row['state'] for row in rows}}))

if __name__=='__main__':main()
