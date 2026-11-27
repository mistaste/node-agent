"""Guarded, independently reversible API-only SNI selection on the shared exit."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
import policy as p
from qualify import BINARY, LOADER, BUNDLE, HAPROXY_SHA, LOADER_SHA

ROOT=Path('/var/lib/guardex-yandex-api-path-20261127')
STATE=ROOT/'exit.json'
UNIT='guardex-yandex-api-path'
TIMER=UNIT+'-rollback'
SYNC=UNIT+'-sync'

def run(args,data=None,check=True,timeout=10):
    r=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
    if check and r.returncode:raise RuntimeError('command_failed:'+args[0])
    return r

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def private(path,directory=False):
    info=path.lstat()
    assert info.st_uid==0 and not info.st_mode&0o022 and not stat.S_ISLNK(info.st_mode)
    assert stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)

def save(value):
    temp=STATE.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.chmod(0o600);temp.replace(STATE)

def basics():
    assert os.geteuid()==0
    private(ROOT,True)
    assert not ROOT.stat().st_mode&0o077
    for name in ('owner.json','controller.py','policy.py','qualify.py','qualification.json'):private(ROOT/name)
    assert json.loads((ROOT/'owner.json').read_text())['task']=='guardex-yandex-api-path-20261127'
    assert sha(BINARY)==HAPROXY_SHA and sha(LOADER)==LOADER_SHA
    assert Path('/proc/self/ns/net').stat().st_ino==Path('/proc/1/ns/net').stat().st_ino
    route=json.loads(run(['ip','-j','route','get','37.230.168.172']).stdout)
    assert route[0]['prefsrc']==p.PUBLIC,'wrong_exit_host'
    qualified=json.loads((ROOT/'qualification.json').read_text())
    assert qualified['isolated_only'] and qualified['namespace_cleanup_verified'] and qualified['strict_tls']
    assert qualified['private_listener_denied'] and qualified['dynamic_original_destination_verified'] and qualified['withdrawal_verified']
    assert qualified['policy_sha256']==sha(ROOT/'policy.py'),'qualification_source_changed'
    return qualified

def owner():
    qualification=basics();private(STATE)
    value=json.loads(STATE.read_text())
    assert value['controller_sha256']==sha(ROOT/'controller.py')
    assert value['policy_sha256']==sha(ROOT/'policy.py')
    assert value['configuration_sha256']==sha(ROOT/'haproxy.cfg')
    assert value['qualification_sha256']==sha(ROOT/'qualification.json')
    return value,qualification

def fields(unit):
    r=run(['systemctl','show',unit,'-p','ActiveState','-p','MainPID','-p','Description'],check=False)
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)

def validate_backbone():
    addresses=json.loads(run(['ip','-j','address','show','dev','gxwg0']).stdout)
    assert any(a.get('local')==p.LOCAL for row in addresses for a in row.get('addr_info',[]))
    allowed={s.strip(',') for line in run(['wg','show','gxwg0','allowed-ips']).stdout.splitlines() for s in line.split()[1:]}
    assert {peer+'/32' for peer in p.CLIENTS}<=allowed,'backbone_identity_changed'

def resolve():
    # DNS rotation changes only this bounded public-destination set. The exact
    # API SNI and the original destination for every other name stay fixed.
    result=run(['getent','ahostsv4',p.HOST],timeout=4).stdout
    return p.addresses([line.split()[0] for line in result.splitlines() if line.split()])

def healthy():
    r=run(['curl','--silent','--show-error','--resolve',p.HOST+':443:'+p.SECONDARY,
           '--connect-timeout','2','--max-time','4','--output','/dev/null','--write-out','%{http_code}',
           'https://'+p.HOST+'/health'],check=False,timeout=6)
    return r.returncode==0 and r.stdout=='200'

def table():
    r=run(['nft','-j','-s','list','table','ip',p.TABLE],check=False)
    if r.returncode:
        tables=json.loads(run(['nft','-j','list','tables']).stdout)['nftables']
        assert not any(row.get('table',{}).get('name')==p.TABLE for row in tables),'unreadable_owned_table'
        return None
    return json.loads(r.stdout)

def verify_table(value,qualification):
    current=table()
    if current is None:return False
    sets=value.get('acceptable_address_sets',[value['addresses']])
    valid=False
    for addresses in sets:
        try: valid=p.nft_identity(current,addresses)==qualification['nft_structure_sha256']
        except AssertionError:continue
        if valid:break
    assert valid,'changed_owned_nat_refusal'
    return True

def deselect(value,qualification):
    if verify_table(value,qualification):run(['nft','delete','table','ip',p.TABLE])

def unit_text():
    return f'''[Unit]
Description={p.TAG}
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
ExecStartPre=/usr/bin/python3 {ROOT}/controller.py prepare
ExecStart={LOADER} --library-path {BUNDLE}/usr/lib {BINARY} -db -f {ROOT}/haproxy.cfg
ExecStartPost=/usr/bin/python3 {ROOT}/controller.py select
ExecStopPost=/usr/bin/python3 {ROOT}/controller.py stop-select
Restart=on-failure
RestartSec=5s
TimeoutStartSec=25s
KillSignal=SIGUSR1
TimeoutStopSec=80s
MemoryMax=128M
LimitNOFILE=8192
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
'''

def sync_service():return f'''[Unit]
Description={p.TAG} health and DNS convergence
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {ROOT}/controller.py sync
TimeoutStartSec=20s
NoNewPrivileges=yes
'''

def sync_timer():return f'''[Unit]
Description={p.TAG} bounded convergence timer
[Timer]
OnActiveSec=15s
OnUnitActiveSec=30s
AccuracySec=1s
Unit={SYNC}.service
[Install]
WantedBy=timers.target
'''

def linked(name,text):
    path=Path('/etc/systemd/system')/name
    assert path.is_symlink() and path.lstat().st_uid==0 and path.resolve()==ROOT/name
    assert (ROOT/name).read_text()==text,'changed_owned_unit'

def authorized(value):
    if value['status']=='retained':return
    assert value['status'] in ('starting','applied') and time.time()<value['deadline_epoch']-10
    assert fields(TIMER+'.timer').get('ActiveState')=='active'

def prepare():
    value,q=owner();authorized(value);linked(UNIT+'.service',unit_text());validate_backbone()
    current=run(['iptables','-w','2','-S',p.CHAIN],check=False)
    if current.returncode:
        run(['iptables','-w','2','-N',p.CHAIN]);current=run(['iptables','-w','2','-S',p.CHAIN])
    assert current.stdout in q['chain_snapshots'],'changed_owned_filter'
    count=q['chain_snapshots'].index(current.stdout)
    for rule in p.rules()[count:]:run(['iptables','-w','2','-A',p.CHAIN,*rule])
    assert run(['iptables','-w','2','-S',p.CHAIN]).stdout==q['chain_snapshots'][-1]
    if run(['iptables','-w','2','-C','INPUT',*p.jump()],check=False).returncode:
        run(['iptables','-w','2','-I','INPUT','1',*p.jump()])

def select():
    value,q=owner();authorized(value);linked(UNIT+'.service',unit_text());validate_backbone()
    assert fields(UNIT+'.service').get('Description')==p.TAG
    assert p.LOCAL+':'+str(p.PORT) in run(['ss','-Hlnt','sport = :'+str(p.PORT)]).stdout
    assert healthy(),'bridge_unhealthy'
    if not verify_table(value,q):run(['nft','-f','-'],data=p.nat_config(value['addresses']))
    assert verify_table(value,q)

def sync():
    value,q=owner();authorized(value);linked(UNIT+'.service',unit_text());validate_backbone()
    if fields(UNIT+'.service').get('ActiveState')!='active':
        deselect(value,q);return {'selected':False,'bridge_healthy':False}
    if not healthy():
        value['health_failures']=value.get('health_failures',0)+1;save(value)
        if value['health_failures']<2:
            return {'selected':verify_table(value,q),'bridge_healthy':False}
        # Withdraw only new-flow selection. Existing TLS streams keep their
        # conntrack entries and the running relay; no write is replayed.
        deselect(value,q);return {'selected':False,'bridge_healthy':False}
    value['health_failures']=0
    prepare() # Heal only the independently owned INPUT jump/rules after reconciliation.
    history=value.get('address_history',{ip:time.time()+600 for ip in value['addresses']})
    try:
        for ip in resolve():history[ip]=time.time()+600
    except (RuntimeError,AssertionError,subprocess.TimeoutExpired):pass
    desired=sorted(ip for ip,expiry in history.items() if expiry>time.time())
    if not desired:desired=value['addresses'] # Retain last validated DNS during a resolver outage.
    desired=p.addresses(desired)
    present=verify_table(value,q)
    value['acceptable_address_sets']=[value['addresses'],desired];save(value)
    if not present:run(['nft','-f','-'],data=p.nat_config(desired))
    elif desired!=value['addresses']:
        run(['nft','-f','-'],data=f'flush set ip {p.TABLE} gateway_ips\nadd element ip {p.TABLE} gateway_ips {{ {", ".join(desired)} }}\n')
    assert p.nft_identity(table(),desired)==q['nft_structure_sha256']
    value.update(addresses=desired,acceptable_address_sets=[desired],address_history=history,last_sync_epoch=time.time());save(value)
    return {'selected':True,'bridge_healthy':True,'destination_count':len(desired)}

def arm():
    q=basics();assert not STATE.exists();validate_backbone()
    assert table() is None and not run(['ss','-Hlnt','sport = :'+str(p.PORT)]).stdout.strip()
    assert run(['iptables','-w','2','-S',p.CHAIN],check=False).returncode!=0
    assert healthy(),'edge_not_qualified'
    for name in (UNIT+'.service',SYNC+'.service',SYNC+'.timer'):
        path=Path('/etc/systemd/system')/name;assert not path.exists() and not path.is_symlink()
        assert fields(name).get('ActiveState') not in ('active','activating'),'occupied_owned_unit_name'
    config=ROOT/'haproxy.cfg';config.write_text(p.haproxy_config());config.chmod(0o600)
    run([str(LOADER),'--library-path',str(BUNDLE/'usr/lib'),str(BINARY),'-c','-f',str(config)])
    addresses=resolve()
    value=dict(status='armed',deadline_epoch=time.time()+900,mutation_intent=False,addresses=addresses,
               controller_sha256=sha(ROOT/'controller.py'),policy_sha256=sha(ROOT/'policy.py'),
               configuration_sha256=sha(config),qualification_sha256=sha(ROOT/'qualification.json'))
    save(value)
    run(['systemd-run','--quiet','--unit',TIMER,'--on-active=900s','--timer-property=AccuracySec=1s',
         '/usr/bin/python3',str(ROOT/'controller.py'),'rollback'])
    return value

def apply():
    value,q=owner();assert value['status']=='armed' and value['deadline_epoch']-time.time()>780
    assert fields(TIMER+'.timer').get('ActiveState')=='active'
    value.update(status='starting',mutation_intent=True);save(value)
    for name,text in [(UNIT+'.service',unit_text()),(SYNC+'.service',sync_service()),(SYNC+'.timer',sync_timer())]:
        file=ROOT/name;file.write_text(text);file.chmod(0o600)
        dest=Path('/etc/systemd/system')/name;assert not dest.exists() and not dest.is_symlink();dest.symlink_to(file)
    run(['systemctl','daemon-reload']);run(['systemctl','start',UNIT+'.service'],timeout=30)
    value,q=owner();assert fields(UNIT+'.service').get('ActiveState')=='active'
    value['status']='applied';save(value);run(['systemctl','start',SYNC+'.timer']);return value

def rollback(force=False):
    value,q=owner()
    if value['status']=='retained' and not force:return {'status':'retained','automatic_rollback_ignored':True}
    if value['status']=='rolled_back':return value
    if value['mutation_intent']:
        deselect(value,q)
        for name,text in [(SYNC+'.timer',sync_timer()),(SYNC+'.service',sync_service())]:
            path=Path('/etc/systemd/system')/name
            if path.exists() or path.is_symlink():
                linked(name,text);run(['systemctl','stop',name],check=False)
        run(['systemctl','stop',UNIT+'.service'],check=False,timeout=90)
        current=run(['iptables','-w','2','-S',p.CHAIN],check=False)
        if not current.returncode:
            assert current.stdout in q['chain_snapshots'],'changed_owned_filter'
            if not run(['iptables','-w','2','-C','INPUT',*p.jump()],check=False).returncode:
                run(['iptables','-w','2','-D','INPUT',*p.jump()])
            run(['iptables','-w','2','-F',p.CHAIN]);run(['iptables','-w','2','-X',p.CHAIN])
        for name,text in [(UNIT+'.service',unit_text()),(SYNC+'.service',sync_service()),(SYNC+'.timer',sync_timer())]:
            dest=Path('/etc/systemd/system')/name
            if dest.exists() or dest.is_symlink():linked(name,text);run(['systemctl','disable',name],check=False);dest.unlink()
        run(['systemctl','daemon-reload'])
    value.update(status='rolled_back',rolled_back_epoch=time.time());save(value)
    run(['systemctl','stop',TIMER+'.timer'],check=False);return value

def retain():
    value,q=owner();assert value['status']=='applied' and value['deadline_epoch']-time.time()>45
    private(ROOT/'acceptance.json');e=json.loads((ROOT/'acceptance.json').read_text())
    assert e['strict_tls'] and e['original_routes_preserved'] and e['real_phone_all_five_verified']
    for country in ('FI','NL','DE','PL','US'):
        row=e['countries'][country];assert row['fresh_successes']>=20 and row['failed']==0
    assert verify_table(value,q) and healthy()
    run(['systemctl','enable',UNIT+'.service',SYNC+'.timer'])
    value.update(status='retained',retained_epoch=time.time(),acceptance_sha256=sha(ROOT/'acceptance.json'));save(value)
    run(['systemctl','stop',TIMER+'.timer']);return value

def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['arm','apply','inspect','prepare','select','stop-select','sync','retain','rollback','backout'])
    action=parser.parse_args().action
    if action in ('prepare','select','stop-select'):
        if action=='prepare':prepare()
        elif action=='select':select()
        else:
            value,q=owner();linked(UNIT+'.service',unit_text());deselect(value,q)
        return
    with (ROOT/'control.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if action=='arm':value=arm()
        elif action=='apply':value=apply()
        elif action=='sync':value=sync()
        elif action=='retain':value=retain()
        elif action in ('rollback','backout'):value=rollback(force=action=='backout')
        else:value,_=owner()
    print(json.dumps({k:v for k,v in value.items() if k in ('status','deadline_epoch','selected','bridge_healthy','destination_count')}))

if __name__=='__main__':main()
