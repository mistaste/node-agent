"""Guarded TLS passthrough on82; consumes only the existing PROXY envelope."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import policy as p

ROOT = Path('/var/lib/guardex-yandex-api-path-20261127')
STATE, CONFIG = ROOT/'edge.json', Path('/etc/nginx/guardex-api-stream.conf')
TIMER = 'guardex-yandex-api-edge-rollback'

def run(args, check=True):
    r=subprocess.run(args,capture_output=True,text=True,timeout=12)
    if check and r.returncode:raise RuntimeError('command_failed:'+args[0])
    return r

def sha(data):return hashlib.sha256(data).hexdigest()

def save(value):
    path=STATE.with_suffix('.tmp');path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600);path.replace(STATE)

def owner():
    for path in (ROOT, ROOT/'owner.json', Path(__file__), ROOT/'policy.py'):
        info=path.lstat();assert info.st_uid==0 and not info.st_mode&0o022 and not stat.S_ISLNK(info.st_mode)
    assert not ROOT.stat().st_mode&0o077
    info=CONFIG.lstat();assert info.st_uid==0 and stat.S_ISREG(info.st_mode) and not info.st_mode&0o022
    assert json.loads((ROOT/'owner.json').read_text())['task']=='guardex-yandex-api-path-20261127'
    route=json.loads(run(['ip','-j','route','get','1.1.1.1']).stdout)
    assert route[0]['prefsrc']==p.SECONDARY,'wrong_edge_host'

def restore(value):
    current=CONFIG.read_text();original=p.restore_edge(current)
    temporary=CONFIG.with_suffix('.guardex-yandex.tmp')
    temporary.write_text(original);temporary.chmod(CONFIG.stat().st_mode&0o777);temporary.replace(CONFIG)
    run(['nginx','-t']);run(['systemctl','reload','nginx.service'])
    value.update(status='rolled_back',rolled_back_epoch=time.time());save(value)
    run(['systemctl','stop',TIMER+'.timer'],check=False)

def main():
    os.umask(0o077);assert os.geteuid()==0;owner()
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['apply','inspect','retain','rollback','backout'])
    parser.add_argument('--expected-before-sha256');args=parser.parse_args()
    with (ROOT/'edge.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.action=='apply':
            assert not STATE.exists(),'edge_scope_exists'
            before=CONFIG.read_bytes();assert sha(before)==args.expected_before_sha256,'changed_edge_configuration'
            after=p.render_edge(before.decode())
            assert not run(['ss','-Hlnt','sport = :19446']).stdout.strip(),'occupied_edge_port'
            (ROOT/'edge-before.conf').write_bytes(before);(ROOT/'edge-before.conf').chmod(0o600)
            value=dict(status='armed',deadline_epoch=time.time()+1200,
                       before_sha256=sha(before),after_sha256=sha(after.encode()),
                       controller_sha256=sha(Path(__file__).read_bytes()),policy_sha256=sha((ROOT/'policy.py').read_bytes()))
            save(value)
            run(['systemd-run','--quiet','--unit',TIMER,'--on-active=1200s',
                 '--timer-property=AccuracySec=1s','/usr/bin/python3',str(Path(__file__).resolve()),'rollback'])
            temporary=CONFIG.with_suffix('.guardex-yandex.tmp')
            try:
                assert CONFIG.read_bytes()==before,'concurrent_edge_change'
                temporary.write_text(after);temporary.chmod(CONFIG.stat().st_mode&0o777);temporary.replace(CONFIG)
                run(['nginx','-t']);run(['systemctl','reload','nginx.service'])
                value['status']='applied';save(value)
            except BaseException:
                if CONFIG.read_text()==after:restore(value)
                raise
        else:
            value=json.loads(STATE.read_text())
            assert value['controller_sha256']==sha(Path(__file__).read_bytes())
            assert value['policy_sha256']==sha((ROOT/'policy.py').read_bytes())
            if args.action in ('rollback','backout'):
                if value['status']=='retained' and args.action=='rollback':
                    print(json.dumps({'status':'retained','automatic_rollback_ignored':True}));return
                if value['status']!='rolled_back':restore(value)
            elif args.action=='retain':
                assert value['status']=='applied'
                p.restore_edge(CONFIG.read_text()) # Exact owned lines must remain intact.
                assert json.loads((ROOT/'edge-acceptance.json').read_text())['fresh_tls_successes']>=20
                value['status']='retained';save(value);run(['systemctl','stop',TIMER+'.timer'])
        print(json.dumps({'status':value['status'],'deadline_epoch':value['deadline_epoch']}))

if __name__=='__main__':main()
