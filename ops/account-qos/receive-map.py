#!/usr/bin/env python3
import json,os,pathlib,re,sys,tempfile
raw=sys.stdin.buffer.read(4*1024*1024+1)
if len(raw)>4*1024*1024:raise SystemExit("oversized mapping")
m=json.loads(raw)
if m.get('version')!=1 or not isinstance(m.get('credentials'),dict) or len(m['credentials'])>100000:raise SystemExit("invalid mapping")
for k,v in m['credentials'].items():
 if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',k) or not re.fullmatch(r'[0-9a-f]{64}',v):raise SystemExit("invalid binding")
p=pathlib.Path('/var/lib/guardex-account-qos');p.mkdir(mode=0o700,exist_ok=True)
f,name=tempfile.mkstemp(dir=p,prefix='.map-')
with os.fdopen(f,'wb')as out:out.write(raw);out.flush();os.fsync(out.fileno())
os.replace(name,p/'accounts.json')
print('mapping refreshed:',len(m['credentials']))
