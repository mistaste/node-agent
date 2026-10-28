#!/usr/bin/env python3
import hashlib,hmac,json,pathlib,subprocess
p=pathlib.Path('/var/lib/guardex-account-qos-export');salt=(p/'salt').read_bytes()
q="SELECT client_uuid::text,user_id::text FROM vpn_profiles WHERE revoked_at IS NULL ORDER BY client_uuid"
raw=subprocess.check_output(['docker','exec','guardex-postgres-1','psql','-X','-U','postgres','-d','guardex','-At','-F','|','-c',q],text=True)
m={}
for row in raw.splitlines():
 credential,account=row.split('|');key=hmac.new(salt,account.encode(),hashlib.sha256).hexdigest()
 if credential in m and m[credential]!=key:raise SystemExit('conflicting account binding')
 m[credential]=key
payload=json.dumps({'version':1,'credentials':m},separators=(',',':')).encode()
subprocess.run(['ssh','-T','-o','UserKnownHostsFile='+str(p/'known_hosts'),'-i',str(p/'mapping-key'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','StrictHostKeyChecking=yes','root@212.127.91.131'],input=payload,check=True,timeout=12)
