#!/usr/bin/env python3
"""Forced-command SSH agent; accepts only bounded IPv6 setup/probe requests."""
import base64,ipaddress,json,re,sys
from fleet import REMOTE_SETUP,REMOTE_PROBE

def main():
    raw=sys.stdin.buffer.read(8193)
    if len(raw)>8192:raise ValueError('oversized request')
    request=json.loads(raw)
    action=request.get('action')
    if action=='setup':
        if set(request)!={'action','install'} or type(request['install']) is not bool:raise ValueError('invalid setup request')
        exec(REMOTE_SETUP,{'PROBE':'2a01:96e0:0:545:1::641','INSTALL':request['install']})
    elif action=='probe':
        if set(request)!={'action','address','hostname','pin'}:raise ValueError('invalid probe request')
        ip=ipaddress.ip_address(request['address'])
        if ip.version!=6 or not ip.is_global or ip.ipv4_mapped or '%' in request['address']:raise ValueError('invalid IPv6')
        if not re.fullmatch(r'[a-zA-Z0-9.-]{1,253}',request['hostname']):raise ValueError('invalid hostname')
        if len(base64.b64decode(request['pin'],validate=True))!=32:raise ValueError('invalid pin')
        exec(REMOTE_PROBE,{'ADDRESS':str(ip),'HOSTNAME':request['hostname'],'PIN':request['pin']})
    else:raise ValueError('unsupported action')

if __name__=='__main__':
    try:main()
    except SystemExit:raise
    except Exception:
        print(json.dumps({'state':'probe_failed','error_code':'ipv6_verifier_request_failed'}))
        raise SystemExit(1)
