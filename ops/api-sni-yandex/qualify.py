"""Real Linux qualification in three isolated namespaces; no production rules."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid
import policy as p

BUNDLE = Path('/var/lib/guardex-sni-netns-qualification/haproxy-bundle-20261105b/image-root')
BINARY, LOADER = BUNDLE/'usr/sbin/haproxy', BUNDLE/'lib/ld-musl-x86_64.so.1'
HAPROXY_SHA = '6e9c23d293b6c2a14fc81ac27e647e41b75b9b91b8b0f2d7cb35a7dce255ed35'
LOADER_SHA = '99eab0629ed5e6bc258bea735a128d1de30c5a8b52f39eed4919452d03c6c4ee'

def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=10, **kw).stdout

SERVER = r'''
import hashlib,http.server,ssl,sys
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_POST(self):
  n=int(self.headers['Content-Length']);assert n==262144
  body=self.rfile.read(n);assert len(body)==n
  result=bytes((i*31+17)&255 for i in range(n))
  self.send_response(200)
  self.send_header('Content-Length',str(n))
  self.send_header('X-Ack-Nonce',self.headers['X-Test-Nonce'])
  self.send_header('X-Ack-SHA256',hashlib.sha256(body).hexdigest())
  address,port=self.connection.getsockname()[:2]
  self.send_header('X-Test-Destination',address+':'+str(port));self.end_headers();self.wfile.write(result)
server=http.server.ThreadingHTTPServer(('0.0.0.0',443),Handler)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(sys.argv[1],sys.argv[2])
server.socket=ctx.wrap_socket(server.socket,server_side=True);server.serve_forever()
'''

CLIENT = r'''
import hashlib,http.client,json,os,socket,ssl,sys,uuid
cert,dest,source,sni,expected=sys.argv[1:]
ctx=ssl.create_default_context(cafile=cert)
raw=socket.create_connection((dest,443),timeout=2,source_address=(source,0))
with ctx.wrap_socket(raw,server_hostname=sni) as sock:
 nonce=uuid.uuid4().hex;body=os.urandom(262144)
 header=('POST / HTTP/1.1\r\nHost: '+sni+'\r\nContent-Length: '+str(len(body))+'\r\nX-Test-Nonce: '+nonce+'\r\nConnection: close\r\n\r\n').encode()
 sock.sendall(header+body);response=http.client.HTTPResponse(sock);response.begin();data=response.read()
 assert response.status==200 and len(data)==262144
 assert response.getheader('X-Ack-Nonce')==nonce
 assert response.getheader('X-Ack-SHA256')==hashlib.sha256(body).hexdigest()
 assert hashlib.sha256(data).hexdigest()=='8f2144a274ead978258dbbcc0b62c5b0ee7335eb2bf729fbb5ca4026af0f0a14'
 assert response.getheader('X-Test-Destination')==expected+':443',response.getheader('X-Test-Destination')
print(json.dumps({'verified':True,'bytes':len(data)}))
'''

def main():
    os.umask(0o077); assert os.geteuid()==0
    assert hashlib.sha256(BINARY.read_bytes()).hexdigest()==HAPROXY_SHA
    assert hashlib.sha256(LOADER.read_bytes()).hexdigest()==LOADER_SHA
    prefix='gxy'+uuid.uuid4().hex[:6]
    client,router,origin=[prefix+s for s in ('c','r','o')]
    created=[];host_links=[];processes=[];results=[]
    root=Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix='guardex-yandex-qualification-') as temporary:
        temp=Path(temporary)
        def ns(name,*args,**kw):return run(['ip','netns','exec',name,*args],**kw)
        try:
            for name in (client,router,origin):
                run(['ip','netns','add',name]);created.append(name);ns(name,'ip','link','set','lo','up')
            for left,right,leftname,rightname in [(client,router,'client','gxwg0'),(router,origin,'origin','router')]:
                # Both ends move out of the host namespace immediately.
                a,b=prefix+'a',prefix+'b'
                run(['ip','link','add',a,'type','veth','peer','name',b])
                host_links.extend((a,b))
                run(['ip','link','set',a,'netns',left]);run(['ip','link','set',b,'netns',right])
                ns(left,'ip','link','set',a,'name',leftname);ns(right,'ip','link','set',b,'name',rightname)
                ns(left,'ip','link','set',leftname,'up');ns(right,'ip','link','set',rightname,'up')
            for addr in (*p.CLIENTS,'10.77.0.99'):ns(client,'ip','addr','add',addr+'/24','dev','client')
            ns(router,'ip','addr','add',p.LOCAL+'/24','dev','gxwg0')
            ns(router,'ip','addr','add',p.PUBLIC+'/32','dev','lo')
            ns(router,'ip','addr','add','192.0.2.1/30','dev','origin')
            ns(origin,'ip','addr','add','192.0.2.2/30','dev','router')
            targets=['37.230.168.172','37.230.168.173',p.SECONDARY]
            for target in targets:
                ns(origin,'ip','addr','add',target+'/32','dev','lo')
                ns(router,'ip','route','add',target+'/32','via','192.0.2.2','dev','origin')
            ns(client,'ip','route','add','default','via',p.LOCAL)
            ns(origin,'ip','route','add','default','via','192.0.2.1')
            ns(router,'sysctl','-q','-w','net.ipv4.ip_forward=1')
            cert,key=temp/'cert.pem',temp/'key.pem'
            run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=gateway.guardex-vpn.com',
                 '-addext','subjectAltName=DNS:gateway.guardex-vpn.com,DNS:other.example.test,DNS:gateway.guardex-vpn.com.evil.test',
                 '-keyout',str(key),'-out',str(cert)])
            server,clientfile=temp/'server.py',temp/'client.py'
            server.write_text(SERVER);clientfile.write_text(CLIENT)
            processes.append(subprocess.Popen(['ip','netns','exec',origin,'python3',str(server),str(cert),str(key)],
                                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            config=temp/'haproxy.cfg';config.write_text(p.haproxy_config())
            haproxy=[str(LOADER),'--library-path',str(BUNDLE/'usr/lib'),str(BINARY)]
            ns(router,*haproxy,'-c','-f',str(config))
            processes.append(subprocess.Popen(['ip','netns','exec',router,*haproxy,'-db','-f',str(config)],
                                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            ns(router,'iptables','-N',p.CHAIN)
            snapshots=[ns(router,'iptables','-S',p.CHAIN)]
            for rule in p.rules():
                ns(router,'iptables','-A',p.CHAIN,*rule);snapshots.append(ns(router,'iptables','-S',p.CHAIN))
            ns(router,'iptables','-I','INPUT','1',*p.jump())
            ns(router,'nft','-f','-',input=p.nat_config([targets[0]]))
            model=p.nft_identity(json.loads(ns(router,'nft','-j','-s','list','table','ip',p.TABLE)),[targets[0]])
            time.sleep(.3)
            assert all(proc.poll() is None for proc in processes)
            def check(source,sni,dest,expected):
                row=json.loads(ns(client,'python3',str(clientfile),str(cert),dest,source,sni,expected))
                assert row['verified'] is True
                results.append({'source':source,'qualified':expected==p.SECONDARY,'bytes':row['bytes']})
            for source in p.CLIENTS:
                check(source,p.HOST,targets[0],p.SECONDARY)
                check(source,'other.example.test',targets[0],targets[0])
            check(p.CLIENTS[0],p.HOST+'.evil.test',targets[0],targets[0])
            check('10.77.0.99',p.HOST,targets[0],targets[0])
            check(p.CLIENTS[0],p.HOST,targets[1],targets[1])
            # The live DNS set can change without changing any other rule.
            ns(router,'nft','-f','-',input=f'flush set ip {p.TABLE} gateway_ips\nadd element ip {p.TABLE} gateway_ips {{ {targets[0]}, {targets[1]} }}\n')
            assert p.nft_identity(json.loads(ns(router,'nft','-j','-s','list','table','ip',p.TABLE)),targets[:2])==model
            check(p.CLIENTS[0],p.HOST,targets[1],p.SECONDARY)
            check(p.CLIENTS[0],'other.example.test',targets[1],targets[1])
            # An ingress cannot directly access the new private listener.
            denied=ns(client,'python3','-c',f'import socket; s=socket.socket();s.settimeout(.3);print(s.connect_ex(("{p.LOCAL}",{p.PORT})))')
            assert denied.strip()!='0'
            # Withdrawal only removes this selector; the original path works.
            ns(router,'nft','delete','table','ip',p.TABLE)
            check(p.CLIENTS[0],p.HOST,targets[0],targets[0])
            report={'isolated_only':True,'strict_tls':True,'verified_bytes_min':262144,
                    'qualified_and_original_verified':results,'private_listener_denied':True,
                    'dynamic_original_destination_verified':True,'withdrawal_verified':True,
                    'nft_structure_sha256':model,'chain_snapshots':snapshots,
                    'policy_sha256':hashlib.sha256((root/'policy.py').read_bytes()).hexdigest(),
                    'haproxy_sha256':HAPROXY_SHA,'loader_sha256':LOADER_SHA}
        finally:
            for process in processes:
                if process.poll() is None:process.terminate()
            for process in processes:
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)
            for name in reversed(created):
                subprocess.run(['ip','netns','delete',name],capture_output=True,timeout=5)
            for name in host_links:
                subprocess.run(['ip','link','delete',name],capture_output=True,timeout=5)
            remaining=run(['ip','netns','list'])
            assert all(name not in remaining for name in created), 'owned_namespace_cleanup_failed'
        report['namespace_cleanup_verified']=True
        (root/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:v for k,v in report.items() if k not in ('chain_snapshots','qualified_and_original_verified')}))

if __name__=='__main__':main()
