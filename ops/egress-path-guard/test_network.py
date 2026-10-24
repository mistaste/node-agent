"""Real WG namespace, independent QA key, IPv4 fault, existing TCP recovery."""
import base64
import json
import pathlib
import subprocess
import uuid

import os
import textwrap

def main():
    if os.environ.get("GUARDEX_EGRESS_NETWORK_TEST") != "1":
        raise SystemExit("Set GUARDEX_EGRESS_NETWORK_TEST=1 to run the owned-server namespace regression")
    ROOT = pathlib.Path(__file__).resolve().parent
    WATCHDOG = ROOT / "watchdog.py"
    TAG = "gxqa"+uuid.uuid4().hex[:8]
    secrets = []

    def ssh(host, command, *, input=None):
        result = subprocess.run(["rtk", "proxy", "ssh", "root@"+host, command], input=input,
                                text=True, capture_output=True, timeout=180)
        if result.returncode:
            message = result.stderr
            for secret in secrets:
                message = message.replace(secret, "[private key redacted]")
            raise RuntimeError(message[-4000:])
        return result.stdout

    private = ssh("72.62.126.100", "wg genkey").strip()
    secrets.append(private)
    public = ssh("72.62.126.100", "wg pubkey", input=private+"\n").strip()
    exit_key = ssh("94.249.195.63", "wg show gxwg0 public-key").strip()
    setup = r'''
    import json,subprocess
    def run(*args):return subprocess.check_output(args,text=True,timeout=8)
    assert not json.loads(run("ip","-j","route","show","exact","10.77.255.253/32"))
    assert "10.77.255.253/32" not in run("wg","show","gxwg0","allowed-ips")
    run("wg","set","gxwg0","peer",PUBLIC,"allowed-ips","10.77.255.253/32")
    try:
     run("ip","route","add","10.77.255.253/32","dev","gxwg0")
     run("nft","insert","rule","ip6","filter","ufw6-user-input","ip6","saddr","2a02:4780:59:7949::1","udp","dport","443","accept","comment",'"'+TAG+'"')
     rules=json.loads(run("nft","-j","list","chain","ip6","filter","ufw6-user-input"))["nftables"]
     handle=next(x["rule"]["handle"] for x in rules if x.get("rule",{}).get("comment")==TAG)
     print(json.dumps({"handle":handle}))
    except BaseException:
     subprocess.run(["ip","route","del","10.77.255.253/32","dev","gxwg0"])
     subprocess.run(["wg","set","gxwg0","peer",PUBLIC,"remove"])
     raise
    '''
    lab = r'''
    import base64,hashlib,json,os,pathlib,signal,subprocess,tempfile,time
    def run(*args,**kwargs):return subprocess.check_output(args,text=True,timeout=12,**kwargs)
    def ns(*args,**kwargs):return run("ip","netns","exec",TAG,*args,**kwargs)
    def stop(signum,frame):raise SystemExit(1)
    signal.signal(signal.SIGTERM,stop)
    assert subprocess.run(["ip","link","show",TAG],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode
    namespace=False;interface=False;watch=None;curl=None;drop=False;underlay_handle=None
    report={}
    with tempfile.TemporaryDirectory(prefix="guardex-egress-qa-") as directory:
     root=pathlib.Path(directory)
     try:
      run("ip","netns","add",TAG);namespace=True
      run("ip","link","add",TAG,"type","wireguard");interface=True
      run("ip","link","set",TAG,"netns",TAG);interface=False
      ns("ip","link","set",TAG,"name","gxwg0")
      ns("wg","set","gxwg0","private-key","/dev/stdin","listen-port","51824","peer",EXIT_KEY,
         "allowed-ips","0.0.0.0/0","endpoint","94.249.195.63:443","persistent-keepalive","5",input=PRIVATE+"\n")
      ns("ip","addr","add","10.77.255.253/32","dev","gxwg0")
      ns("ip","link","set","gxwg0","mtu","1280","up")
      ns("ip","link","set","lo","up")
      ns("ip","route","add","default","dev","gxwg0")
      config={"interface":"gxwg0","peer_public_key":EXIT_KEY,"probe_ip":"10.77.0.14",
              "endpoints":["94.249.195.63:443","[2a14:7c0:1002:19c4::]:443"]}
      (root/"config.json").write_text(json.dumps(config))
      (root/"watchdog.py").write_bytes(base64.b64decode(WATCHDOG_B64))
      os.chown(root,65532,65532)
      def healthy():
       for _ in range(8):
        r=subprocess.run(["ip","netns","exec",TAG,"ping","-n","-c","1","-W","2","-s","1200","10.77.0.14"],capture_output=True,text=True,timeout=4)
        if r.returncode==0:return True
        time.sleep(.5)
       return False
      assert healthy(),"QA IPv4 WG path failed before fault"
      report["ipv4_healthy_before"]=True
      ns("wg","set","gxwg0","peer",EXIT_KEY,"endpoint",config["endpoints"][1])
      assert healthy(),"QA IPv6 WG path failed before fault"
      report["ipv6_healthy_before"]=True
      check=["ip","netns","exec",TAG,"setpriv","--reuid=65532","--regid=65532","--clear-groups",
             "curl","--disable","--silent","--show-error","--fail","--noproxy","*","--max-time","5",
             "--connect-to","guardex-vpn.com:443:82.208.22.95:443","--output",str(root/"uid-control.body"),
             "https://guardex-vpn.com/v1/network/probe?bytes=2097152"]
      negative=subprocess.run(check,capture_output=True,text=True,timeout=8)
      report["transport_uid"]=65532
      report["namespace_owner_policy_negative_control_rejected"]=negative.returncode!=0
      if negative.returncode!=0:
       run("nft","insert","rule","inet","guardex_transport","output","meta","skuid","65532",
           "ip6","daddr","2a14:7c0:1002:19c4::","udp","sport","51824","udp","dport","443",
           "counter","accept","comment",'"'+TAG+'"')
       rules=json.loads(run("nft","-j","list","chain","inet","guardex_transport","output"))["nftables"]
       underlay_handle=next(r["rule"]["handle"] for r in rules if r.get("rule",{}).get("comment")==TAG)
      else:
       # Moving the device between netns can scrub socket ownership metadata.
       # Do not present this topology test as proof of production owner policy.
       report["owner_policy_requires_separate_production_acceptance"]=True
      positive=subprocess.run(check,capture_output=True,text=True,timeout=8)
      assert positive.returncode==0,"transport UID remained blocked after the scoped underlay permission"
      assert hashlib.sha256((root/"uid-control.body").read_bytes()).hexdigest()=="70a5aa60279a696319d492e948cc9ba794da0e9174b81ad1d702554502f4801f"
      report["transport_uid_https_verified"]=True
      # Drop the QA peer's old receive session before returning from the IPv6
      # preflight. Otherwise an in-flight authenticated IPv6 packet can roam the
      # endpoint back before the fault, producing a false-positive recovery.
      ns("wg","set","gxwg0","peer",EXIT_KEY,"remove")
      ns("wg","set","gxwg0","peer",EXIT_KEY,"allowed-ips","0.0.0.0/0",
         "endpoint",config["endpoints"][0],"persistent-keepalive","5")
      assert healthy()
      assert ns("wg","show","gxwg0","endpoints").split()[1]==config["endpoints"][0]
      log=(root/"guard.log").open("w")
      watch=subprocess.Popen(["ip","netns","exec",TAG,"python3",str(root/"watchdog.py"),"--config",str(root/"config.json")],stdout=log,stderr=subprocess.STDOUT)
      metrics=(root/"metrics").open("w");errors=(root/"errors").open("w")
      command=["ip","netns","exec",TAG,"setpriv","--reuid=65532","--regid=65532","--clear-groups","stdbuf","-oL","curl","--disable","--silent","--show-error","--fail","--fail-early",
               "--noproxy","*","--max-time","60","--limit-rate","2M",
               "--connect-to","guardex-vpn.com:443:82.208.22.95:443","--write-out","%{json}\n"]
      for i in range(32):command += ["--output",str(root/(str(i)+".body")),"https://guardex-vpn.com/v1/network/probe?bytes=2097152"]
      curl=subprocess.Popen(command,stdout=metrics,stderr=errors)
      deadline=time.time()+15
      while not (root/"0.body").exists() or (root/"0.body").stat().st_size<500000:
       assert curl.poll() is None,"HTTPS failed before fault"
       assert time.time()<deadline,"HTTPS did not start"
       time.sleep(.1)
      rules=chr(10).join(['table inet '+TAG+' {',' chain output {','  type filter hook output priority -10; policy accept;','  ip daddr 94.249.195.63 udp sport 51824 udp dport 443 drop',' }','}',''])
      assert ns("wg","show","gxwg0","endpoints").split()[1]==config["endpoints"][0]
      run("nft","-f","-",input=rules.replace(chr(92)+"n",chr(10)));drop=True
      report["fault_injected_at"]=time.time()
      assert curl.wait(timeout=100)==0,"HTTPS failed across failover"
      metrics.close();errors.close()
      records=[json.loads(line) for line in (root/"metrics").read_text().splitlines()]
      assert len(records)==32 and all(r["http_code"]==200 and r["size_download"]==2097152 for r in records)
      assert sum(r["num_connects"] for r in records)==1,"TCP connection was replaced rather than recovered"
      assert all(hashlib.sha256((root/(str(i)+".body")).read_bytes()).hexdigest()=="70a5aa60279a696319d492e948cc9ba794da0e9174b81ad1d702554502f4801f" for i in range(32))
      endpoint=ns("wg","show","gxwg0","endpoints").split()[1]
      assert endpoint==config["endpoints"][1],endpoint
      watch.terminate();watch.wait(timeout=10);watch=None;log.close()
      guard_events=[json.loads(line) for line in (root/"guard.log").read_text().splitlines()]
      assert any(e.get("event")=="egress_endpoint_switched" and e["from"]==config["endpoints"][0]
                 and e["to"]==config["endpoints"][1] and e["time"]>=report["fault_injected_at"] for e in guard_events), "no actual guard recovery after the fault"
      report.update(verified_files=32,verified_bytes=32*2097152,tcp_connections=1,final_endpoint=endpoint,
                    guard_events=guard_events,
                    healthy_after=healthy())
      print(json.dumps(report),flush=True)
     finally:
      for process in (curl,watch):
       if process is not None and process.poll() is None:
        process.terminate();process.wait(timeout=10)
      if drop:subprocess.run(["nft","delete","table","inet",TAG],check=True)
      if underlay_handle is not None:subprocess.run(["nft","delete","rule","inet","guardex_transport","output","handle",str(underlay_handle)],check=True)
      if namespace:subprocess.run(["ip","netns","del",TAG],check=True)
      if interface:subprocess.run(["ip","link","del",TAG],check=True)
    '''
    state = None
    try:
        prefix="PUBLIC="+repr(public)+"\nTAG="+repr(TAG)+"\n"
        state=json.loads(ssh("94.249.195.63","python3 -",input=prefix+textwrap.dedent(setup)))
        prefix="PRIVATE="+repr(private)+"\nEXIT_KEY="+repr(exit_key)+"\nTAG="+repr(TAG)+"\nWATCHDOG_B64="+repr(base64.b64encode(WATCHDOG.read_bytes()).decode())+"\n"
        result=ssh("72.62.126.100","timeout 150 python3 -",input=prefix+textwrap.dedent(lab))
        report=json.loads(result)
        (ROOT/"dualstack-lab-results.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report))
    finally:
        if state is not None:
            cleanup="import subprocess\n"+"subprocess.run(['wg','set','gxwg0','peer',"+repr(public)+",'remove'],check=True)\nsubprocess.run(['ip','route','del','10.77.255.253/32','dev','gxwg0'],check=True)\nsubprocess.run(['nft','delete','rule','ip6','filter','ufw6-user-input','handle',"+repr(str(state["handle"]))+"],check=True)\n"
            ssh("94.249.195.63","python3 -",input=cleanup)

if __name__ == "__main__":
    main()
