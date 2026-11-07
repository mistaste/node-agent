"""Pure policy generators for the separately guarded NL+ID qualification.

No application, retention, service or network operations. The server owner
must qualify generated rendering, activate under its independent rollback
guard and retain only after actual normal-phone acceptance.
"""
CLIENTS = ('10.77.2.1', '10.77.0.13')
LOCAL = '10.77.0.18'
PRIMARY = '193.247.73.15'
SECONDARY = '82.208.22.95'
PUBLIC = '94.249.195.63'
PORT = 19445
TABLE = 'gx_sni_nlid_20261107a'
CHAIN = 'GX_SNINLID_1107A'
TAG = 'guardex-sni-nlid-20261107a'


def nat_config():
    return f'''table ip {TABLE} {{
 chain select {{
  type nat hook prerouting priority -175; policy accept;
  iifname "gxwg0" ip saddr {{ {', '.join(CLIENTS)} }} ip daddr {PRIMARY} tcp dport 443 tcp flags & (fin|syn|rst|ack) == syn counter dnat to {LOCAL}:{PORT}
 }}
}}
'''


def input_jump():
    return ['-d', LOCAL, '-p', 'tcp', '--dport', str(PORT), '-m', 'comment',
            '--comment', TAG, '-j', CHAIN]


def allowances():
    return [['-i', 'gxwg0', '-s', source, '-d', LOCAL, '-p', 'tcp',
             '--dport', str(PORT), '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED',
             '--ctorigdst', PRIMARY, '--ctorigdstport', '443', '-m', 'comment',
             '--comment', TAG, '-j', 'ACCEPT'] for source in CLIENTS]


def deny_other_listener_inputs():
    return ['-m', 'comment', '--comment', TAG, '-j', 'DROP']


def haproxy_config():
    return f'''global
    maxconn 1024
defaults
    mode tcp
    timeout connect 4s
    timeout client 75s
    timeout server 75s
frontend owned_sni
    bind {LOCAL}:{PORT}
    tcp-request inspect-delay 1s
    tcp-request content accept if {{ req.ssl_hello_type 1 }}
    use_backend qualified_api if {{ req.ssl_sni -i api.guardex-vpn.com api.guardex-vpn.ru }}
    default_backend original_origin
backend qualified_api
    source {PUBLIC}
    server qualified82 {SECONDARY}:443
backend original_origin
    source {PUBLIC}
    server primary193 {PRIMARY}:443
'''
