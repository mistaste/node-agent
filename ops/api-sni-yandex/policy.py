"""Exact owned API SNI repair; all TLS bytes remain end-to-end encrypted."""
import hashlib
import ipaddress
import json

HOST = 'gateway.guardex-vpn.com'
CLIENTS = ('10.77.0.5', '10.77.0.9', '10.77.0.13', '10.77.0.17', '10.77.0.25')
LOCAL, PUBLIC, SECONDARY = '10.77.0.18', '94.249.195.63', '82.208.22.95'
PORT = 19446
TABLE, CHAIN, TAG = 'gx_yandex_api_20261127', 'GX_YANDEX_API_1127', 'guardex-yandex-api-20261127'
EDGE_LINE = '        gateway.guardex-vpn.com 127.0.0.1:19446; # guardex-yandex-api-20261127\n'
EDGE_BLOCK = '''    # BEGIN guardex-yandex-api-20261127
    server {
        listen 127.0.0.1:19446 proxy_protocol;
        resolver 1.1.1.1 8.8.8.8 valid=60s ipv6=off;
        resolver_timeout 2s;
        set $guardex_yandex_destination gateway.guardex-vpn.com:443;
        proxy_pass $guardex_yandex_destination;
        proxy_protocol off;
        proxy_next_upstream off;
        proxy_connect_timeout 2s;
        proxy_timeout 75s;
    }
    # END guardex-yandex-api-20261127
'''

def addresses(values):
    result = sorted(set(values), key=ipaddress.ip_address)
    assert 1 <= len(result) <= 16
    assert all(ipaddress.IPv4Address(v).is_global and v not in (PUBLIC, SECONDARY, '193.247.73.15') for v in result)
    return result

def nat_config(values):
    ips = ', '.join(addresses(values))
    return f'''table ip {TABLE} {{
 set gateway_ips {{ type ipv4_addr; elements = {{ {ips} }}; }}
 chain select {{
  type nat hook prerouting priority -175; policy accept;
  iifname "gxwg0" ip saddr {{ {', '.join(CLIENTS)} }} ip daddr @gateway_ips tcp dport 443 tcp flags & (fin|syn|rst|ack) == syn counter dnat to {LOCAL}:{PORT}
 }}
}}
'''

def jump():
    return ['-d', LOCAL, '-p', 'tcp', '--dport', str(PORT), '-m', 'comment', '--comment', TAG, '-j', CHAIN]

def rules():
    # The original port must be443: direct access to the private listener fails.
    return [['-i', 'gxwg0', '-s', peer, '-d', LOCAL, '-p', 'tcp', '--dport', str(PORT),
             '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED', '--ctorigdstport', '443',
             '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'] for peer in CLIENTS] + [
             ['-m', 'comment', '--comment', TAG, '-j', 'DROP']]

def haproxy_config():
    return f'''global
    maxconn 1024
defaults
    mode tcp
    retries 0
    timeout connect 2s
    timeout client 75s
    timeout server 75s
frontend owned_gateway_sni
    bind {LOCAL}:{PORT}
    tcp-request inspect-delay 2s
    tcp-request content accept if {{ req.ssl_hello_type 1 }}
    use_backend qualified_gateway if {{ req.ssl_sni -i {HOST} }}
    default_backend original_destination
backend qualified_gateway
    source {PUBLIC}
    server qualified82 {SECONDARY}:443
backend original_destination
    source {PUBLIC}
    server original 0.0.0.0:0
'''

def render_edge(before):
    assert HOST not in before and TAG not in before, 'foreign_gateway_configuration'
    anchor = '        default 127.0.0.1:8443;\n'
    assert before.count(anchor) == 1 and before.rstrip().endswith('}')
    current = before.replace(anchor, EDGE_LINE + anchor)
    offset = current.rfind('}')
    return current[:offset] + EDGE_BLOCK + current[offset:]

def restore_edge(current):
    assert current.count(EDGE_LINE) == 1 and current.count(EDGE_BLOCK) == 1, 'changed_owned_edge'
    return current.replace(EDGE_LINE, '').replace(EDGE_BLOCK, '')

def nft_identity(value, expected_ips):
    """Verify set contents, hash every rule/chain/set property except handles."""
    result = []
    found = False
    def strip(item):
        if isinstance(item, dict):
            return {k: (None if k == 'counter' else strip(v)) for k, v in item.items() if k != 'handle'}
        if isinstance(item, list): return [strip(v) for v in item]
        return item
    for row in value['nftables']:
        if 'metainfo' in row: continue
        row = strip(row)
        if 'set' in row:
            item = row['set']
            assert not found and item['name'] == 'gateway_ips' and item['table'] == TABLE
            assert sorted(item.get('elem', [])) == sorted(expected_ips), 'changed_owned_addresses'
            item['elem'] = ['$RESOLVED_GATEWAY_IPS']
            found = True
        result.append(row)
    assert found
    return hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
