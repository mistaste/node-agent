"""Validate fresh all-host closure evidence, without rollback/open/flag authority."""
import hashlib
import hmac
import json
import math
import re
import time

import barrier
import guard

HOSTS = frozenset(('207.241.172.230', '82.117.84.37', '72.62.126.100',
                   '5.255.124.73', '212.127.91.131', '142.248.80.169'))
HEX = re.compile(r'^[a-f0-9]{64}$')
MAX_AGE = 30
MAX_FUTURE_SKEW = 2


class Rejected(ValueError):
    pass


class ClosureGate:
    def __init__(self, config, persist):
        if set(config['hosts']) != HOSTS or not callable(persist):
            raise Rejected('exact six inventoried hosts and durable receipt writer required')
        if not HEX.fullmatch(config['guard_source_sha256']):
            raise Rejected('sealed guard source required')
        if type(config['created_epoch']) is not int or type(config['deadline_epoch']) is not int:
            raise Rejected('fixed operation epochs required')
        if not 60 <= config['deadline_epoch'] - config['created_epoch'] <= 3600:
            raise Rejected('bounded fixed operation window required')
        identifiers, secrets = set(), set()
        for host, record in config['hosts'].items():
            manifest = record['manifest']
            guard.validate_manifest(manifest)
            if (manifest['scope'] != config['scope'] or manifest['image'] != config['image']
                    or manifest['deadline_epoch'] != config['deadline_epoch']):
                raise Rejected('host manifest disagrees with sealed operation')
            secret = record['bearer_sha256']
            if not HEX.fullmatch(secret) or secret in secrets:
                raise Rejected('unique per-host bearer digests required')
            secrets.add(secret)
            for cid in manifest['containers'].values():
                if cid in identifiers:
                    raise Rejected('container identity copied between hosts')
                identifiers.add(cid)
        self.config = config
        self.persist = persist
        self.reports = {}

    def _authorized(self, source_ip, token):
        if source_ip not in HOSTS or not isinstance(token, str) or not 32 <= len(token) <= 128:
            raise Rejected('unauthorized host')
        digest = hashlib.sha256(token.encode('utf-8')).hexdigest()
        if not hmac.compare_digest(digest, self.config['hosts'][source_ip]['bearer_sha256']):
            raise Rejected('unauthorized host')

    def submit(self, source_ip, token, report, now=None):
        self._authorized(source_ip, token)
        now = time.time() if now is None else now
        if not isinstance(report, dict):
            raise Rejected('receipt object required')
        if report.get('scope') != self.config['scope'] or report.get('host') != source_ip:
            raise Rejected('receipt scope/source mismatch')
        if report.get('guard_source_sha256') != self.config['guard_source_sha256']:
            raise Rejected('unqualified guard source')
        sequence, observed = report.get('sequence'), report.get('observed_epoch')
        if (type(sequence) is not int or sequence < 1 or type(observed) not in (int, float)
                or not math.isfinite(observed)):
            raise Rejected('monotonic sequence and actual observation epoch required')
        serialized = json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False)
        digest = hashlib.sha256(serialized.encode()).hexdigest()
        previous = self.reports.get(source_ip)
        if previous and sequence <= previous['sequence']:
            if sequence == previous['sequence'] and digest == previous['sha256']:
                # A retried request never refreshes the original observation.
                return {'duplicate': True, 'status': self.status(now)}
            raise Rejected('out-of-order or changed receipt replay')
        if not -MAX_FUTURE_SKEW <= now - observed <= MAX_AGE:
            raise Rejected('stale or future observation')
        if observed < self.config['created_epoch']:
            raise Rejected('receipt predates this operation')
        manifest = self.config['hosts'][source_ip]['manifest']
        problems = []
        try:
            verified = barrier.inspect(manifest['scope'], manifest['ingress_ports'], report.get('nft_document') or {})
        except (KeyError, TypeError, ValueError, AttributeError):
            verified = False
        if not verified:
            problems.append('actual_inventoried_barrier_unconfirmed')
        actual = report.get('containers')
        stopped = isinstance(actual, list) and len(actual) == 4
        seen = set()
        for item in actual if isinstance(actual, list) else []:
            if not isinstance(item, dict):
                stopped = False
                continue
            labels = item.get('Config', {}).get('Labels') or {}
            service = labels.get('com.docker.compose.service')
            if service not in guard.SERVICES or service in seen:
                stopped = False
                continue
            seen.add(service)
            state = item.get('State') or {}
            if (not guard.matching(item, manifest, service) or state.get('Running') is not False
                    or type(state.get('Pid')) is not int or state['Pid'] != 0):
                stopped = False
        if seen != guard.SERVICES or not stopped:
            problems.append('actual_pinned_runtime_closure_unconfirmed')
        expiry = report.get('expiry') or {}
        native = report.get('native_final_file')
        counters = False
        if isinstance(native, str) and len(native.encode()) <= 8 << 20:
            try:
                decoded = json.loads(native)
                closed_at, ended = expiry.get('barrier_closed_epoch'), expiry.get('ended_epoch')
                stopped_ids = {(x.get('service'), x.get('id'), x.get('PID')) for x in expiry.get('stopped', [])}
                wanted_ids = {(name, cid, 0) for name, cid in manifest['containers'].items()}
                counters = (expiry.get('scope') == self.config['scope']
                            and expiry.get('deadline_epoch') == self.config['deadline_epoch']
                            and expiry.get('global_flags_changed') is False
                            and expiry.get('legacy_ingress_restored') is False
                            and type(closed_at) in (int, float) and type(ended) in (int, float)
                            and self.config['created_epoch'] <= closed_at <= ended <= observed + MAX_FUTURE_SKEW
                            and ended - closed_at >= 30 and stopped_ids == wanted_ids
                            and verified and stopped
                            and set(decoded) == {'trusttunnel', 'naive'}
                            and all(isinstance(v, list) for v in decoded.values())
                            and hashlib.sha256(native.encode()).hexdigest() == expiry.get('native_final_SHA256')
                            and expiry.get('native_stable_30s') is True and not expiry.get('errors'))
            except (ValueError, TypeError, AttributeError):
                pass
        if not counters:
            problems.append('retained_native_snapshot_unqualified')
        receipt = dict(host=source_ip, sequence=sequence, observed_epoch=observed,
                       sha256=digest, inventoried_ingress_closed=verified and stopped,
                       native_snapshot_retained=counters, problems=problems)
        # A disk failure must prevent publishing a new consensus state.
        try:
            self.persist(receipt, report)
        except Exception:
            # An old positive must not survive a failed attempt to durably
            # record newer evidence, especially a newly running engine.
            self.reports.pop(source_ip, None)
            raise
        self.reports[source_ip] = receipt
        return {'duplicate': False, 'receipt': receipt, 'status': self.status(now)}

    def status(self, now=None):
        now = time.time() if now is None else now
        hosts = {}
        for host in sorted(HOSTS):
            report = self.reports.get(host)
            fresh = bool(report and -MAX_FUTURE_SKEW <= now - report['observed_epoch'] <= MAX_AGE)
            hosts[host] = dict(fresh=fresh,
                               inventoried_ingress_closed=bool(fresh and report['inventoried_ingress_closed']),
                               native_snapshot_retained=bool(fresh and report['native_snapshot_retained']))
        return dict(scope=self.config['scope'], hosts=hosts,
                    all_inventoried_hosts_closed=all(x['inventoried_ingress_closed'] for x in hosts.values()),
                    all_native_snapshot_files_retained=all(x['native_snapshot_retained'] for x in hosts.values()),
                    deadline_expired=now >= self.config['deadline_epoch'],
                    rollback_authorized=False, ingress_open_authorized=False,
                    required_next='Independent route completeness and final normal-pusher DB joins; checked accounting boundary and qualified legacy restore')
