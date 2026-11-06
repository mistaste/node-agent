"""Validate final source-separated native counters against a later DB snapshot.

Pure validation only. Database collection, native quiescence, profile attribution,
credit settlement and any accounting-boundary mutation remain separate checks.
"""
import hashlib
import re
import uuid

MAX_INT64 = (1 << 63) - 1


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('canonical UUID required')
    return value


def counter(value):
    if type(value) is not int or not 0 <= value <= MAX_INT64:
        raise ValueError('nonnegative int64 native counter required')
    return value


def native_rows(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {'trusttunnel', 'naive'}:
        raise ValueError('both real native source snapshots required')
    result = {}
    for source, clients in snapshot.items():
        if not isinstance(clients, list):
            raise ValueError('native source must contain the actual client array')
        for client in clients:
            if not isinstance(client, dict):
                raise ValueError('native client object required')
            username = client.get('username')
            if not isinstance(username, str):
                raise ValueError('native client UUID required')
            username = canonical_uuid(username.strip().lower())
            uplink, downlink = counter(client.get('inbound')), counter(client.get('outbound'))
            counter(client.get('sessions'))
            key = ('naive:' if source == 'naive' else '') + username
            digest = hashlib.sha256(key.encode()).hexdigest()
            if digest in result:
                # Match the normal collector's TrustTunnel aggregation. Naive
                # samples are separate, so duplicate keys are ambiguous there.
                if source != 'trusttunnel':
                    raise ValueError('duplicate Naive source identity')
                uplink = counter(result[digest]['uplink'] + uplink)
                downlink = counter(result[digest]['downlink'] + downlink)
            result[digest] = dict(source=source, uplink=uplink, downlink=downlink)
    return result


def verify(snapshot, server_id, database_rows):
    """Require exact raw counter equality, never >= across a possible reset.

    A matching row proves only the durable source counter. Attribution, daily
    free/Premium accounting and ledger/settlement joins are not inferred from it.
    """
    canonical_uuid(server_id)
    expected = native_rows(snapshot)
    if not isinstance(database_rows, list):
        raise ValueError('actual database counter rows required')
    indexed = {}
    for row in database_rows:
        if not isinstance(row, dict):
            raise ValueError('database row object required')
        canonical_uuid(row.get('server_id'))
        if row['server_id'] != server_id:
            continue
        digest = row.get('client_key_sha256')
        if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest) or digest in indexed:
            raise ValueError('unique exact database source identity required')
        indexed[digest] = (counter(row.get('last_uplink')), counter(row.get('last_downlink')))
    missing, different = [], []
    positive = 0
    for digest, sample in expected.items():
        value = (sample['uplink'], sample['downlink'])
        if value == (0, 0):
            # A fresh zero counter can legitimately reset an older nonzero row;
            # require the normal pusher to persist that reset before handover.
            if digest not in indexed:
                continue
        else:
            positive += 1
        if digest not in indexed:
            missing.append(digest)
        elif indexed[digest] != value:
            different.append(digest)
    return dict(source_rows=len(expected), positive_rows=positive,
                missing_source_keys=sorted(missing), different_source_keys=sorted(different),
                all_source_counters_reconciled=not missing and not different,
                rollback_authorized=False, ingress_open_authorized=False,
                attribution_and_ledger_reconciled=False)
