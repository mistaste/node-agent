"""Stopped staging rejects running/foreign candidates and changed retained policy."""
import copy
from pathlib import Path
import tempfile
import unittest

import compose_plan
import stage
from test_compose_plan import fixture, SCOPE, BASE, IMAGE


def inputs():
    effective, actual = fixture()
    value = dict(schema=1, scope=SCOPE, image=IMAGE, source_revision='a'*40,
                 ingress_ports=[443, 18443, 19080, 19443])
    plan = compose_plan.render(SCOPE, IMAGE, value['source_revision'], BASE+'/source', BASE+'/quota', effective, actual)
    return value, plan


def candidate(plan, name):
    item = plan['services'][name]
    return dict(Id='b'*64, Image=IMAGE, RestartCount=0,
        State=dict(Running=False, Pid=0),
        Config=dict(Cmd=item['command'], Entrypoint=item.get('entrypoint'),
                    User=item.get('user', ''), WorkingDir=item.get('working_dir', ''),
                    Env=[key+'='+value.replace('$$', '$') for key, value in item['environment'].items() if value is not None],
                    Labels={'guardex.quota.rollout.scope':SCOPE,'com.docker.compose.project':plan['name'],
                            'com.docker.compose.service':name}),
        HostConfig=dict(RestartPolicy={'Name':'no'},NetworkMode='host',ReadonlyRootfs=item.get('read_only',False),
                        Privileged=False,CapAdd=item.get('cap_add'),CapDrop=item.get('cap_drop'),
                        SecurityOpt=item.get('security_opt'),Memory=item.get('mem_limit',0),
                        PidsLimit=item.get('pids_limit'),NanoCpus=round(float(item.get('cpus',0))*1_000_000_000)),
        Mounts=[dict(Type='bind',Source=v['source'],Destination=v['target'],RW=not v.get('read_only',False))
                for v in item.get('volumes',[]) if v['type']=='bind'])


class StageTests(unittest.TestCase):
    def test_four_stopped_candidates_preserve_plan_environment_mounts_and_identity(self):
        value, plan = inputs(); stage.validate_plan(plan, value)
        for name in plan['services']:
            stage.verify_candidate(candidate(plan,name), name, plan, value, {})

    def test_running_foreign_or_changed_candidate_cannot_be_declared_staged(self):
        value, plan = inputs(); name = 'node-agent'
        for change in ('running','pid','image','scope','project','command','mount','env','caps','user','readonly','security','cpus','entrypoint'):
            item = candidate(plan,name)
            if change == 'running': item['State']['Running'] = True
            elif change == 'pid': item['State']['Pid'] = 45
            elif change == 'image': item['Image'] = 'sha256:'+'f'*64
            elif change == 'scope': item['Config']['Labels']['guardex.quota.rollout.scope'] = 'foreign'
            elif change == 'project': item['Config']['Labels']['com.docker.compose.project'] = 'foreign'
            elif change == 'command': item['Config']['Cmd'] = ['sh']
            elif change == 'mount': item['Mounts'][0]['Source'] = '/foreign'
            elif change == 'env': item['Config']['Env'] = ['AGENT_VERSION=wrong']
            elif change == 'caps': item['HostConfig']['CapAdd'] = ['SYS_ADMIN']
            elif change == 'user': item['Config']['User'] = '65532'
            elif change == 'readonly': item['HostConfig']['ReadonlyRootfs'] = False
            elif change == 'security': item['HostConfig']['SecurityOpt'] = []
            elif change == 'cpus': item['HostConfig']['NanoCpus'] = 1
            else: item['Config']['Entrypoint'] = ['foreign']
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage.verify_candidate(item,name,plan,value,{})

    def test_plan_rejects_dependency_build_restart_source_or_quota_escape(self):
        value, original = inputs()
        for change in ('dependency','build','restart','source','quota','mode','image'):
            plan = copy.deepcopy(original); item = plan['services']['node-agent']
            if change == 'dependency': item['depends_on'] = {'foreign':{}}
            elif change == 'build': item['build'] = '.'
            elif change == 'restart': item['restart'] = 'always'
            elif change == 'source': next(v for v in item['volumes'] if v['target']=='/opt/guardex-node')['source'] = '/foreign'
            elif change == 'quota': plan['services']['quota-broker']['volumes'][0]['source'] = '/foreign'
            elif change == 'mode': item['environment']['GUARDEX_HARD_QUOTA_REQUIRED'] = 'false'
            else: item['image'] = 'latest'
            with self.subTest(change=change), self.assertRaises(ValueError): stage.validate_plan(plan,value)

    def test_identity_ignores_routine_health_logs_but_detects_pid_restart_or_epoch(self):
        _, plan = inputs(); item = candidate(plan,'node-agent'); original = stage.runtime_identity(item)
        item['State']['Health'] = {'Status':'healthy','Log':[{'End':'later'}]}
        self.assertEqual(original,stage.runtime_identity(item))
        for key in ('Pid','StartedAt'):
            changed = copy.deepcopy(item); changed['State'][key] = 99
            self.assertNotEqual(original,stage.runtime_identity(changed))
        item['RestartCount'] = 1
        self.assertNotEqual(original,stage.runtime_identity(item))

    def test_private_stage_record_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/'record.json'
            stage.write_new(path,{'scope':'first'})
            with self.assertRaises(FileExistsError): stage.write_new(path,{'scope':'changed'})
            self.assertIn('first',path.read_text())

    def test_legacy_mount_order_does_not_mask_real_config_or_ownership_changes(self):
        value, plan = inputs(); old = candidate(plan,'node-agent')
        old['State'].update(Running=True,Pid=123)
        old['Config']['Labels']['com.docker.compose.project'] = 'guardex-node'
        current = copy.deepcopy(old); current['Mounts'].reverse()
        self.assertTrue(stage.legacy_matches(old,current,'node-agent'))
        current['Mounts'][0]['RW'] = not current['Mounts'][0]['RW']
        self.assertFalse(stage.legacy_matches(old,current,'node-agent'))
        current = copy.deepcopy(old); current['Config']['Env'].append('CHANGED=value')
        self.assertFalse(stage.legacy_matches(old,current,'node-agent'))

    def test_compose_decimal_memory_encoding_preserves_exact_budget(self):
        value, plan = inputs(); name='node-agent'
        item=candidate(plan,name); item['HostConfig']['Memory']=805306368
        plan['services'][name]['mem_limit']='805306368'
        stage.verify_candidate(item,name,plan,value,{})
        item['HostConfig']['Memory']=805306369
        with self.assertRaises(ValueError): stage.verify_candidate(item,name,plan,value,{})


if __name__ == '__main__': unittest.main()
