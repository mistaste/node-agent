import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0,str(Path(__file__).parent))
import controller as c

class ControllerTests(unittest.TestCase):
    def test_unhealthy_bridge_withdraws_new_selection_without_stopping_live_streams(self):
        value={'status':'retained','health_failures':1};qualification={}
        with patch.object(c,'owner',return_value=(value,qualification)), \
             patch.object(c,'authorized'),patch.object(c,'linked'),patch.object(c,'validate_backbone'), \
             patch.object(c,'fields',return_value={'ActiveState':'active'}),patch.object(c,'healthy',return_value=False), \
             patch.object(c,'deselect') as deselect,patch.object(c,'run') as run,patch.object(c,'save'):
            result=c.sync()
            deselect.assert_called_once_with(value,qualification)
            self.assertFalse(result['selected']);run.assert_not_called()

    def test_one_transient_health_failure_keeps_verified_selection(self):
        with patch.object(c,'owner',return_value=({'status':'retained'},{})), \
             patch.object(c,'authorized'),patch.object(c,'linked'),patch.object(c,'validate_backbone'), \
             patch.object(c,'fields',return_value={'ActiveState':'active'}),patch.object(c,'healthy',return_value=False), \
             patch.object(c,'verify_table',return_value=True),patch.object(c,'save'),patch.object(c,'deselect') as deselect:
            self.assertTrue(c.sync()['selected']);deselect.assert_not_called()

    def test_retained_scope_ignores_automatic_rollback(self):
        with patch.object(c,'owner',return_value=({'status':'retained'},{})),patch.object(c,'deselect') as deselect:
            self.assertTrue(c.rollback()['automatic_rollback_ignored']);deselect.assert_not_called()

    def test_foreign_nat_is_never_deleted(self):
        with patch.object(c,'verify_table',side_effect=AssertionError('foreign')),patch.object(c,'run') as run:
            with self.assertRaises(AssertionError):c.deselect({}, {})
            run.assert_not_called()

    def test_listener_is_drained_and_convergence_is_bounded(self):
        self.assertIn('KillSignal=SIGUSR1',c.unit_text())
        self.assertIn('TimeoutStopSec=80s',c.unit_text())
        self.assertIn('OnUnitActiveSec=30s',c.sync_timer())
        self.assertNotIn(' conntrack ',c.unit_text())

if __name__=='__main__':unittest.main()
