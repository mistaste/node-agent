import importlib.machinery
import pathlib
import unittest

queue = importlib.machinery.SourceFileLoader('egress_queue', str(pathlib.Path(__file__).with_name('guardex-egress-queue'))).load_module()


class QueueSafety(unittest.TestCase):
    def test_simple_fifo(self):
        self.assertEqual(queue.queue_plan([dict(root=True, kind='pfifo_fast')]), [['root', 'fq_codel']])

    def test_existing_aqm_is_not_reset(self):
        self.assertEqual(queue.queue_plan([dict(root=True, kind='fq_codel')]), [])

    def test_multiqueue_root_is_preserved(self):
        q = [dict(root=True, kind='mq'), dict(parent=':1', kind='fq'), dict(parent=':2', kind='fq_codel')]
        self.assertEqual(queue.queue_plan(q), [['parent', ':1', 'fq_codel']])

    def test_custom_shaper_is_preserved(self):
        for kind in ['htb', 'cake', 'tbf', 'noqueue']:
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                queue.queue_plan([dict(root=True, kind=kind)])

    def test_default_multiqueue_gets_addressable_handle(self):
        q = [dict(root=True, kind='mq', handle='0:'), dict(parent=':1', kind='fq'), dict(parent=':2', kind='fq')]
        self.assertEqual(queue.queue_plan(q), [['root', 'handle', '1:', 'mq'], ['parent', '1:1', 'fq_codel'], ['parent', '1:2', 'fq_codel']])

    def test_custom_multiqueue_leaf_is_preserved(self):
        with self.assertRaises(ValueError):
            queue.queue_plan([dict(root=True, kind='mq'), dict(parent=':1', kind='tbf')])


if __name__ == '__main__':
    unittest.main()
