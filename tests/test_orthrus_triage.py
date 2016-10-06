import time
import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusTriage(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_triage(self):
        args = parse_cmdline(self.description, ['triage', '-j', self.cmd.jobId])
        cmd = OrthrusTriage(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        args = parse_cmdline(self.description, ['create', '-asan', '-fuzz'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                                                '-s=./seeds'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', self.cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())
        time.sleep(2*TEST_SLEEP)
        args = parse_cmdline(self.description, ['stop'])
        cmd = OrthrusStop(args, self.config)
        self.assertTrue(cmd.run())

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)