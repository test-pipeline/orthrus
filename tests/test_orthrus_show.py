import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusShow(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}

    def test_show_jobs(self):
        args = parse_cmdline(self.description, ['show', '-j'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

    def test_show_status(self):
        # Start/show/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId])
        start_cmd = OrthrusStart(args, self.config)
        start_cmd.run()
        time.sleep(10)
        args = parse_cmdline(self.description, ['show'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['stop'])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()

    def test_show_cov(self):
        # Start/sleep/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId, '-c'])
        start_cmd = OrthrusStart(args, self.config)
        start_cmd.run()
        # Long sleep so that afl-cov catches up
        time.sleep(60)
        args = parse_cmdline(self.description, ['stop'])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()
        # Sleep again so afl-cov finishes
        time.sleep(30)
        args = parse_cmdline(self.description, ['show', '-cov'])
        cmd = OrthrusShow(args, self.config, True)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-fuzz', '-cov'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        # Add job
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '-s=./seeds'])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)