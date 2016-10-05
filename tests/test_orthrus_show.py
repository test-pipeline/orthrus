import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusShow(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_show_jobs(self):
        args = parse_cmdline(self.description, ['show', '-j'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

    def test_show_status(self):
        # Start/sleep/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId])
        start_cmd = OrthrusStart(args, self.config)
        start_cmd.run()
        # Sleep until we discover crashes
        time.sleep(20)
        args = parse_cmdline(self.description, ['stop'])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()
        args = parse_cmdline(self.description, ['show'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

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

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        # Create
        args = parse_cmdline(self.description, ['create', '-fuzz', '-cov'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()
        # Add job
        args = parse_cmdline(self.description, ['add', '--job=main @@', '-s=./seeds'])
        self.add_cmd = OrthrusAdd(args, self.config)
        self.add_cmd.run()

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)