import time
import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusStart(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}

    def test_start(self):
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_resume_and_minimize(self):
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())
        time.sleep(TEST_SLEEP)
        args = parse_cmdline(self.description, ['stop'])
        cmd = OrthrusStop(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId, '-m'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_start_coverage(self):
        self.is_coverage = True
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.jobId, '-c'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.is_coverage = False

    def tearDown(self):
        if not self.is_coverage:
            args = parse_cmdline(self.description, ['stop'])
        else:
            args = parse_cmdline(self.description, ['stop', '-c'])
        cmd = OrthrusStop(args, self.config)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        args = parse_cmdline(cls.description, ['create', '-asan', '-cov'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        args = parse_cmdline(cls.description, ['add', '--job=main @@',
                                               '-i=./afl-arch-out.tar.gz'])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)