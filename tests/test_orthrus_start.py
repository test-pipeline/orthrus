import time
import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusStart(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_start(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                '-s=./seeds'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_resume(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                '-s=./seeds'])
        add_cmd = OrthrusAdd(args, self.config)
        self.assertTrue(add_cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', add_cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())
        time.sleep(10)
        args = parse_cmdline(self.description, ['stop'])
        cmd = OrthrusStop(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', add_cmd.jobId, '-m'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_start_after_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
            '-i=./afl-arch-out.tar.gz'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_start_minimize_after_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
            '-i=./afl-arch-out.tar.gz'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', cmd.jobId, '-m'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_start_coverage(self):
        self.is_coverage = True
        args = parse_cmdline(self.description, ['add', '--job=main @@',
            '-s=./seeds'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', cmd.jobId, '-c'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.is_coverage = False
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        args = parse_cmdline(self.description, ['create', '-asan', '-cov'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()

    def tearDown(self):
        if not self.is_coverage:
            args = parse_cmdline(self.description, ['stop'])
        else:
            args = parse_cmdline(self.description, ['stop', '-c'])
        cmd = OrthrusStop(args, self.config)
        self.assertTrue(cmd.run())
        shutil.rmtree(self.orthrusdirname)