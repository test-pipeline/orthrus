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
        args = parse_cmdline(self.description, ['start', '-j', add_cmd.jobId])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        args = parse_cmdline(self.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()

    def tearDown(self):
        args = parse_cmdline(self.description, ['stop'])
        cmd = OrthrusStop(args, self.config)
        self.assertTrue(cmd.run())
        shutil.rmtree(self.orthrusdirname)