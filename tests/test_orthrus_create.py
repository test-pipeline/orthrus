import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusCreate(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}

    def test_create_asan(self):
        args = parse_cmdline(self.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, self.config)
        self.assertTrue(cmd.run())

    def test_create_fuzz(self):
        args = parse_cmdline(self.description, ['create', '-fuzz'])
        cmd = OrthrusCreate(args, self.config)
        self.assertTrue(cmd.run())

    def test_create_cov(self):
        args = parse_cmdline(self.description, ['create', '-cov'])
        cmd = OrthrusCreate(args, self.config)
        self.assertTrue(cmd.run())

    def test_create_asan_cov(self):
        args = parse_cmdline(self.description, ['create', '-asan', '-sancov'])
        cmd = OrthrusCreate(args, self.config)
        self.assertTrue(cmd.run())

    def test_create_harden_cov(self):
        args = parse_cmdline(self.description, ['create', '-fuzz', '-sancov'])
        cmd = OrthrusCreate(args, self.config)
        self.assertTrue(cmd.run())

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)