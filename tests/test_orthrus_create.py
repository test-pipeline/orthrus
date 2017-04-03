import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusCreate(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    blacklist_file = 'asan_blacklist.txt'

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

    def test_create_asan_blacklist_fail(self):
        if os.path.exists(self.blacklist_file):
            os.remove(self.blacklist_file)
        args = parse_cmdline(self.description, ['create', '-asanblacklist'])
        cmd = OrthrusCreate(args, self.config)
        self.assertFalse(cmd.run())
        self.touch_blacklist()

    def test_create_asan_blacklist(self):
        args = parse_cmdline(self.description, ['create', '-asanblacklist'])
        cmd = OrthrusCreate(args, self.config)
        self.assertTrue(cmd.run())

    def test_create_dict(self):
        args = parse_cmdline(self.description, ['create', '-dict'])
        cmd = OrthrusCreate(args, self.config)
        # TODO: Fix Test infra for dict
        self.assertFalse(cmd.run())

    @classmethod
    def touch_blacklist(cls):
        with open(cls.blacklist_file, 'w') as file:
            file.write('#')

    @classmethod
    def setUpClass(cls):
        cls.touch_blacklist()

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)