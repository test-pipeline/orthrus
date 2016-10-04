import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusAdd(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_add_job(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def test_add_and_seed(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                            '-s=./seeds'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def test_add_and_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                    '-i=./afl-out.tar.gz'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def test_add_and_import_crashes(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                    '-i=./afl-crash-out.tar.gz'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def test_add_and_import_archive(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
            '-i=./afl-arch-out.tar.gz'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        args = parse_cmdline(self.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)