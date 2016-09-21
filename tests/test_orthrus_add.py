import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusAdd(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_add_job(self):
        args = parse_cmdline(self.description, ['add', '--job="main 12 @@"'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def test_add_and_seed(self):
        args = parse_cmdline(self.description, ['add', '--job="main 12 @@"',
                            '-s=/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/seeds'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def test_add_and_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main 12 @@',
                    '-i=/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/afl-out.tar.gz'])
        cmd = OrthrusAdd(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        args = parse_cmdline(self.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)