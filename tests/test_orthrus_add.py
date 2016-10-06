import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusAdd(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    archive_dir = orthrusdirname + '/archive'

    def test_add_job(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_seed(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                            '-s=./seeds'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                    '-i=./afl-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_import_crashes(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
                    '-i=./afl-crash-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_import_archive(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@',
            '-i=./afl-arch-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    @classmethod
    def setUpClass(cls):
        args = parse_cmdline(cls.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)

    def tearDown(self):
        OrthrusRemove(parse_cmdline(self.description, ['remove', '-j', self.cmd.jobId]), self.config).run()
        shutil.rmtree(self.archive_dir)
        os.makedirs(self.archive_dir)