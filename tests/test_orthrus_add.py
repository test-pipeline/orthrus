import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusAdd(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    archive_dir = orthrusdirname + '/archive'
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def test_add_job(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(self.routineconf_file)])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_seed(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(self.routineconf_file), '-s=./seeds'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(self.routineconf_file), '-i=./afl-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_import_crashes(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(self.routineconf_file), '-i=./afl-crash-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_and_import_archive(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(self.routineconf_file), '-i=./afl-arch-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_abtest_job(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=abtests', '--jobconf={}'.
                             format(self.abconf_file)])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_abtest_and_seed(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=abtests', '--jobconf={}'.
                             format(self.abconf_file), '-s=./seeds'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_abtest_and_import(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=abtests', '--jobconf={}'.
                             format(self.abconf_file), '-i=./afl-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_abtest_and_import_crashes(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=abtests', '--jobconf={}'.
                             format(self.abconf_file), '-i=./afl-crash-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    def test_add_abtest_and_import_archive(self):
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--jobtype=abtests', '--jobconf={}'.
                             format(self.abconf_file), '-i=./afl-arch-out.tar.gz'])
        self.cmd = OrthrusAdd(args, self.config)
        self.assertTrue(self.cmd.run())

    @classmethod
    def setUpClass(cls):
        args = parse_cmdline(cls.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        abconf_dict = {'num_jobs': 2, 'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast',
                       'fuzzerB_args': ''}
        routineconf_dict = {'fuzzer': 'afl-fuzz', 'fuzzer_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)

    def tearDown(self):
        OrthrusRemove(parse_cmdline(self.description, ['remove', '-j', self.cmd.job.id]), self.config).run()
        shutil.rmtree(self.archive_dir)
        os.makedirs(self.archive_dir)