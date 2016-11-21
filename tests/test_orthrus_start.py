import time
import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusStart(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'

    def test_start(self):
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.job.id])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_resume_and_minimize(self):
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.job.id])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())
        time.sleep(TEST_SLEEP)
        args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd.job.id])
        cmd = OrthrusStop(args, self.config, True)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.job.id, '-m'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_start_coverage(self):
        self.is_coverage = True
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.job.id, '-c'])
        cmd = OrthrusStart(args, self.config, True)
        self.assertTrue(cmd.run())

    def test_start_abtest(self):
        self.is_abtest = True
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_resume_and_minimize_abtest(self):
        self.is_abtest = True
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())
        time.sleep(TEST_SLEEP)
        args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusStop(args, self.config, True)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd_abtest.job.id, '-m'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def test_start_coverage_abtest(self):
        self.is_coverage = True
        self.is_abtest = True
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd_abtest.job.id, '-c'])
        cmd = OrthrusStart(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.is_coverage = False
        self.is_abtest = False

    def tearDown(self):
        if not self.is_coverage:
            if self.is_abtest:
                args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd_abtest.job.id])
            else:
                args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd.job.id])
        else:
            # Sleep until afl-cov records its pid in afl-cov-status file and then stop
            time.sleep(TEST_SLEEP)
            if self.is_abtest:
                args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd_abtest.job.id, '-c'])
            else:
                args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd.job.id, '-c'])
        cmd = OrthrusStop(args, self.config, True)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        args = parse_cmdline(cls.description, ['create', '-asan', '-fuzz', '-cov'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        args = parse_cmdline(cls.description, ['add', '--job=main @@',
                                               '-s=./seeds/dummy_seed0'])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()

        ## abtest
        abconf_dict = {'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast', 'fuzzerB_args': '-p coe'}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=main @@',
                                           '-s=./seeds', '--abconf={}'.format(cls.abconf_file)])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)