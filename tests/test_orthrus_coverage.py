import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusCoverage(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def test_coverage(self):
        args = parse_cmdline(self.description, ['coverage', '-j', self.add_cmd.job.id])
        cmd = OrthrusCoverage(args, self.config)
        self.assertTrue(cmd.run())
        time.sleep(3*TEST_SLEEP)
        self.assertTrue(os.path.isfile(self.add_cmd.job.rootdir + '/afl-out/cov/web/index.html'))

    def test_coverage_abtest(self):
        args = parse_cmdline(self.description, ['coverage', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusCoverage(args, self.config)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-fuzz', '-cov'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        # Add routine
        routineconf_dict = {'fuzzer': 'afl-fuzz', 'fuzzer_args': ''}
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(cls.routineconf_file), '-s=./seeds'])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()
        # Add a/b test
        abconf_dict = {'num_jobs':2, 'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast',
                       'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '-s=./seeds', '--jobtype=abtests', '--jobconf={}'.
                             format(cls.abconf_file)])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest.run()
        # Start routine
        args = parse_cmdline(cls.description, ['start', '-j', cls.add_cmd.job.id])
        start_cmd = OrthrusStart(args, cls.config)
        start_cmd.run()
        time.sleep(TEST_SLEEP)
        # Stop routine
        args = parse_cmdline(cls.description, ['stop', '-j', cls.add_cmd.job.id])
        cmd = OrthrusStop(args, cls.config, True)
        cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)