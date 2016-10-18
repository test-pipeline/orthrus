import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusShow(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'

    def test_show_jobs(self):
        args = parse_cmdline(self.description, ['show', '-conf'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

    def test_show_status(self):
        # Start/show/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.job.id])
        start_cmd = OrthrusStart(args, self.config)
        start_cmd.run()
        time.sleep(2*TEST_SLEEP)
        args = parse_cmdline(self.description, ['show', '-j', self.add_cmd.job.id])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd.job.id])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()

    def test_show_status_abtest(self):
        # Start/show/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd_abtest.job.id])
        start_cmd = OrthrusStart(args, self.config)
        start_cmd.run()
        time.sleep(2 * TEST_SLEEP)
        args = parse_cmdline(self.description, ['show', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())
        args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd_abtest.job.id])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()

    def test_show_cov(self):
        # Start/sleep/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd.job.id, '-c'])
        start_cmd = OrthrusStart(args, self.config, True)
        start_cmd.run()
        # Long sleep so that afl-cov catches up
        time.sleep(2*TEST_SLEEP)
        args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd.job.id])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()
        # Sleep again so afl-cov finishes
        time.sleep(TEST_SLEEP)
        args = parse_cmdline(self.description, ['show', '-j', self.add_cmd.job.id, '-cov'])
        cmd = OrthrusShow(args, self.config, True)
        self.assertTrue(cmd.run())

    def test_show_cov_abtest(self):
        # Start/sleep/stop job
        args = parse_cmdline(self.description, ['start', '-j', self.add_cmd_abtest.job.id, '-c'])
        start_cmd = OrthrusStart(args, self.config, True)
        start_cmd.run()
        # Long sleep so that afl-cov catches up
        time.sleep(2*TEST_SLEEP)
        args = parse_cmdline(self.description, ['stop', '-j', self.add_cmd_abtest.job.id])
        stop_cmd = OrthrusStop(args, self.config)
        stop_cmd.run()
        # Sleep again so afl-cov finishes
        time.sleep(TEST_SLEEP)
        args = parse_cmdline(self.description, ['show', '-j', self.add_cmd_abtest.job.id, '-cov'])
        cmd = OrthrusShow(args, self.config, True)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-fuzz', '-cov'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        # Add job
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '-s=./seeds'])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()
        # Add a/b test job
        abconf_dict = {'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast', 'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '-s=./seeds', '--abconf={}'.
                             format(cls.abconf_file)])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)