import unittest
import time
import json
import shutil
from orthrus.orthrus_add import OrthrusAdd
from orthrus.orthrus_create import OrthrusCreate
from orthrus.orthrus_start import OrthrusStart
from orthrus.orthrus_stop import OrthrusStop
from orthrusutils.orthrusutils import parse_cmdline, TEST_SLEEP

class TestOrthrusStart(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

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
        assert cmd.run(), "Failed class cmd"

        # Add routine job
        abconf_dict = {'job_type': 'abtests', 'fuzz_cmd': 'main @@', 'num_jobs': 2,
                       'job_desc': [{'fuzzer': 'afl-fuzz', 'fuzzer_args': '', 'seed_dir': './seeds'},
                                    {'fuzzer': 'afl-fuzz-fast', 'fuzzer_args': '-p coe', 'seed_dir': './seeds'}
                                    ]
                       }
        routineconf_dict = {'job_type': 'routine', 'fuzz_cmd': 'main @@', 'num_jobs': 1,
                            'job_desc': [{'fuzzer': 'afl-fuzz', 'fuzzer_args': '', 'seed_dir': './seeds/dummy_seed0'}
                                         ]
                            }
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

        args = parse_cmdline(cls.description, ['add', '--jobconf={}'.format(cls.routineconf_file)])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        assert cls.add_cmd.run(), "Failed class cmd"

        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '--jobconf={}'.format(cls.abconf_file)])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        assert cls.add_cmd_abtest.run(), "Failed class cmd"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)