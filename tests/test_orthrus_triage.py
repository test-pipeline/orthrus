import unittest
import time
import json
import shutil
import os
from orthrus.orthrus_add import OrthrusAdd
from orthrus.orthrus_create import OrthrusCreate
from orthrus.orthrus_start import OrthrusStart
from orthrus.orthrus_stop import OrthrusStop
from orthrus.orthrus_triage import OrthrusTriage
from orthrusutils.orthrusutils import parse_cmdline, TEST_SLEEP

class TestOrthrusTriage(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def test_triage(self):
        args = parse_cmdline(self.description, ['triage', '-j', self.add_cmd.job.id])
        cmd = OrthrusTriage(args, self.config, test=True)
        self.assertTrue(cmd.run())

    def test_triage_abtest(self):
        args = parse_cmdline(self.description, ['triage', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusTriage(args, self.config, test=True)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, cls.config)
        assert cmd.run(), "Failed class cmd"
        # Add routine job
        routineconf_dict = {'job_type': 'routine', 'fuzz_cmd': 'main @@', 'num_jobs': 1,
                    'job_desc': [{'fuzzer': 'afl-fuzz', 'fuzzer_args': '', 'seed_dir': './seeds'}
                                 ]
                    }
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

        args = parse_cmdline(cls.description, ['add', '--jobconf={}'.format(cls.routineconf_file)])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        assert cls.add_cmd.run(), "Failed class cmd"
        # Start routine job fuzzing
        args = parse_cmdline(cls.description, ['start', '-j', cls.add_cmd.job.id])
        cmd = OrthrusStart(args, cls.config)
        assert cmd.run(), "Failed class cmd"
        time.sleep(2*TEST_SLEEP)
        # Stop routine job fuzzing
        args = parse_cmdline(cls.description, ['stop', '-j', cls.add_cmd.job.id])
        cmd = OrthrusStop(args, cls.config, True)
        assert cmd.run(), "Failed class cmd"
        # Add a/b test job
        abconf_dict = {'job_type': 'abtests', 'fuzz_cmd': 'main @@', 'num_jobs': 2,
                       'job_desc': [{'fuzzer': 'afl-fuzz', 'fuzzer_args': '', 'seed_dir': './seeds'},
                                    {'fuzzer': 'afl-fuzz-fast', 'fuzzer_args': '-p coe', 'seed_dir': './seeds'}
                                    ]
                       }
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--jobconf={}'.format(cls.abconf_file)])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        assert cls.add_cmd_abtest.run(), "Failed class cmd"
        # Start a/b test job
        args = parse_cmdline(cls.description, ['start', '-j', cls.add_cmd_abtest.job.id])
        cmd = OrthrusStart(args, cls.config)
        assert cmd.run(), "Failed class cmd"
        time.sleep(2 * TEST_SLEEP)
        # Stop a/b test job
        args = parse_cmdline(cls.description, ['stop', '-j', cls.add_cmd_abtest.job.id])
        cmd = OrthrusStop(args, cls.config, True)
        assert cmd.run(), "Failed class cmd"
        # Simulate old triage unique and exploitable dirs
        sim_dirs = []
        for id in cls.add_cmd_abtest.job.jobids:
            sim_dirs.append(cls.orthrusdirname + '/jobs/abtests/{}/{}/unique'.format(cls.add_cmd_abtest.job.id, id))
            sim_dirs.append(cls.orthrusdirname + '/jobs/abtests/{}/{}/exploitable'.format(cls.add_cmd_abtest.job.id, id))

        for dir in sim_dirs:
            os.makedirs(dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)