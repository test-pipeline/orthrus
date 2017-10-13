import unittest
import shutil
import json
import os
import subprocess
import glob
from orthrus.orthrus_add import OrthrusAdd
from orthrus.orthrus_create import OrthrusCreate
from orthrus.orthrus_triage import OrthrusTriage
from orthrusutils.orthrusutils import parse_cmdline


class TestGdbOrthrus(unittest.TestCase):
    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def test_gdb_orthrus(self):
        cmd = ['gdb', '-q', '-ex=r', '-ex=call $jsonify("tmp.json")', '-ex=quit', '--args', '{}/binaries/harden-dbg/bin/main_no_abort'
            .format(self.orthrusdirname), glob.glob('{}/unique/harden/HARDEN*'.format(self.add_cmd.job.rootdir))[0]]
        ret = subprocess.Popen(cmd, stdout=open(os.devnull), stderr=subprocess.STDOUT).wait()
        self.assertTrue(((ret == 0) and os.path.exists("tmp.json")))

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-fuzz'])
        cmd = OrthrusCreate(args, cls.config)
        assert cmd.run(), "Failed class cmd"
        # Add job
        routineconf_dict = {'job_type': 'routine', 'fuzz_cmd': 'main_no_abort @@', 'num_jobs': 1,
                            'job_desc': [{'fuzzer': 'afl-fuzz', 'fuzzer_args': '', 'seed_dir': './seeds'}
                                         ]
                            }
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

        args = parse_cmdline(cls.description, ['add', '--jobconf={}'.format(cls.routineconf_file),
                                               '-i=./afl-crash-out-rename.tar.gz'])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()

        # Triage
        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)
        if os.path.exists("tmp.json"):
            os.remove("tmp.json")
