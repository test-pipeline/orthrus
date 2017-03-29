import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusRuntime(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def test_runtime_routine_asan(self):
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd1.job.id])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(self.add_cmd1.job.rootdir)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(self.add_cmd1.job.rootdir)))
        ## Fail cos regen
        self.assertFalse(cmd.run())
        ## Regen and check
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd1.job.id, '--regenerate'])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(self.add_cmd1.job.rootdir)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(self.add_cmd1.job.rootdir)))

    def test_runtime_routine_harden_asan(self):
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd2.job.id])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(self.add_cmd2.job.rootdir)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(self.add_cmd2.job.rootdir)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/harden'.format(self.add_cmd2.job.rootdir)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/harden/*.json'.format(self.add_cmd2.job.rootdir)))
        ## Fail cos regen
        self.assertFalse(cmd.run())
        ## Regen and check
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd2.job.id, '--regenerate'])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(self.add_cmd2.job.rootdir)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(self.add_cmd2.job.rootdir)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/harden'.format(self.add_cmd2.job.rootdir)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/harden/*.json'.format(self.add_cmd2.job.rootdir)))

    def test_runtime_abtests(self):
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd_abtest.job.id])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())

        # Check if files were generated
        joba_root = '{}/{}'.format(self.add_cmd_abtest.job.rootdir, self.add_cmd_abtest.job.jobids[0])
        jobb_root = '{}/{}'.format(self.add_cmd_abtest.job.rootdir, self.add_cmd_abtest.job.jobids[1])

        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(joba_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(joba_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(jobb_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(jobb_root)))
        ## Fail cos regen
        self.assertFalse(cmd.run())
        ## Regen and check
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd_abtest.job.id, '--regenerate'])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(joba_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(joba_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(jobb_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(jobb_root)))

    def test_runtime_abtests_harden_asan(self):
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd_abtest2.job.id])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())

        # Check if files were generated
        joba_root = '{}/{}'.format(self.add_cmd_abtest2.job.rootdir, self.add_cmd_abtest2.job.jobids[0])
        jobb_root = '{}/{}'.format(self.add_cmd_abtest2.job.rootdir, self.add_cmd_abtest2.job.jobids[1])

        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(joba_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(joba_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/harden'.format(joba_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/harden/*.json'.format(joba_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(jobb_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(jobb_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/harden'.format(jobb_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/harden/*.json'.format(jobb_root)))
        ## Fail cos regen
        self.assertFalse(cmd.run())
        ## Regen and check
        args = parse_cmdline(self.description, ['runtime', '-j', self.add_cmd_abtest2.job.id, '--regenerate'])
        cmd = OrthrusRuntime(args, self.config)
        self.assertTrue(cmd.run())
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(joba_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(joba_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/harden'.format(joba_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/harden/*.json'.format(joba_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/asan'.format(jobb_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/asan/*.json'.format(jobb_root)))
        self.assertTrue(os.path.exists('{}/crash-analysis/runtime/harden'.format(jobb_root)))
        self.assertTrue(glob.glob('{}/crash-analysis/runtime/harden/*.json'.format(jobb_root)))

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-asan', '-fuzz'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        # Add routine job 1 (asan only)
        routineconf_dict = {'fuzzer': 'afl-fuzz', 'fuzzer_args': ''}
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

        args = parse_cmdline(cls.description, ['add', '--job=test_asan @@', '--jobtype=routine', '--jobconf={}'.
                             format(cls.routineconf_file), '-i=./afl-crash-out-rename.tar.gz'])
        cls.add_cmd1 = OrthrusAdd(args, cls.config)
        cls.add_cmd1.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd1.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        # Add routine job 2 (harden+asan)
        args = parse_cmdline(cls.description, ['add', '--job=main_no_abort @@', '--jobtype=routine', '--jobconf={}'.
                             format(cls.routineconf_file), '-i=./afl-crash-out-rename.tar.gz'])
        cls.add_cmd2 = OrthrusAdd(args, cls.config)
        cls.add_cmd2.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd2.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        # Add a/b test job (asan only)
        abconf_dict = {'num_jobs':2, 'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast',
                       'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=test_asan @@', '-i=./afl-crash-out.tar.gz', '--jobconf={}'.
                             format(cls.abconf_file), '--jobtype=abtests'])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd_abtest.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        # Add a/b test job (asan + harden)
        args = parse_cmdline(cls.description, ['add', '--job=main_no_abort @@', '-i=./afl-crash-out.tar.gz', '--jobconf={}'.
                             format(cls.abconf_file), '--jobtype=abtests'])
        cls.add_cmd_abtest2 = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest2.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd_abtest2.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)