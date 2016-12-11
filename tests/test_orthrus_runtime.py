import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusRuntime(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'

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

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-asan', '-fuzz'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()
        # Add routine job 1 (asan only)
        args = parse_cmdline(cls.description, ['add', '--job=test_asan @@',
                                                '-i=./afl-crash-out-rename.tar.gz'])
        cls.add_cmd1 = OrthrusAdd(args, cls.config)
        cls.add_cmd1.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd1.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        # Add routine job 2 (harden+asan)
        args = parse_cmdline(cls.description, ['add', '--job=main_no_abort @@',
                                                '-i=./afl-crash-out-rename.tar.gz'])
        cls.add_cmd2 = OrthrusAdd(args, cls.config)
        cls.add_cmd2.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd2.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

        # Add a/b test job
        abconf_dict = {'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast', 'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)
        args = parse_cmdline(cls.description, ['add', '--job=test_asan @@', '-i=./afl-crash-out.tar.gz', '--abconf={}'.
                             format(cls.abconf_file)])
        cls.add_cmd_abtest = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtest.run()

        args = parse_cmdline(cls.description, ['triage', '-j', cls.add_cmd_abtest.job.id])
        cmd = OrthrusTriage(args, cls.config, test=True)
        cmd.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)