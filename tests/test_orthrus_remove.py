import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusRemove(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'
    routineconf_file = orthrusdirname + '/conf/routineconf.conf'

    def test_remove_job(self):
        # Remove job
        args = parse_cmdline(self.description, ['remove', '-j=' + self.add_cmd.job.id])
        cmd = OrthrusRemove(args, self.config)
        self.assertTrue(cmd.run())

    def test_remove_job_abtest(self):
        # Remove abtest job
        args = parse_cmdline(self.description, ['remove', '-j=' + self.add_cmd_abtests.job.id])
        cmd = OrthrusRemove(args, self.config)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()

        # abtests set up
        routineconf_dict = {'fuzzer': 'afl-fuzz', 'fuzzer_args': ''}
        with open(cls.routineconf_file, 'w') as routineconf_fp:
            json.dump(routineconf_dict, routineconf_fp, indent=4)

        abconf_dict = {'num_jobs':2, 'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast',
                       'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)

        # Add job
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '--jobtype=routine', '--jobconf={}'.
                             format(cls.routineconf_file)])
        cls.add_cmd = OrthrusAdd(args, cls.config)
        cls.add_cmd.run()

        # Add abtest job
        args = parse_cmdline(cls.description, ['add', '--job=main @@', '--jobtype=abtests', '--jobconf={}'.
                             format(cls.abconf_file)])
        cls.add_cmd_abtests = OrthrusAdd(args, cls.config)
        cls.add_cmd_abtests.run()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)