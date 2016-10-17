import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusRemove(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'
    config = {'orthrus': {'directory': orthrusdirname}}
    abconf_file = orthrusdirname + '/conf/abconf.conf'

    def test_remove_job(self):
        # Add job
        args = parse_cmdline(self.description, ['add', '--job=main @@'])
        add_cmd = OrthrusAdd(args, self.config)
        add_cmd.run()

        # Remove job
        args = parse_cmdline(self.description, ['remove', '-j=' + add_cmd.job.id])
        cmd = OrthrusRemove(args, self.config)
        self.assertTrue(cmd.run())

    def test_remove_job_abtest(self):
        # Add abtest job
        args = parse_cmdline(self.description, ['add', '--job=main @@', '--abconf={}'.format(self.abconf_file)])
        add_cmd = OrthrusAdd(args, self.config)
        add_cmd.run()

        # Remove abtest job
        args = parse_cmdline(self.description, ['remove', '-j=' + add_cmd.job.id, '--abtest'])
        cmd = OrthrusRemove(args, self.config)
        self.assertTrue(cmd.run())

    @classmethod
    def setUpClass(cls):
        # Create
        args = parse_cmdline(cls.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, cls.config)
        cmd.run()

        # abtests set up
        abconf_dict = {'fuzzerA': 'afl-fuzz', 'fuzzerA_args': '', 'fuzzerB': 'afl-fuzz-fast', 'fuzzerB_args': ''}
        with open(cls.abconf_file, 'w') as abconf_fp:
            json.dump(abconf_dict, abconf_fp, indent=4)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.orthrusdirname)