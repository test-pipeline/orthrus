import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusRemove(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_remove_job(self):
        args = parse_cmdline(self.description, ['remove', '-j=' + self.add_cmd.jobId])
        cmd = OrthrusRemove(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        # Create
        args = parse_cmdline(self.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()
        # Add job
        args = parse_cmdline(self.description, ['add', '--job=main @@'])
        self.add_cmd = OrthrusAdd(args, self.config)
        self.add_cmd.run()

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)