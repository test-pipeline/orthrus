import unittest
from orthrus.commands import *
from orthrusutils.orthrusutils import *

class TestOrthrusShow(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_show_jobs(self):
        args = parse_cmdline(self.description, ['show', '-j'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

    def test_show_status(self):
        args = parse_cmdline(self.description, ['show'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

    def test_show_cov(self):
        args = parse_cmdline(self.description, ['show', '-cov'])
        cmd = OrthrusShow(args, self.config)
        self.assertTrue(cmd.run())

    def setUp(self):
        self.config = {'orthrus' : {'directory': self.orthrusdirname}}
        # Create
        args = parse_cmdline(self.description, ['create', '-asan'])
        cmd = OrthrusCreate(args, self.config)
        cmd.run()
        # Add job
        args = parse_cmdline(self.description, ['add', '--job=main 12 @@'])
        self.add_cmd = OrthrusAdd(args, self.config)
        self.add_cmd.run()

    def tearDown(self):
        shutil.rmtree(self.orthrusdirname)