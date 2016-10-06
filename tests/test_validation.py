import unittest
from orthrusutils.orthrusutils import *
from orthrus.commands import *

class TestOrthrusValidate(unittest.TestCase):

    description = 'Test harness'
    orthrusdirname = '.orthrus'

    def test_validate(self):
        args = parse_cmdline(self.description, ['validate'])
        cmd = OrthrusValidate(args, self.config_pass)
        self.assertTrue(cmd.run())

    def test_validate_false(self):
        args = parse_cmdline(self.description, ['validate'])
        cmd = OrthrusValidate(args, self.config_fail)
        self.assertFalse(cmd.run())

    def setUp(self):
        # self.config_pass = {'dependencies': [('clang', 'on'), ('gcc', 'on'), ('afl-fuzz', 'on'),
        #                                                 ('afl-clang', 'on'), ('afl-clang++', 'on'),
        #                                                 ('afl-collect', 'on'), ('afl-minimize', 'on'),
        #                                                 ('afl-multicore', 'on'), ('gdb', 'on'), ('afl-cov', 'on'),
        #                                                 ('lcov', 'on'), ('genhtml', 'on')]}
        self.config_pass = parse_config('../../conf/orthrus.conf')

        self.config_fail = {'dependencies': [('joombaloomba', 'on')]}