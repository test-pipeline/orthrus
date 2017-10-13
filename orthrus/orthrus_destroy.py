'''
Orthrus destroy implementation
'''
import sys
import shutil
from orthrusutils import orthrusutils as util

class OrthrusDestroy(object):
    def __init__(self, args, config, testinput=None):
        self._args = args
        self._config = config
        self.testinput = testinput
        self.orthrusdir = self._config['orthrus']['directory']

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Destroy Orthrus workspace")
        util.color_print_singleline(util.bcolors.OKGREEN, "\t[?] Delete complete workspace? [y/n]...: ")

        if (self.testinput and 'y' in self.testinput) or 'y' in sys.stdin.readline()[0]:

            if not util.pprint_decorator_fargs(util.func_wrapper(shutil.rmtree, self.orthrusdir),
                                               'Deleting workspace', indent=2):
                return False

        return True