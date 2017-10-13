'''
Orthrus validate implementation
'''
from orthrusutils import orthrusutils as util

class OrthrusValidate(object):

    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.success_msg = "\t\t[+] All requirements met. Orthrus is ready for use!"

    def get_on(self):
        return [item for item in self._config['dependencies'] if item[1] == 'on']

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Validating Orthrus dependencies")
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] The following programs have been marked as required in " \
                                               "~/.orthrus/orthrus.conf")
        for prog, _ in self.get_on():
            util.color_print(util.bcolors.OKGREEN, "\t\t\t[+] {}".format(prog))

        if not util.pprint_decorator_fargs(util.func_wrapper(util.validate_inst, self._config),
                                           'Checking if requirements are met', indent=2):
            return False
        util.color_print(util.bcolors.OKGREEN, self.success_msg)
        return True