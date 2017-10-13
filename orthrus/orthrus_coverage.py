'''
Orthrus coverage implementation
'''
import os
from orthrusutils import orthrusutils as util
from job import job as j

class OrthrusCoverage(object):

    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
        self.fail_msg = "failed. Are you sure you have done orthrus add --job or passed the " \
                         "right job ID? orthrus show -j might help."

    def run(self):

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Checking coverage for job ID [{}]".format(
            self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        if self.job_token.type == 'abtests':
            util.color_print(util.bcolors.WARNING, "\t[+] Coverage interface for A/B tests is not supported at the "
                                                   "moment")
            return True

        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Checking test coverage for {} job ID [{}]".format(
            self.job_token.type, self.job_token.id))

        #run_afl_cov(orthrus_dir, jobroot_dir, target_arg, params, livemode=False, test=False):
        util.run_afl_cov(self.orthrusdir, self.job_token.rootdir, self.job_token.target, self.job_token.params)

        util.color_print(util.bcolors.OKGREEN, "\t\t[+] This might take a while. Please check {} for progress."
                         .format(self.job_token.rootdir + "/afl-out/cov/afl-cov.log"))
        return True