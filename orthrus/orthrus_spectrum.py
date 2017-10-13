'''
Orthrus spectrum implementation
'''
import os
import glob
from orthrusutils import orthrusutils as util
from job import job as j
from spectrum.afl_sancov import AFLSancovReporter

class OrthrusSpectrum(object):

    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
        self.fail_msg = "failed. Are you sure you have done orthrus add --job or passed the " \
                         "right job ID? orthrus show -j might help."
        self.is_harden = os.path.exists(self.orthrusdir + "/binaries/coverage/ubsan")
        self.is_asan = os.path.exists(self.orthrusdir + "/binaries/coverage/asan")

    def run_afl_sancov(self, rootdir, is_asan=False):
        if is_asan:
            bin_path = self.orthrusdir + "/binaries/coverage/asan/bin/{}".format(self.job_token.target)
            crash_dir = rootdir + "/unique/asan"
            sanitizer = 'asan'
            target = self.orthrusdir + "/binaries/coverage/asan/bin/" + \
                     self.job_token.target + " " + self.job_token.params.replace("@@", "AFL_FILE")
        else:
            bin_path = self.orthrusdir + "/binaries/coverage/ubsan/bin/{}".format(self.job_token.target)
            crash_dir = rootdir + "/unique/harden"
            sanitizer = 'ubsan'
            target = self.orthrusdir + "/binaries/coverage/ubsan/bin/" + \
                     self.job_token.target + " " + self.job_token.params.replace("@@", "AFL_FILE")

        # def __init__(self, parsed_args, cov_cmd, bin_path, crash_dir, afl_out, sanitizer):
        reporter = AFLSancovReporter(self._args, target, bin_path, crash_dir, '{}/afl-out'.format(rootdir),
                                     sanitizer)
        return reporter.run()

    def spectrum_wrapper(self, jobrootdir, jobid):

        self.crash_dir = '{}/unique'.format(jobrootdir)
        if not os.path.exists(self.crash_dir):
            util.color_print(util.bcolors.WARNING, "\t\t[+] It looks like you are attempting to generate crash spectrum "
                                                   "before crash triage. Please triage first.")
            return False

        self.asan_crashes = glob.glob('{}/asan/*id*sig*'.format(self.crash_dir))
        self.harden_crashes = glob.glob('{}/harden/*id*sig*'.format(self.crash_dir))

        if not self.asan_crashes and not self.harden_crashes:
            util.color_print(util.bcolors.INFO, "\t\t[+] There are no crashes to analyze!")
            return True

        if (self.asan_crashes and not self.is_asan) or (self.harden_crashes and not self.is_harden):
            util.color_print(util.bcolors.WARNING, "\t\t[+] It looks like you are attempting to generate crash spectrum "
                                                   "without sanitizer coverage binaries. Did you run orthrus create "
                                                   "with -sancov argument?")
            return False

        self.is_second_run = os.path.exists('{}/crash-analysis/spectrum'.format(jobrootdir))
        if self.is_second_run and not self._args.regenerate:
            util.color_print(util.bcolors.WARNING, "\t\t[+] It looks like crash spectrum has already been generated. "
                                                   "Please pass --regenerate to regenerate. Old data will be lost unless "
                                                   "manually archived.")
            return False

        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Generating crash spectrum for job ID [{}]".format(jobid))

        if self.asan_crashes:
            if self.run_afl_sancov(jobrootdir, True):
               return False
        if self.harden_crashes:
            if self.run_afl_sancov(jobrootdir):
                return False

        return True

    def spectrum_abtests(self):
        count = 0
        for rootdir,id in [('{}/{}'.format(self.job_token.rootdir, jobId), jobId) for jobId in self.job_token.jobids]:
            group = 'Config {}'.format(count)
            count += 1
            if not util.pprint_decorator_fargs(util.func_wrapper(self.spectrum_wrapper, rootdir, id),
                                               'Obtaining spectrum for {}'.format(group), indent=2):
                return False

        return True

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting spectrum generation for job ID [{}]".format(
            self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                           "Checking Orthrus workspace", 2,
                                           'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        if self._args.version:
            reporter = AFLSancovReporter(self._args, None, None, None, None, None)
            if reporter.run():
                return False
            return True

        if self.job_token.type == 'routine':
            return self.spectrum_wrapper(self.job_token.rootdir, self.job_token.id)
        else:
            return self.spectrum_abtests()