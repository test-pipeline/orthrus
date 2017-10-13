'''
Orthrus runtime implementation
'''
import os
import shutil
import glob
import time
from orthrusutils import orthrusutils as util
from job import job as j
from runtime.runtime import RuntimeAnalyzer

class OrthrusRuntime(object):

    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
        self.is_harden = os.path.exists(self.orthrusdir + "/binaries/harden-dbg")
        self.is_asan = os.path.exists(self.orthrusdir + "/binaries/asan-dbg")
        self.fail_msg = "failed. Are you sure you have done orthrus add --job or passed the " \
                         "right job ID? orthrus show -j might help."

    def analyze(self, job_rootdir, is_asan=False):
        if is_asan:
            bin_path = self.orthrusdir + "/binaries/asan-dbg/bin/{}".format(self.job_token.target)
            crash_dir = job_rootdir + "/unique/asan"
            sanitizer = 'asan'
            target = self.orthrusdir + "/binaries/asan-dbg/bin/" + \
                     self.job_token.target + " " + self.job_token.params
        else:
            bin_path = self.orthrusdir + "/binaries/harden-dbg/bin/{}".format(self.job_token.target)
            crash_dir = job_rootdir + "/unique/harden"
            sanitizer = 'harden'
            target = self.orthrusdir + "/binaries/harden-dbg/bin/" + \
                     self.job_token.target + " " + self.job_token.params

        #__init__(self, job_token, crash_dir, sanitizer)
        analyzer = RuntimeAnalyzer(job_rootdir, bin_path, target, crash_dir, sanitizer)
        return analyzer.run()

    def analyze_wrapper(self, job_rootdir, job_id):
        crash_dir = '{}/unique'.format(job_rootdir)
        if not os.path.exists(crash_dir):
            util.color_print(util.bcolors.WARNING, "\t\t[+] It looks like you are attempting to analyze crashes you don't "
                                                   "have or not triaged. Please run triage!")
            return False

        asan_crashes = glob.glob('{}/asan/*id*sig*'.format(crash_dir))
        harden_crashes = glob.glob('{}/harden/*id*sig*'.format(crash_dir))

        if not asan_crashes and not harden_crashes:
            util.color_print(util.bcolors.INFO, "\t\t[+] There are no crashes to analyze!")
            return True

        if (asan_crashes and not self.is_asan) or (harden_crashes and not self.is_harden):
            util.color_print(util.bcolors.WARNING, "\t\t[+] It looks like you are attempting to invoke crash analysis "
                                                   "without sanitizer and/or debug binaries. Did you run orthrus create "
                                                   "with -asan -fuzz?")
            return False

        runtime_path = '{}/crash-analysis/runtime'.format(job_rootdir)
        is_second_run = os.path.exists(runtime_path)
        if is_second_run:
            if not self._args.regenerate:
                util.color_print(util.bcolors.WARNING, "\t\t[+] It looks like dynamic analysis results are already there. "
                                                       "Please pass --regenerate to regenerate. Old data will be archived.")
                return False
            else:
                util.color_print(util.bcolors.OKGREEN, "\t\t[+] Archiving old analysis results.")
                shutil.move(runtime_path, "{}.{}".format(runtime_path, time.strftime("%Y-%m-%d-%H:%M:%S")))

        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Performing dynamic analysis of crashes for {} job ID [{}]".format(
            self.job_token.type, job_id))

        if asan_crashes:
            if not self.analyze(job_rootdir, True):
               return False
        if harden_crashes:
            if not self.analyze(job_rootdir):
                return False
        return True

    def runtime_abtests(self):
        count = 0
        for rootdir, id in [('{}/{}'.format(self.job_token.rootdir, jobId), jobId) for jobId in self.job_token.jobids]:
            group = 'Config {}'.format(count)
            count += 1

            if not util.pprint_decorator_fargs(util.func_wrapper(self.analyze_wrapper, rootdir, id),
                                               'Analyzing crashes in {} group'.format(group), indent=2):
                return False

        return True

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting dynamic analysis of all crashes for"
                                                                  " job ID [{}]".format(self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                           "Checking Orthrus workspace", 2,
                                           'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        if self.job_token.type == 'abtests':
            return self.runtime_abtests()
        else:
            return self.analyze_wrapper(self.job_token.rootdir, self.job_token.id)