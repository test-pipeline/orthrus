'''
Orthrus stop implementation
'''
import os
import re
from orthrusutils import orthrusutils as util
from job import job as j

class OrthrusStop(object):
    def __init__(self, args, config, test=False):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
        self.routinedir = self.orthrusdir + j.ROUTINEDIR
        self.abtestsdir = self.orthrusdir + j.ABTESTSDIR
        self.test = test

    # NOTE: Supported for routine fuzzing jobs only
    def get_afl_cov_pid(self):
        pid_regex = re.compile(r'afl_cov_pid[^\d]+(?P<pid>\d+)')

        jobs_dir = self.routinedir
        jobs_list = os.walk(jobs_dir).next()[1]

        pids = []
        if not jobs_list:
            return pids
        for job in jobs_list:
            dir = jobs_dir + "/" + job + "/afl-out/cov"
            if not os.path.isdir(dir):
                continue
            file = dir + "/afl-cov-status"
            if not os.path.isfile(file):
                continue
            with open(file) as f:
                content = f.readline()
            match = pid_regex.match(content)
            if match:
                pids.append(match.groups()[0])
        return pids

    def kill_fuzzers_test(self):
        if self.job_token.type == 'routine':
            return util.run_cmd("pkill -15 afl-fuzz")
        else:
            for fuzzer in self.job_token.fuzzers:
                # FIXME: Silently failing
                if not util.run_cmd("pkill -15 {}".format(fuzzer)):
                    return True
        return True

    def run_helper(self):

        if self.test:
            if not util.pprint_decorator(self.kill_fuzzers_test, "Stopping {} job for ID [{}]".format(
                    self.job_token.type, self.job_token.id), indent=2):
                return False
        else:
            if not self.is_qemu:
                kill_cmd = ["afl-multikill -S HARDEN && afl-multikill -S ASAN"]
            else:
                kill_cmd = ["afl-multikill -S QEMU"]

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, kill_cmd),
                                               "Stopping {} job for ID [{}]".format(self.job_token.type,
                                                                                    self.job_token.id),
                                               indent=2):
                return False

        ## Kill afl-cov only for routine jobs
        if self._args.coverage and self.job_token.type == 'routine' and not self.is_qemu:
            util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Stopping afl-cov for {} job... ".
                                        format(self.job_token.type))
            for pid in self.get_afl_cov_pid():
                kill_aflcov_cmd = ["kill", "-15", pid]
                if not util.run_cmd(" ".join(kill_aflcov_cmd)):
                    return False
            util.color_print(util.bcolors.OKGREEN, "done")

        return True

    def run(self):

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Stopping fuzzers for job ID [{}]".
                         format(self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                           "Checking Orthrus workspace", 2,
                                           'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Stopping fuzzing jobs")
        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2):
            return False

        if self.job_token.type == 'routine' and self.job_token.qemus:
            self.is_qemu = True
        elif self.job_token.type == 'abtests' and (self.job_token.qemus[0] and self.job_token.qemus[1]):
            self.is_qemu = True
        else:
            self.is_qemu = False

        if self._args.coverage and self.is_qemu:
            util.color_print(util.bcolors.WARNING, "\t\t[-] You are trying to stop an afl-cov process that likely does"
                                                   " not exist since it appears you are fuzzing in qemu mode. Please "
                                                   "remove the -c option in the future.")

        return self.run_helper()