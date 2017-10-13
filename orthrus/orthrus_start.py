'''
Orthrus start implementation
'''
import os
import subprocess
from orthrusutils import orthrusutils as util
from job import job as j

class OrthrusStart(object):
    def __init__(self, args, config, test=False):
        self._args = args
        self._config = config
        self.test = test
        self.orthrusdir = self._config['orthrus']['directory']
        self.fail_msg = "failed. Are you sure you have done orthrus add --job or passed the " \
                        "right job ID. orthrus show -j might help"
        self.is_harden = os.path.exists(self.orthrusdir + "/binaries/afl-harden")
        self.is_asan = os.path.exists(self.orthrusdir + "/binaries/afl-asan")
        self.is_qemu = os.path.exists(self.orthrusdir + "/binaries/afl-qemu")

    def check_core_pattern(self):
        cmd = ["cat /proc/sys/kernel/core_pattern"]
        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Checking core_pattern... ")
        try:
            if "core" not in subprocess.check_output(" ".join(cmd), shell=True, stderr=subprocess.STDOUT):
                util.color_print(util.bcolors.FAIL, "failed")
                util.color_print(util.bcolors.FAIL, "\t\t\t[-] Please do echo core | "
                                                    "sudo tee /proc/sys/kernel/core_pattern")
                return False
        except subprocess.CalledProcessError as e:
            print e.output
            return False
        util.color_print(util.bcolors.OKGREEN, "done")

    def print_cmd_diag(self, file):
        output = open(self.orthrusdir + file, "r")
        for line in output:
            if "Starting master" in line or "Starting slave" in line:
                util.color_print(util.bcolors.OKGREEN, "\t\t\t" + line)
            if " Master " in line or " Slave " in line:
                util.color_print_singleline(util.bcolors.OKGREEN, "\t\t\t\t" + "[+] " + line)
        output.close()

    def compute_cores_per_job(self, job_type):
        if job_type == 'routine':
            if self.is_harden and self.is_asan:
                self.core_per_subjob = self.total_cores / 2
            elif (self.is_harden and not self.is_asan) or (not self.is_harden and self.is_asan):
                self.core_per_subjob = self.total_cores
            elif self.is_qemu and not self.is_asan and not self.is_harden:
                self.core_per_subjob = self.total_cores
        else:
            if self.is_harden and self.is_asan:
                self.core_per_subjob = self.total_cores / (2 * self.job_token.num_jobs)
            elif (self.is_harden and not self.is_asan) or (not self.is_harden and self.is_asan):
                self.core_per_subjob = self.total_cores / self.job_token.num_jobs
            elif self.is_qemu and not self.is_asan and not self.is_harden:
                self.core_per_subjob = self.total_cores / self.job_token.num_jobs

    def _start_fuzzers(self, jobroot_dir, job_type):
        if os.listdir(jobroot_dir + "/afl-out/") == []:
            start_cmd = "start"
            add_cmd = "add"
        else:
            start_cmd = "resume"
            add_cmd = "resume"

        self.check_core_pattern()

        env = os.environ.copy()
        env.update({'AFL_SKIP_CPUFREQ': '1'})

        if self.is_harden and self.is_asan:
            harden_file = self.orthrusdir + "/logs/afl-harden.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/harden-job.conf",
                   start_cmd, str(self.core_per_subjob), "-v"]

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, harden_file),
                                               'Starting AFL harden fuzzer as master', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-harden.log")

            # if self.is_asan:
            asan_file = self.orthrusdir + "/logs/afl-asan.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/asan-job.conf ", add_cmd, \
                   str(self.core_per_subjob), "-v"]
            # This ensures SEGV crashes are named sig:11 and not sig:06
            # See: https://groups.google.com/forum/#!topic/afl-users/aklNGdKbpkI
            util.overrride_default_afl_asan_options(env)

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, asan_file),
                                               'Starting AFL ASAN fuzzer as slave', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-asan.log")

        elif (self.is_harden and not self.is_asan):
            harden_file = self.orthrusdir + "/logs/afl-harden.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/harden-job.conf",
                   start_cmd, str(self.core_per_subjob), "-v"]

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, harden_file),
                                               'Starting AFL harden fuzzer as master', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-harden.log")

        elif (not self.is_harden and self.is_asan):

            asan_file = self.orthrusdir + "/logs/afl-asan.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/asan-job.conf", start_cmd, \
                   str(self.core_per_subjob), "-v"]
            # This ensures SEGV crashes are named sig:11 and not sig:06
            # See: https://groups.google.com/forum/#!topic/afl-users/aklNGdKbpkI
            util.overrride_default_afl_asan_options(env)

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, asan_file),
                                               'Starting AFL ASAN fuzzer as master', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-asan.log")

        elif self.is_qemu:
            qemu_file = self.orthrusdir + "/logs/afl-qemu.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/qemu-job.conf", start_cmd, \
                   str(self.core_per_subjob), "-v"]

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, qemu_file),
                                               'Starting AFL QEMU fuzzer as master', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-qemu.log")

        return True

    def start_and_cover(self):

        for rootdir, id in zip(self.rootdirs, self.ids):
            if not util.pprint_decorator_fargs(util.func_wrapper(self._start_fuzzers, rootdir, self.job_token.type),
                                               'Starting fuzzer for {} job ID [{}]'.format(self.job_token.type, id),
                                               indent=2):
                try:
                    subprocess.call("pkill -9 afl-fuzz", shell=True, stderr=subprocess.STDOUT)
                except OSError, subprocess.CalledProcessError:
                    return False
                return False

            # Live coverage is only supported for routine jobs
            # To support live coverage for abtests jobs, we would need to create two code base dir each with a gcno file
            # set due to the way gcov works.
            if self._args.coverage:
                if self.job_token.type == 'routine':
                    if not self.job_token.qemus:
                        if not util.pprint_decorator_fargs(util.func_wrapper(util.run_afl_cov, self.orthrusdir, rootdir,
                                                                             self.job_token.target,
                                                                             self.job_token.params, True,
                                                                             self.test),
                                                           'Starting afl-cov for {} job ID [{}]'.format(
                                                               self.job_token.type, id),
                                                           indent=2):
                            return False
                    else:
                        util.color_print(util.bcolors.WARNING,
                                         "\t\t[+] Live coverage in afl-qemu mode is not supported at the"
                                         " moment")
                        return True
                else:
                    util.color_print(util.bcolors.WARNING, "\t\t[+] Live coverage for a/b tests is not supported at the"
                                                           " moment")
                    return True
        return True

    def min_and_reseed(self):

        for rootdir, id, qemu in zip(self.rootdirs, self.ids, self.qemus):
            if len(os.listdir(rootdir + "/afl-out/")) > 0:

                if not util.pprint_decorator_fargs(util.func_wrapper(util.minimize_and_reseed, self.orthrusdir, rootdir,
                                                                     id, self.job_token.target, self.job_token.params,
                                                                     qemu),
                                                   'Minimizing afl sync dir for {} job ID [{}]'.
                                                           format(self.job_token.type, id),
                                                   indent=2):
                    return False
        return True

    def run(self):

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting fuzzers for job ID [{}]".
                         format(self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                           "Checking Orthrus workspace", 2,
                                           'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

        if self.is_qemu:
            if not util.pprint_decorator_fargs((not (self.is_harden or self.is_asan)),
                                               "Checking sanity of configuration", 2,
                                               'failed. Running afl-qemu together with vanilla afl not supported!'):
                return False

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting fuzzing jobs")

        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        self.total_cores = self.job_token.num_cores

        '''
        n = number of cores
        Half the cores for AFL Harden (1 Master: n/2 - 1 slave)
        Half the cores for AFL ASAN (n/2 slaves)
        OR if asan only present
        1 AFL ASAN Master, n-1 AFL ASAN slaves

        In a/b test mode, each group has
        Half the cores for AFL Harden (1 Master: n/4 - 1 slave)
        Half the cores for AFL ASAN (n/4 slaves)
        OR if asan only present
        1 AFL ASAN Master, n/2 - 1 AFL ASAN slaves
        '''

        self.compute_cores_per_job(self.job_token.type)

        if self.core_per_subjob == 0:
            self.core_per_subjob = 1
            if self.job_token.type != 'routine':
                util.color_print(util.bcolors.WARNING, "\t\t\t[-] You do not have sufficient processor cores to carry"
                                                       " out a scientific a/b test. Consider a routine job instead.")

        self.rootdirs = []
        self.ids = []
        self.qemus = []

        if self.job_token.type == 'routine':
            self.rootdirs.append(self.job_token.rootdir)
            self.ids.append(self.job_token.id)
            self.qemus.append(self.job_token.qemus)
        else:
            self.rootdirs.extend(self.job_token.rootdir + '/{}'.format(id) for id in self.job_token.jobids)
            self.ids.extend(self.job_token.jobids)
            self.qemus.extend(self.job_token.qemus)

        if self._args.minimize:
            if not self.min_and_reseed():
                return False

        if not self.start_and_cover():
            return False

        return True