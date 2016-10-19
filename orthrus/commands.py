'''
Orthrus commands implementation
'''
import os
import sys
import shutil
import re
import subprocess
import random
import glob
import webbrowser
import tarfile
import time
import json
from orthrusutils import orthrusutils as util
from builder import builder as b
from job import job as j

class OrthrusCreate(object):

    def __init__(self, args, config):
        self.args = args
        self.config = config
        self.orthrusdirs = ['binaries', 'conf', 'logs', 'jobs', 'archive']
        self.fail_msg_bin = "Could not find ELF binaries. While we cannot guarantee " \
                            "that all libraries were instrumented correctly, they most likely were."

    def verifycmd(self, cmd):
        try:
            subprocess.check_output(cmd, shell=True)
        except subprocess.CalledProcessError:
            return False

        return True

    def verifyafl(self, binpath):
        cmd = ['objdump -t ' + binpath + ' | grep __afl_maybe_log']
        return self.verifycmd(cmd)

    def verifyasan(self, binpath):
        cmd = ['objdump -t ' + binpath + ' | grep __asan_get_shadow_mapping']
        return self.verifycmd(cmd)

    def verifycov(self, binpath):
        cmd = ['objdump -t ' + binpath + ' | grep gcov_write_block']
        return self.verifycmd(cmd)

    def verify(self, binpath, benv):

        if 'afl' in benv.cc and not self.verifyafl(binpath):
            return False
        if ('-fsanitize=address' in benv.cflags or 'AFL_USE_ASAN=1' in benv.misc) and not self.verifyasan(binpath):
            return False
        if '-ftest-coverage' in benv.cflags and not self.verifycov(binpath):
            return False

        return True

    def create(self, dest, BEnv, logfn):

        install_path = dest
        os.mkdir(install_path)

        ### Configure
        config_flags = ['--prefix=' + os.path.abspath(install_path)] + \
                       self.args.configure_flags.split(" ")

        builder = b.Builder(b.BuildEnv(BEnv),
                            config_flags,
                            self.config['orthrus']['directory'] + "/logs/" + logfn)

        if not util.pprint_decorator(builder.configure, 'Configuring', 2):
            return False


        ### Make install
        if not util.pprint_decorator(builder.make_install, 'Compiling', 2):
            return False

        util.copy_binaries(install_path + "bin/")

        # Fixes https://github.com/test-pipeline/orthrus/issues/1
        # Soft fail when no ELF binaries found.
        binary_paths = util.return_elf_binaries(install_path + 'bin/')
        if not util.pprint_decorator_fargs(binary_paths, 'Looking for ELF binaries', 2, fail_msg=self.fail_msg_bin):
            return True

        sample_binpath = random.choice(binary_paths)

        if not util.pprint_decorator_fargs(util.func_wrapper(self.verify, sample_binpath, BEnv),
                                     'Verifying instrumentation', 2):
            return False

        return True

    def run(self):

        if os.path.exists(self.config['orthrus']['directory']):
            util.color_print(util.bcolors.ERROR, "Error: Orthrus workspace already exists!")
            return False

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Create Orthrus workspace")
        
        os.mkdir(self.config['orthrus']['directory'])
        dirs = ['/{}/'.format(x) for x in self.orthrusdirs]
        map(lambda x: os.mkdir(self.config['orthrus']['directory'] + x), dirs)

        # AFL-ASAN
        if self.args.afl_asan:

            ### Prepare
            util.color_print(util.bcolors.HEADER,
                             "\t[+] Installing binaries for afl-fuzz with AddressSanitizer")
            install_path = self.config['orthrus']['directory'] + "/binaries/afl-asan/"
            if not self.create(install_path, b.BuildEnv.BEnv_afl_asan, 'afl-asan_inst.log'):
                return False

            #
            # ASAN Debug 
            #
            util.color_print(util.bcolors.HEADER,
                             "\t[+] Installing binaries for debug with AddressSanitizer")
            install_path = self.config['orthrus']['directory'] + "/binaries/asan-dbg/"
            if not self.create(install_path, b.BuildEnv.BEnv_asan_debug, 'afl-asan_dbg.log'):
                return False

        ### AFL-HARDEN
        if self.args.afl_harden:
            util.color_print(util.bcolors.HEADER,
                             "\t[+] Installing binaries for afl-fuzz in harden mode")
            install_path = self.config['orthrus']['directory'] + "/binaries/afl-harden/"
            if not self.create(install_path, b.BuildEnv.BEnv_afl_harden, 'afl_harden.log'):
                return False

            #
            # Harden Debug 
            #
            util.color_print(util.bcolors.HEADER,
                             "\t[+] Installing binaries for debug in harden mode")
            install_path = self.config['orthrus']['directory'] + "/binaries/harden-dbg/"
            if not self.create(install_path, b.BuildEnv.BEnv_harden_debug, 'afl_harden_dbg.log'):
                return False

        ### Coverage
        if self.args.coverage:
            util.color_print(util.bcolors.HEADER, "\t[+] Installing binaries for obtaining test coverage information")
            install_path = self.config['orthrus']['directory'] + "/binaries/coverage/"
            if not self.create(install_path, b.BuildEnv.BEnv_coverage, 'gcc_coverage.log'):
                return False

        return True

class OrthrusAdd(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']

    def copy_samples(self, jobroot_dir):
        samplevalid = False

        if os.path.isdir(self._args.sample):
            for dirpath, dirnames, filenames in os.walk(self._args.sample):
                for fn in filenames:
                    fpath = os.path.join(dirpath, fn)
                    if os.path.isfile(fpath):
                        shutil.copy(fpath, jobroot_dir + "/afl-in/")
            if filenames:
                samplevalid = True
        elif os.path.isfile(self._args.sample):
            samplevalid = True
            shutil.copy(self._args.sample, jobroot_dir + "/afl-in/")

        if not samplevalid:
            return False

        return True

    def seed_job(self, rootdir, id):

        if not util.pprint_decorator_fargs(util.func_wrapper(self.copy_samples, rootdir),
                                          'Adding initial samples for job ID [{}]'.format(id), 2,
                                          'seed dir or file invalid. No seeds copied'):
            return False

        return True

    def write_asan_config(self, afl_in, afl_out, jobroot_dir, fuzzer=None, fuzzer_params=None):

        ## Create an afl-utils JSON config for AFL-ASAN fuzzing setting it as slave if AFL-HARDEN target exists
        asanjob_config = {}
        asanjob_config['input'] = afl_in
        asanjob_config['output'] = afl_out
        asanjob_config['target'] = ".orthrus/binaries/afl-asan/bin/{}".format(self.job.target)
        asanjob_config['cmdline'] = self.job.params
        # asanjob_config['file'] = "@@"
        # asanjob_config.set("afl.ctrl", "file", ".orthrus/jobs/" + self.jobId + "/afl-out/.cur_input_asan")
        asanjob_config['timeout'] = "3000+"

        # See: https://github.com/mirrorer/afl/blob/master/docs/notes_for_asan.txt
        if util.is64bit():
            asanjob_config['mem_limit'] = "30000000"
        else:
            asanjob_config['mem_limit'] = "800"

        asanjob_config['session'] = "SESSION"
        # https://github.com/rc0r/afl-utils/issues/34
        # asanjob_config['interactive'] = False

        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
            asanjob_config['slave_only'] = True

        if fuzzer:
            asanjob_config['fuzzer'] = fuzzer

        if fuzzer_params:
            asanjob_config['afl_margs'] = fuzzer_params

        self.write_config(asanjob_config, "{}/asan-job.conf".format(jobroot_dir))

    def write_harden_config(self, afl_in, afl_out, jobroot_dir, fuzzer=None, fuzzer_params=None):
        ## Create an afl-utils JSON config for AFL-HARDEN
        hardenjob_config = {}
        hardenjob_config['input'] = afl_in
        hardenjob_config['output'] = afl_out
        hardenjob_config['target'] = ".orthrus/binaries/afl-harden/bin/{}".format(self.job.target)
        hardenjob_config['cmdline'] = self.job.params
        # hardenjob_config['file'] = "@@"
        hardenjob_config['timeout'] = "3000+"
        hardenjob_config['mem_limit'] = "800"
        hardenjob_config['session'] = "SESSION"
        # hardenjob_config['interactive'] = False

        if fuzzer:
            hardenjob_config['fuzzer'] = fuzzer

        if fuzzer_params:
            hardenjob_config['afl_margs'] = fuzzer_params

        self.write_config(hardenjob_config, "{}/harden-job.conf".format(jobroot_dir))

    def write_config(self, config_dict, config_file):
        with open(config_file, 'wb') as file:
            json.dump(config_dict, file, indent=4)

    def config_wrapper(self, afl_in, afl_out, jobroot_dir, fuzzer=None, fuzzer_params=None):
        self.write_asan_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
        self.write_harden_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
        return True

    def config_job(self, rootdir, id, fuzzer=None, fuzzer_params=None):
        afl_dirs = [rootdir + '/{}'.format(dirname) for dirname in ['afl-in', 'afl-out']]

        for dir in afl_dirs:
            os.mkdir(dir)

        # HT: http://stackoverflow.com/a/13694053/4712439
        if not util.pprint_decorator_fargs(util.func_wrapper(self.config_wrapper, afl_dirs[0], afl_dirs[1],
                                                             rootdir, fuzzer, fuzzer_params),
                                           'Configuring {} job for ID [{}]'.format(self.jobtype, id), 2):
            return False

        return True

    def extract_job(self, jobroot_dir):
        next_session = 0

        if not tarfile.is_tarfile(self._args._import):
            return False

        if not os.path.exists(jobroot_dir + "/afl-out/"):
            return False

        syncDir = os.listdir(jobroot_dir + "/afl-out/")
        for directory in syncDir:
            if "SESSION" in directory:
                next_session += 1

        is_single = True
        with tarfile.open(self._args._import, "r") as tar:
            try:
                info = tar.getmember("fuzzer_stats")
            except KeyError:
                is_single = False

            if is_single:
                outDir = jobroot_dir + "/afl-out/SESSION" + "{:03d}".format(next_session)
                os.mkdir(outDir)
                tar.extractall(outDir)
            else:
                tmpDir = jobroot_dir + "/tmp/"
                os.mkdir(tmpDir)
                tar.extractall(tmpDir)
                for directory in os.listdir(jobroot_dir + "/tmp/"):
                    outDir = jobroot_dir + '/afl-out/'
                    shutil.move(tmpDir + directory, outDir)
                shutil.rmtree(tmpDir)

        return True

    def import_job(self, rootdir, id, target, params):

        if not util.pprint_decorator_fargs(util.func_wrapper(self.extract_job, rootdir),
                                           'Importing afl sync dir for job ID [{}]'.format(id),
                                           indent=2):
            return False

        util.minimize_sync_dir(self.orthrusdir, rootdir, id, target, params)
        return True

    def run_helper(self, rootdir, id, fuzzer, fuzzer_param):
        if not self.config_job(rootdir, id, fuzzer, fuzzer_param):
            return False
        if self._args._import and not self.import_job(rootdir, id, self.job.target, self.job.params):
            return False
        if self._args.sample and not self.seed_job(rootdir, id):
            return False

        return True

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Adding fuzzing job to Orthrus workspace")


        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir + "/binaries/"),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you did orthrus create -asan or -fuzz'):
            return False

        if self._args.abconf:
            self.jobtype = 'abtests'
        else:
            self.jobtype = 'routine'

        self.job = j.job(self._args.job, self.jobtype, self.orthrusdir, self._args.abconf)

        self.rootdirs = []
        self.ids = []
        self.fuzzers = []
        self.fuzzer_param = []

        if not util.pprint_decorator(self.job.materialize, 'Adding {} job'.format(self.jobtype), 2,
                                     'Invalid a/b test configuration or existing job found!'):
            return False

        if self.jobtype == 'routine':
            self.rootdirs.append(self.job.rootdir)
            self.ids.append(self.job.id)
            self.fuzzers.append(None)
            self.fuzzer_param.append(None)
        else:
            self.rootdirs.extend((self.job.rootdir + '/{}'.format(self.job.joba_id),
                                  self.job.rootdir + '/{}'.format(self.job.jobb_id)))
            self.ids.extend((self.job.joba_id, self.job.jobb_id))
            self.fuzzers.extend((self.job.fuzzerA, self.job.fuzzerB))
            self.fuzzer_param.extend((self.job.fuzzerA_args, self.job.fuzzerB_args))

        for rootdir, id, fuzzer, fuzzer_param in zip(self.rootdirs, self.ids, self.fuzzers, self.fuzzer_param):
            if not self.run_helper(rootdir, id, fuzzer, fuzzer_param):
                return False
        return True

class OrthrusRemove(object):

    fail_msg = "failed. Are you sure you have done orthrus add --job or passed the " \
               "right job ID. orthrus show -j might help"
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
    
    def run(self):

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Removing fuzzing job from Orthrus workspace")

        job_token = j.jobtoken(self.orthrusdir, self._args.job_id)
        if not util.pprint_decorator(job_token.materialize, 'Retrieving job [{}]'.format(job_token.id), indent=2,
                                     fail_msg=self.fail_msg):
            return False

        if not util.pprint_decorator_fargs(util.func_wrapper(shutil.move,
                                                             self.orthrusdir + "/jobs/{}/{}".format(job_token.type,
                                                                                                   job_token.id),
                                                             self.orthrusdir + "/archive/" +
                                                                    time.strftime("%Y-%m-%d-%H:%M:%S") + "-"
                                                                    + job_token.id),
                                           'Archiving data for {} job [{}]'.format(job_token.type,job_token.id),
                                           indent=2):
            return False

        j.remove_id_from_conf(job_token.jobsconf, job_token.id, job_token.type)
        return True

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
        else:
            if self.is_harden and self.is_asan:
                self.core_per_subjob = self.total_cores / 4
            elif (self.is_harden and not self.is_asan) or (not self.is_harden and self.is_asan):
                self.core_per_subjob = self.total_cores / 2

    def _start_fuzzers(self, jobroot_dir, job_type):
        if os.listdir(jobroot_dir + "/afl-out/") == []:
            start_cmd = "start"
        else:
            start_cmd = "resume"

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
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/asan-job.conf ", "add", \
                   str(self.core_per_subjob), "-v"]

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

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, asan_file),
                                               'Starting AFL ASAN fuzzer as master', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-asan.log")

        return True
    
    def run_helper(self, rootdir, id):
        if len(os.listdir(rootdir + "/afl-out/")) > 0 and self._args.minimize:

            if not util.pprint_decorator_fargs(util.func_wrapper(util.minimize_sync_dir, self.orthrusdir, rootdir,
                                                                 id, self.job_token.target, self.job_token.params),
                                               'Minimizing afl sync dir for {} job ID [{}]'.
                                                       format(self.job_token.type,id),
                                               indent=2):
                return False

        if not util.pprint_decorator_fargs(util.func_wrapper(self._start_fuzzers, rootdir, self.job_token.type),
                                           'Starting fuzzer for {} job ID [{}]'.format(self.job_token.type,id),
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
                if not util.pprint_decorator_fargs(util.func_wrapper(util.run_afl_cov, self.orthrusdir, rootdir,
                                                                    self.job_token.target, self.job_token.params, True,
                                                                    self.test),
                                                   'Starting afl-cov for {} job ID [{}]'.format(self.job_token.type, id),
                                                   indent=2):
                    return False
            else:
                util.color_print(util.bcolors.WARNING, "\t\t[+] Live coverage for a/b tests is not supported at the"
                                                       " moment")
                return True
        return True
        
    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting fuzzing jobs")

        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        self.total_cores = int(util.getnproc())

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

        if self.job_token.type == 'routine':
            self.rootdirs.append(self.job_token.rootdir)
            self.ids.append(self.job_token.id)
        else:
            self.rootdirs.extend((self.job_token.rootdir + '/{}'.format(self.job_token.joba_id),
                                 self.job_token.rootdir + '/{}'.format(self.job_token.jobb_id)))
            self.ids.extend((self.job_token.joba_id, self.job_token.jobb_id))

        for rootdir, id in zip(self.rootdirs, self.ids):
            if not self.run_helper(rootdir, id):
                return False

        return True
    
class OrthrusStop(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
        self.routinedir = self.orthrusdir + j.ROUTINEDIR
        self.abtestsdir = self.orthrusdir + j.ABTESTSDIR

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

    def run_helper(self):
        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Stopping {} job for ID [{}]... ".
                         format(self.job_token.type, self.job_token.id))

        try:
            ## Kill all fuzzers
            kill_fuzz_cmd = ["pkill", "-9"]
            if self.job_token.type == 'routine':
                kill_fuzz_cmd.append("afl-fuzz")
                util.run_cmd(" ".join(kill_fuzz_cmd))
            else:
                for fuzzer in [self.job_token.fuzzerA, self.job_token.fuzzerB]:
                    util.run_cmd(" ".join(kill_fuzz_cmd + [fuzzer]))

            util.color_print(util.bcolors.OKGREEN, "done")

            ## Kill afl-cov only for routine jobs
            if self._args.coverage and self.job_token.type == 'routine':
                util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Stopping afl-cov for {} job... ".
                                            format(self.job_token.type))
                for pid in self.get_afl_cov_pid():
                    kill_aflcov_cmd = ["kill", "-9", pid]
                    util.run_cmd(" ".join(kill_aflcov_cmd))
                util.color_print(util.bcolors.OKGREEN, "done")
        except:
            return False
        return True

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Stopping fuzzing jobs")
        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2):
            return False

        return self.run_helper()

class OrthrusShow(object):
    
    def __init__(self, args, config, test=False):
        self._args = args
        self._config = config
        self.test = test
        self.orthrusdir = self._config['orthrus']['directory']
        self.jobsconf = self.orthrusdir + j.JOBCONF
        self.routinedir = self.orthrusdir + j.ROUTINEDIR
        self.abtestsdir = self.orthrusdir + j.ABTESTSDIR
        self.fail_msg = "No coverage info found. Have you run orthrus coverage or" \
                                                " orthrus start -c already?"

    def opencov(self, syncDir, job_type, job_id):
        cov_web_indexhtml = syncDir + "/cov/web/index.html"

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, cov_web_indexhtml),
                                       'Opening coverage html for {} job ID [{}]'.format(job_type, job_id),
                                       indent=2, fail_msg=self.fail_msg):
            return False

        if self.test:
            return True

        webbrowser.open_new_tab(cov_web_indexhtml)
        return True

    # TODO: Add feature
    # def opencov_abtests(self):
    #
    #     control_sync = '{}/{}/afl-out'.format(self.job_token.rootdir, self.job_token.joba_id)
    #     exp_sync = '{}/{}/afl-out'.format(self.job_token.rootdir, self.job_token.jobb_id)
    #
    #     if not self.opencov(control_sync, self.job_token.type, self.job_token.joba_id):
    #         return False
    #     if not self.opencov(exp_sync, self.job_token.type, self.job_token.jobb_id):
    #         return False
    #     return True

    def whatsup(self, syncDir):
        try:
            output = subprocess.check_output(["afl-whatsup", "-s", syncDir])
        except subprocess.CalledProcessError as e:
            print e.output
            return False
        output = output[output.find("==\n\n") + 4:]

        for line in output.splitlines():
            util.color_print(util.bcolors.OKBLUE, "\t" + line)
        triaged_unique = 0

        unique_dir = syncDir + "../unique"
        if os.path.exists(unique_dir):
            triaged_unique = len(glob.glob(unique_dir + "/*id*sig*"))
        util.color_print(util.bcolors.OKBLUE, "\t     Triaged crashes : " + str(triaged_unique))
        return True

    def whatsup_abtests(self, control_sync, exp_sync):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "A/B test status")
        util.color_print(util.bcolors.OKBLUE, "Control group")
        if not self.whatsup(control_sync):
            return False
        util.color_print(util.bcolors.OKBLUE, "Experiment group")
        if not self.whatsup(exp_sync):
            return False
        return True


    def show_job(self):
        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2):
            return False

        if self.job_token.type == 'routine':
            return self.whatsup('{}/afl-out'.format(self.job_token.rootdir))
        else:
            return self.whatsup_abtests('{}/{}/afl-out'.format(self.job_token.rootdir, self.job_token.joba_id),
                                        '{}/{}/afl-out'.format(self.job_token.rootdir, self.job_token.jobb_id))

    def show_conf(self):
        with open(self.jobsconf, 'r') as jobconf_fp:
            jobsconf_dict = json.load(jobconf_fp)

        self.routine_list = jobsconf_dict['routine']
        self.abtest_list = jobsconf_dict['abtests']
        # self.routine_syncdirs = ['{}/{}'.format(self.routinedir,item['id']) for item in self.routine_list]
        # self.abtest_rootdirs = ['{}/{}'.format(self.abtestsdir,item['id']) for item in self.abtest_list]

        for idx, routine in enumerate(self.routine_list):
            util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Configured routine jobs:")
            util.color_print(util.bcolors.OKBLUE, "\t" + str(idx) + ") [" + routine['id'] + "] " +
                             routine['target'] + " " + routine['params'])
        for idx, abtest in enumerate(self.abtest_list):
            util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Configured a/b tests:")
            util.color_print(util.bcolors.OKBLUE, "\t" + str(idx) + ") [" + abtest['id'] + "] " +
                             abtest['target'] + " " + abtest['params'])
            util.color_print(util.bcolors.OKBLUE, "\t" + "Control group")
            util.color_print(util.bcolors.OKBLUE, "\t" + "Fuzzer A: {}\t Fuzzer A args: {}".
                             format(abtest['fuzzerA'],abtest['fuzzerA_args']))
            util.color_print(util.bcolors.OKBLUE, "\t" + "Experiment group")
            util.color_print(util.bcolors.OKBLUE, "\t" + "Fuzzer B: {}\t Fuzzer B args: {}".
                             format(abtest['fuzzerB'],abtest['fuzzerB_args']))
        return True

    def show_cov(self):
        # We have already processed the job
        if self.job_token.type == 'routine':
            util.color_print(util.bcolors.OKGREEN, "\t[+] Opening coverage in new browser tabs")
            return self.opencov('{}/afl-out'.format(self.job_token.rootdir), self.job_token.type, self.job_token.id)
        else:
            util.color_print(util.bcolors.WARNING, "\t[+] Coverage interface for A/B tests is not supported at the "
                                                   "moment")
            return True
            # util.color_print(util.bcolors.OKGREEN, "\t[+] Opening A/B test coverage in new browser tabs")
            # return self.opencov_abtests()

    def run(self):
        if self._args.job_id:
            if not self.show_job():
                return False
            if self._args.cov and not self.show_cov():
                return False
        elif self._args.conf:
            return self.show_conf()
        return True

class OrthrusTriage(object):
    
    def __init__(self, args, config, test=False):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']
        self.fail_msg = "failed. Are you sure you have done orthrus add --job or passed the " \
                         "right job ID? orthrus show -j might help."
        self.is_harden = os.path.exists(self.orthrusdir + "/binaries/afl-harden")
        self.is_asan = os.path.exists(self.orthrusdir + "/binaries/afl-asan")
        self.jobsconf = self.orthrusdir + j.JOBCONF
        self.routinedir = self.orthrusdir + j.ROUTINEDIR
        self.abtestsdir = self.orthrusdir + j.ABTESTSDIR
        self.test = test

    def tidy(self, crash_dir):

        dest = crash_dir + "/.scripts"
        if not os.path.exists(dest):
            os.mkdir(dest)

        for script in glob.glob(crash_dir + "/gdb_script*"):
            shutil.move(script, dest)

        return True

    def triage(self, jobroot_dir, inst, indir=None, outdir=None):
        env = os.environ.copy()
        asan_flag = {}
        asan_flag['ASAN_OPTIONS'] = "abort_on_error=1:disable_coredump=1:symbolize=1"
        env.update(asan_flag)

        if inst is 'harden':
            prefix = 'HARDEN'
        elif inst is 'asan' or inst is 'all':
            prefix = 'ASAN'
            inst = 'asan'
        else:
            util.color_print(util.bcolors.FAIL, "failed!")
            return False

        if not indir:
            syncDir = jobroot_dir + "/afl-out/"
        else:
            syncDir = indir

        if not outdir:
            dirname = jobroot_dir + "/exploitable/" + "{}/".format(prefix) + "crashes"
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            triage_outDir = dirname
        else:
            triage_outDir = outdir

        logfile = self.orthrusdir + "/logs/" + "afl-{}_dbg.log".format(inst)
        launch = self.orthrusdir + "/binaries/{}-dbg/bin/".format(inst) + \
                 self.job_token.target + " " + \
                 self.job_token.params.replace("&", "\&")
        cmd = " ".join(["afl-collect", "-r", "-j", util.getnproc(), "-e gdb_script",
                        syncDir, triage_outDir, "--", launch])

        if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, "ulimit -c 0; " + cmd, env, logfile),
                                           'Triaging {} job ID [{}]'.format(self.job_token.type, self.job_token.id),
                                           indent=2):
            return False

        if not util.pprint_decorator_fargs(util.func_wrapper(self.tidy, triage_outDir), 'Tidying crash dir',
                                           indent=2):
            return False

        return True

    def prepare_for_rerun(self, jobroot_dir):
        util.color_print(util.bcolors.OKGREEN, "[?] Rerun triaging? [y/n]...: ")

        if not self.test and 'y' not in sys.stdin.readline()[0]:
            return False

        shutil.move(jobroot_dir + "/unique/", jobroot_dir + "/unique." + time.strftime("%Y-%m-%d-%H:%M:%S"))
        os.mkdir(jobroot_dir + "/unique/")
        return True

    def make_unique_dirs(self, jobroot_dir):
        unique_dir = '{}/unique'.format(jobroot_dir)
        if not os.path.exists(unique_dir):
            os.mkdir(unique_dir)
            return True
        else:
            return False

    def triage_wrapper(self, jobroot_dir, job_id):
        if not self.make_unique_dirs(jobroot_dir) and not self.prepare_for_rerun(jobroot_dir):
            return False


        if self.is_harden:
            if not util.pprint_decorator_fargs(util.func_wrapper(self.triage, jobroot_dir, 'harden'),
                                               'Triaging harden mode crashes for {} job ID [{}]'.format(
                                                   self.job_token.type, job_id), indent=2):
                return False

        if self.is_asan:
            if not util.pprint_decorator_fargs(util.func_wrapper(self.triage, jobroot_dir, 'asan'),
                                               'Triaging asan mode crashes for {} job ID [{}]'.format(
                                                   self.job_token.type, job_id), indent=2):
                return False

        #Second pass over all exploitable crashes
        exp_path = jobroot_dir + "/exploitable/"
        uniq_path = jobroot_dir + "/unique/"
        if os.path.exists(exp_path):
            if not util.pprint_decorator_fargs(util.func_wrapper(self.triage, jobroot_dir, 'all', exp_path,
                                                                 uniq_path),
                                               'Triaging all mode crashes for {} job ID [{}]'.format(
                                                   self.job_token.type, job_id), indent=2):
                return False

        triaged_crashes = glob.glob(uniq_path + "*id*sig*")
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Triaged " + str(len(triaged_crashes)) + \
                         " crashes. See {}".format(uniq_path))
        if not triaged_crashes:
            util.color_print(util.bcolors.OKBLUE, "\t\t[+] Nothing to do")
            return True

        return True

    def triage_abtests(self):
        for rootdir,id in [('{}/{}'.format(self.job_token.rootdir, jobId), jobId) for jobId in [self.job_token.joba_id,
                                                                                    self.job_token.jobb_id]]:
            if id == self.job_token.joba_id:
                group = 'control'
            else:
                group = 'experiment'

            if not util.pprint_decorator_fargs(util.func_wrapper(self.triage_wrapper, rootdir, id),
                                               'Triaging crashes in {} group'.format(group), indent=2):
                return False

        return True

    def run(self):
        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Triaging crashes for {} job ID [{}]".format(
            self.job_token.type, self.job_token.id))

        if self.job_token.type == 'routine':
            return self.triage_wrapper(self.job_token.rootdir, self.job_token.id)
            # return self.triage_routine()
        else:
            return self.triage_abtests()

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

class OrthrusDestroy(object):
    
    def __init__(self, args, config, testinput=None):
        self._args = args
        self._config = config
        self.testinput = testinput
    
    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Destroy Orthrus workspace")
        util.color_print_singleline(util.bcolors.BOLD + util.bcolors.HEADER, "[?] Delete complete workspace? [y/n]...: ")

        if (self.testinput and 'y' in self.testinput) or 'y' in sys.stdin.readline()[0]:
            util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Deleting all files... ")
            if not os.path.exists(self._config['orthrus']['directory']):
                util.color_print(util.bcolors.OKBLUE, "destroyed already")
            else:
                shutil.rmtree(self._config['orthrus']['directory'])
                if not os.path.isdir(self._config['orthrus']['directory']):
                    util.color_print(util.bcolors.OKGREEN, "done")
                else:
                    util.color_print(util.bcolors.FAIL, "failed")
                    return False
        return True

class OrthrusValidate(object):

    def __init__(self, args, config):
        self._args = args
        self._config = config

    def get_on(self):
        return [item for item in self._config['dependencies'] if item[1] == 'on']

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Validating Orthrus dependencies")
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] The following programs have been marked as required in " \
                                               "~/.orthrus/orthrus.conf")
        for prog, _ in self.get_on():
            util.color_print(util.bcolors.OKGREEN, "\t\t\t[+] {}".format(prog))

        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Checking if requirements are met.")
        if not util.validate_inst(self._config):
            return False
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] All requirements met. Orthrus is ready for use!")
        return True