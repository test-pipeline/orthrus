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
import ConfigParser
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

        ## Verify instrumentation
        # sample_binpath = random.choice(glob.glob(install_path + 'bin/*'))
        sample_binpath = random.choice(util.return_elf_binaries(install_path + 'bin/'))

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

        if os.path.exists(self._config['orthrus']['directory'] + "binaries/afl-harden"):
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
    
    def _start_fuzzers(self, jobroot_dir, job_type):
        if os.listdir(jobroot_dir + "/afl-out/") == []:
            start_cmd = "start"
        else:
            start_cmd = "resume"

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

        if job_type == 'routine':
            core_per_subjob = self.total_cores / 2
            core_for_asan_only = self.total_cores
        else:
            core_per_subjob = self.total_cores / 4
            core_for_asan_only = self.total_cores / 2

        if core_per_subjob == 0:
            core_per_subjob = 1
            if job_type != 'routine':
                util.color_print(util.bcolors.WARNING, "\t\t\t[-] You do not have sufficient processor cores to carry"
                                                       " out a scientific a/b test. Consider a routine job instead.")

        self.check_core_pattern()

        env = os.environ.copy()
        env.update({'AFL_SKIP_CPUFREQ': '1'})

        if os.path.exists(self.orthrusdir + "/binaries/afl-harden"):

            harden_file = self.orthrusdir + "/logs/afl-harden.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/harden-job.conf",
                                           start_cmd, str(core_per_subjob), "-v"]

            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, harden_file),
                                               'Starting AFL harden fuzzer as master', indent=2):
                return False

            self.print_cmd_diag("/logs/afl-harden.log")
            
            if os.path.exists(self.orthrusdir + "/binaries/afl-asan"):
                asan_file = self.orthrusdir + "/logs/afl-asan.log"
                cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/asan-job.conf ", "add", \
                                str(core_per_subjob), "-v"]

                if not util.pprint_decorator_fargs(util.func_wrapper(util.run_cmd, " ".join(cmd), env, asan_file),
                                                   'Starting AFL ASAN fuzzer as slave', indent=2):
                    return False

                self.print_cmd_diag("/logs/afl-asan.log")

        elif os.path.exists(self.orthrusdir + "/binaries/afl-asan"):

            asan_file = self.orthrusdir + "/logs/afl-asan.log"
            cmd = ["afl-multicore", "--config={}".format(jobroot_dir) + "/asan-job.conf", start_cmd, \
                   str(core_for_asan_only), "-v"]

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
        if self._args.coverage and self.job_token.type == 'routine':
            if not util.pprint_decorator_fargs(util.func_wrapper(util.run_afl_cov, self.orthrusdir, rootdir,
                                                                self.job_token.target, self.job_token.params, True,
                                                                self.test),
                                               'Starting afl-cov for {} job ID [{}]'.format(self.job_token.type, id),
                                               indent=2):
                return False
        return True
        
    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting fuzzing jobs")

        self.job_token = j.jobtoken(self.orthrusdir, self._args.job_id)

        if not util.pprint_decorator(self.job_token.materialize, 'Retrieving job ID [{}]'.format(self.job_token.id),
                                     indent=2, fail_msg=self.fail_msg):
            return False

        self.total_cores = int(util.getnproc())
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

    def get_afl_cov_pid(self):
        pid_regex = re.compile(r'afl_cov_pid[^\d]+(?P<pid>\d+)')

        jobs_dir = self._config['orthrus']['directory'] + "/jobs"
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

    def opencov_abtests(self):

        control_sync = '{}/{}/afl-out'.format(self.job_token.rootdir, self.job_token.joba_id)
        exp_sync = '{}/{}/afl-out'.format(self.job_token.rootdir, self.job_token.jobb_id)

        if not self.opencov(control_sync, self.job_token.type, self.job_token.joba_id):
            return False
        if not self.opencov(exp_sync, self.job_token.type, self.job_token.jobb_id):
            return False
        return True

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

    # def whatsup_routine(self):
    #     for routine_job in self.routine_list:
    #         id = routine_job['id']
    #         target = routine_job['target']
    #         # params = routine_job['params']
    #         syncdir = '{}/{}/afl-out'.format(self.routinedir, id)
    #         util.color_print(util.bcolors.OKBLUE, "\tJob [" + id + "] " + "for target '" + target + "':")
    #         if not self.whatsup(syncdir):
    #             return False
    #     return True

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
            util.color_print(util.bcolors.OKGREEN, "\t[+] Opening A/B test coverage in new browser tabs")
            return self.opencov_abtests()

    def run(self):
        if self._args.job_id:
            if not self.show_job():
                return False
            if self._args.cov and not self.show_cov():
                return False
        elif self._args.conf:
            return self.show_conf()
        return True

    # def run(self):
    #     job_config = ConfigParser.ConfigParser()
    #     job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
    #     if self._args.jobs:
    #         util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Configured jobs found:")
    #         for num, section in enumerate(job_config.sections()):
    #             t = job_config.get(section, "target")
    #             p = job_config.get(section, "params")
    #             util.color_print(util.bcolors.OKGREEN, "\t" + str(num) + ") [" + section + "] " + t + " " + p)
    #     elif self._args.cov:
    #         for jobId in job_config.sections():
    #             cov_web_indexhtml = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/" + \
    #                                 "cov/web/index.html"
    #             if os.path.exists(cov_web_indexhtml):
    #                 util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Opening coverage html for job {} "
    #                                                                           "in a new browser tab".format(jobId))
    #                 # Early return for tests
    #                 if self.test:
    #                     return True
    #                 webbrowser.open_new_tab(cov_web_indexhtml)
    #             else:
    #                 util.color_print(util.bcolors.INFO, "No coverage info at {}. Have you run orthrus coverage or"
    #                                                     " orthrus start -c already?".format(cov_web_indexhtml))
    #                 return False
    #     else:
    #         util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Status of jobs:")
    #
    #         for jobId in job_config.sections():
    #             syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"
    #             try:
    #                 output = subprocess.check_output(["afl-whatsup", "-s", syncDir])
    #             except subprocess.CalledProcessError as e:
    #                 print e.output
    #                 return False
    #             output = output[output.find("==\n\n") + 4:]
    #
    #             util.color_print(util.bcolors.OKBLUE, "\tJob [" + jobId + "] " + "for target '" +
    #                              job_config.get(jobId, "target") + "':")
    #             for line in output.splitlines():
    #                 util.color_print(util.bcolors.OKBLUE, "\t" + line)
    #             triaged_unique = 0
    #             if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"):
    #                 triaged_unique = len(glob.glob(self._config['orthrus']['directory'] + "/jobs/" + jobId +
    #                                                "/unique/*id*sig*"))
    #             util.color_print(util.bcolors.OKBLUE, "\t     Triaged crashes : " + str(triaged_unique) + " available")
    #
    #     return True

class OrthrusTriage(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config

    def tidy(self, crash_dir):

        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Tidying crash dir...")

        dest = crash_dir + "/.scripts"
        if not os.path.exists(dest):
            os.mkdir(dest)

        for script in glob.glob(crash_dir + "/gdb_script*"):
            shutil.move(script, dest)

        util.color_print(util.bcolors.OKGREEN, "done!")
        return True

    def triage(self, jobId, inst, indir=None, outdir=None):
        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Collect and verify '{}' mode crashes... "
                                    .format(inst))

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
            syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"
        else:
            syncDir = indir

        if not outdir:
            dirname = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/exploitable/" + \
                      "{}/".format(prefix) + "crashes"
            if not os.path.exists(dirname):
                os.makedirs(dirname)
            triage_outDir = dirname
        else:
            triage_outDir = outdir

        logfile = self._config['orthrus']['directory'] + "/logs/" + "afl-{}_dbg.log".format(inst)
        launch = self._config['orthrus']['directory'] + "/binaries/{}-dbg/bin/".format(inst) + \
                 self.job_config.get(jobId, "target") + " " + \
                 self.job_config.get(jobId, "params").replace("&", "\&")
        cmd = " ".join(["afl-collect", "-r", "-j", util.getnproc(), "-e gdb_script",
                        syncDir, triage_outDir, "--", launch])
        rv = util.run_cmd("ulimit -c 0; " + cmd, env, logfile)
        if not rv:
            util.color_print(util.bcolors.FAIL, "failed")
            return rv

        util.color_print(util.bcolors.OKGREEN, "done")

        if not self.tidy(triage_outDir):
            return False

        return True

    def run(self):

        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Check Orthrus workspace... ")

        orthrus_root = self._config['orthrus']['directory']
        if not util.validate_job(orthrus_root, self._args.job_id):
            util.color_print(util.bcolors.FAIL, "failed. Are you sure you have done orthrus add --job or passed the "
                                                "right job ID. orthrus show -j might help")
            return False

        util.color_print(util.bcolors.OKGREEN, "done")
        self.job_config = ConfigParser.ConfigParser()
        self.job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
        jobId = self._args.job_id

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Triaging crashes for job [" \
                         + jobId + "]")

        if not os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"):
            os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/")
        else:
            util.color_print(util.bcolors.OKGREEN, "[?] Rerun triaging? [y/n]...: ")

            if 'y' not in sys.stdin.readline()[0]:
                return True

            shutil.move(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/",
                        self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique." \
                        + time.strftime("%Y-%m-%d-%H:%M:%S"))
            os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/")

        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
            if not self.triage(jobId, 'harden'):
                return False
        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-asan"):
            if not self.triage(jobId, 'asan'):
                return False

        #Second pass over all exploitable crashes
        exp_path = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/exploitable/"
        uniq_path = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"
        if os.path.exists(exp_path):
            if not self.triage(jobId, 'all', exp_path, uniq_path):
                return False

        triaged_crashes = os.listdir(uniq_path)
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Triaged " + str(len(triaged_crashes)) + \
                         " crashes. See {}".format(uniq_path))
        if not triaged_crashes:
            util.color_print(util.bcolors.OKBLUE, "\t\t[+] Nothing to do")
            return True

        return True

class OrthrusCoverage(object):

    def __init__(self, args, config):
        self._args = args
        self._config = config

    def run(self):

        util.color_print_singleline(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Checking test coverage for job [" \
                 + self._args.job_id + "]... ")
        orthrus_root = self._config['orthrus']['directory']
        if not util.validate_job(orthrus_root, self._args.job_id):
            util.color_print(util.bcolors.FAIL, "failed. Are you sure you have done orthrus add --job or passed the "
                                                "right job ID. orthrus show -j might help")
            return False

        jobId = self._args.job_id
        self.job_config = ConfigParser.ConfigParser()
        self.job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")


        util.run_afl_cov(orthrus_root, jobId, self.job_config.get(jobId, "target"),
                         self.job_config.get(jobId, "params"))

        util.color_print(util.bcolors.OKGREEN, "done")
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Please check {} for coverage info"
                         .format(orthrus_root+"/jobs/"+jobId+"/afl-out/""cov"))
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