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
import string
from orthrusutils import orthrusutils as util
from builder import builder as b
from job import job as j
from spectrum.afl_sancov import AFLSancovReporter
from runtime.runtime import RuntimeAnalyzer

class OrthrusCreate(object):

    def __init__(self, args, config, test=False):
        self.args = args
        self.config = config
        self.test = test
        self.orthrusdir = self.config['orthrus']['directory']
        self.orthrus_subdirs = ['binaries', 'conf', 'logs', 'jobs', 'archive']
        self.fail_msg_bin = "Could not find ELF binaries. While we cannot guarantee " \
                            "that all libraries were instrumented correctly, they most likely were."

    def archive(self):

        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[?] Rerun create? [y/n]...: ")

        if not self.test and 'y' not in sys.stdin.readline()[0]:
            return False

        if not util.pprint_decorator_fargs(util.func_wrapper(shutil.move, '{}/binaries'.format(self.orthrusdir),
                                            '{}/archive/binaries.{}'.format(self.orthrusdir,
                                                                            time.strftime("%Y-%m-%d-%H:%M:%S"))),
                                           'Archiving binaries to {}/archive'.format(self.orthrusdir), indent=2):
            return False
        return True

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

    def verifyubsan(self, binpath):
        cmd = ['objdump -t ' + binpath + ' | grep ubsan_init']
        return self.verifycmd(cmd)

    def verify_gcccov(self, binpath):
        cmd = ['objdump -t ' + binpath + ' | grep gcov_write_block']
        return self.verifycmd(cmd)

    def verify_sancov(self, binpath):
        cmd = ['objdump -t ' + binpath + ' | grep __sanitizer_cov_module_init']
        return self.verifycmd(cmd)

    def verify_asancov(self, binpath):
        if not (self.verifyasan(binpath) and self.verify_sancov(binpath)):
            return False
        return True

    def verify_ubsancov(self, binpath):
        if not (self.verifyubsan(binpath) and self.verify_sancov(binpath)):
            return False
        return True

    def verify(self, binpath, benv):

        if 'afl' in benv.cc and not self.verifyafl(binpath):
            return False
        if ('-fsanitize=address' in benv.cflags or 'AFL_USE_ASAN=1' in benv.misc) and not self.verifyasan(binpath):
            return False
        if '-ftest-coverage' in benv.cflags and not self.verify_gcccov(binpath):
            return False
        if '-fsanitize-coverage' in benv.cflags and '-fsanitize=address' in benv.cflags and not self.verify_asancov(binpath):
            return False
        if '-fsanitize-coverage' in benv.cflags and '-fsanitize=undefined' in benv.cflags and not self.verify_ubsancov(binpath):
            return False

        return True

    def create(self, dest, BEnv, logfn, gendict=False):

        if not gendict:
            install_path = dest
            util.mkdir_p(install_path)

            ### Configure
            config_flags = ['--prefix=' + os.path.abspath(install_path)] + \
                           self.args.configure_flags.split(" ")
        else:
            config_flags = self.args.configure_flags.split(" ")

        builder = b.Builder(b.BuildEnv(BEnv),
                            config_flags,
                            self.config['orthrus']['directory'] + "/logs/" + logfn)

        if not util.pprint_decorator(builder.configure, 'Configuring', 2):
            return False


        ### Make install
        if not gendict:
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
        else:
            if not util.pprint_decorator(builder.clang_sdict, 'Creating input dict via clang-sdict', 2):
                return False

        return True

    def run(self):

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Creating Orthrus workspace")

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.config['orthrus']['directory']) is False,
                                           'Checking if workspace exists', indent=2,
                                           fail_msg='yes'):
            if not self.archive():
                return False

        util.mkdir_p(self.config['orthrus']['directory'])
        dirs = ['/{}/'.format(x) for x in self.orthrus_subdirs]
        map(lambda x: util.mkdir_p(self.config['orthrus']['directory'] + x), dirs)

        # AFL-ASAN
        if self.args.afl_asan:
            install_path = self.config['orthrus']['directory'] + "/binaries/afl-asan/"

            if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_afl_asan,
                                                                 'afl-asan_inst.log'),
                                               'Installing binaries for afl-fuzz with AddressSanitizer',
                                               indent=1):
                return False

            #
            # ASAN Debug 
            #
            install_path = self.config['orthrus']['directory'] + "/binaries/asan-dbg/"
            if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_asan_debug,
                                                                 'afl-asan_dbg.log'),
                                               'Installing binaries for debug with AddressSanitizer',
                                               indent=1):
                return False
        # AFL-ASAN-BLACKLIST
        elif self.args.afl_asan_blacklist:

            install_path = self.config['orthrus']['directory'] + "/binaries/afl-asan/"

            is_blacklist = os.path.exists('asan_blacklist.txt')
            if not util.pprint_decorator_fargs(is_blacklist, 'Checking if asan_blacklist.txt exists',
                                               indent=2):
                return False

            if not util.pprint_decorator_fargs(
                    util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_afl_asan_blacklist,
                                      'afl-asan_inst.log'),
                    'Installing binaries for afl-fuzz with AddressSanitizer (blacklist)',
                    indent=1):
                return False

            #
            # ASAN Debug
            #
            install_path = self.config['orthrus']['directory'] + "/binaries/asan-dbg/"
            if not util.pprint_decorator_fargs(
                    util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_asan_debug_blacklist,
                                      'afl-asan_dbg.log'),
                    'Installing binaries for debug with AddressSanitizer (blacklist)',
                    indent=1):
                return False

        ### AFL-HARDEN
        if self.args.afl_harden:

            install_path = self.config['orthrus']['directory'] + "/binaries/afl-harden/"
            if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_afl_harden,
                                                                 'afl_harden.log'),
                                               'Installing binaries for afl-fuzz in harden mode',
                                               indent=1):
                if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path,
                                                                     b.BuildEnv.BEnv_afl_harden_softfail,
                                                                    'afl-harden_soft.log'),
                                                'Retrying without the (sometimes problematic) AFL_HARDEN=1 setting',
                                                indent=1):
                    return False

            #
            # Harden Debug 
            #
            install_path = self.config['orthrus']['directory'] + "/binaries/harden-dbg/"
            if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_harden_debug,
                                                                 'afl-harden_dbg.log'),
                                               'Installing binaries for debug in harden mode',
                                               indent=1):
                if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path,
                                                                     b.BuildEnv.BEnv_harden_debug_softfail,
                                                                    'afl-harden_dbg_soft.log'),
                                                    'Retrying without FORTIFY compilation flag',
                                                    indent=1):
                    return False

        ### Coverage
        if self.args.coverage:
            install_path = self.config['orthrus']['directory'] + "/binaries/coverage/gcc/"
            if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path, b.BuildEnv.BEnv_gcc_coverage,
                                                                 'gcc_coverage.log'),
                                               'Installing binaries for obtaining test coverage information',
                                               indent=1):
                return False

        ### SanitizerCoverage
        if self.args.san_coverage:
            if self.args.afl_asan:
                install_path = self.config['orthrus']['directory'] + "/binaries/coverage/asan/"
                if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path,
                                                                     b.BuildEnv.BEnv_asan_coverage,
                                                                    'asan_coverage.log'),
                                                    'Installing binaries for obtaining ASAN coverage',
                                                    indent=1):
                    return False
            if self.args.afl_harden:
                install_path = self.config['orthrus']['directory'] + "/binaries/coverage/ubsan/"
                if not util.pprint_decorator_fargs(util.func_wrapper(self.create, install_path,
                                                                     b.BuildEnv.BEnv_ubsan_coverage,
                                                                    'ubsan_coverage.log'),
                                                    'Installing binaries for obtaining HARDEN coverage (via UBSAN)',
                                                    indent=1):
                    return False

        if self.args.dictionary:
            if not util.pprint_decorator_fargs(util.func_wrapper(self.create, None,
                                                                 b.BuildEnv.BEnv_bear,
                                                                 'bear.log', True),
                                               'Generating input dictionary',
                                               indent=1):
                return False

        if self.args.binary:
            install_path = self.config['orthrus']['directory'] + "/binaries/afl-qemu/"
            util.copy_binaries(install_path + "bin/")
            util.color_print(util.bcolors.OKGREEN, "\t\t[+] Installing binaries as-is for afl-qemu fuzzing...done")

        return True

class OrthrusAdd(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
        self.orthrusdir = self._config['orthrus']['directory']

    def copy_samples(self, jobroot_dir, seed_dir):
        samplevalid = False

        if os.path.isdir(seed_dir):
            for dirpath, dirnames, filenames in os.walk(seed_dir):
                for fn in filenames:
                    fpath = os.path.join(dirpath, fn)
                    if os.path.isfile(fpath):
                        shutil.copy(fpath, jobroot_dir + "/afl-in/")
            if filenames:
                samplevalid = True
        elif os.path.isfile(seed_dir):
            samplevalid = True
            shutil.copy(seed_dir, jobroot_dir + "/afl-in/")

        if not samplevalid:
            return False

        return True

    def seed_job(self, rootdir, id, seed_dir):

        if not util.pprint_decorator_fargs(util.func_wrapper(self.copy_samples, rootdir, seed_dir),
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
        asanjob_config['mem_limit'] = "none"
        # if util.is64bit():
        #     asanjob_config['mem_limit'] = "none"
        # else:
        #     asanjob_config['mem_limit'] = "none"

        asanjob_config['session'] = "ASAN"
        # https://github.com/rc0r/afl-utils/issues/34
        # FIXME: We do this due to a bug in afl-utils/afl-multicore that results in pgid not being written
        # to disk when the 'interactive' key is undefined in the fuzzer configuration file passed to it.
        # We set it to 0 because simplejson (that afl-utils uses) does not recognize False. Hack alert!
        asanjob_config['interactive'] = 0

        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
            asanjob_config['master_instances'] = 0

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
        hardenjob_config['mem_limit'] = "none"
        hardenjob_config['session'] = "HARDEN"
        hardenjob_config['interactive'] = 0

        if fuzzer:
            hardenjob_config['fuzzer'] = fuzzer

        if fuzzer_params:
            hardenjob_config['afl_margs'] = fuzzer_params

        self.write_config(hardenjob_config, "{}/harden-job.conf".format(jobroot_dir))

    def write_qemu_config(self, afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params):
        ## Create an afl-utils JSON config for AFL-HARDEN
        qemujob_config = {}
        qemujob_config['input'] = afl_in
        qemujob_config['output'] = afl_out
        qemujob_config['target'] = ".orthrus/binaries/afl-qemu/bin/{}".format(self.job.target)
        qemujob_config['cmdline'] = self.job.params
        # hardenjob_config['file'] = "@@"
        qemujob_config['timeout'] = "3000+"
        qemujob_config['mem_limit'] = "none"
        qemujob_config['session'] = "QEMU"
        qemujob_config['interactive'] = 0

        if fuzzer:
            qemujob_config['fuzzer'] = fuzzer

        if fuzzer_params:
            qemujob_config['afl_margs'] = fuzzer_params + " -Q"
        else:
            qemujob_config['afl_margs'] = "-Q"

        self.write_config(qemujob_config, "{}/qemu-job.conf".format(jobroot_dir))

    def write_config(self, config_dict, config_file):
        with open(config_file, 'wb') as file:
            json.dump(config_dict, file, indent=4)

    def config_wrapper(self, afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params, qemu):
        if qemu:
            self.write_qemu_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
        else:
            self.write_asan_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
            self.write_harden_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
        return True

    def config_job(self, rootdir, id, fuzzer, fuzzer_params, qemu):
        afl_dirs = [rootdir + '/{}'.format(dirname) for dirname in ['afl-in', 'afl-out']]

        for dir in afl_dirs:
            os.mkdir(dir)

        # HT: http://stackoverflow.com/a/13694053/4712439
        if not util.pprint_decorator_fargs(util.func_wrapper(self.config_wrapper, afl_dirs[0], afl_dirs[1],
                                                             rootdir, fuzzer, fuzzer_params, qemu),
                                           'Configuring {} job for ID [{}]'.format(self.job.jobtype, id), 2):
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

        util.minimize_and_reseed(self.orthrusdir, rootdir, id, target, params)
        return True

    def run_helper(self, rootdir, id, fuzzer, fuzzer_param, seed_dir, qemu):
        if not self.config_job(rootdir, id, fuzzer, fuzzer_param, qemu):
            return False
        if self._args._import and not self.import_job(rootdir, id, self.job.target, self.job.params):
            return False
        if not self.seed_job(rootdir, id, seed_dir):
            return False

        return True

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Adding new job to Orthrus workspace")


        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir + "/binaries/"),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you did orthrus create -asan, -fuzz or -bin'):
            return False

        self.job = j.job(self.orthrusdir, self._args.jobconf)

        self.rootdirs = []
        self.ids = []
        self.fuzzers = []
        self.fuzzer_param = []
        self.seed_dirs = []
        self.qemus = []

        if not util.pprint_decorator(self.job.materialize, 'Adding job', 2,
                                     'Invalid job configuration or a duplicate!'):
            return False

        if self.job.jobtype == 'routine':
            self.rootdirs.append(self.job.rootdir)
            self.ids.append(self.job.id)
            self.fuzzers.extend(self.job.fuzzers)
            self.fuzzer_param.extend(self.job.fuzzer_args)
            self.seed_dirs.extend(self.job.seeddirs)
            self.qemus.extend(self.job.qemus)
        else:
            self.rootdirs.extend(self.job.rootdir + '/{}'.format(id) for id in self.job.jobids)
            self.ids.extend(self.job.jobids)
            self.fuzzers.extend(self.job.fuzzers)
            self.fuzzer_param.extend(self.job.fuzzer_args)
            self.seed_dirs.extend(self.job.seeddirs)
            self.qemus.extend(self.job.qemus)

        for rootdir, id, fuzzer, fuzzer_param, seed_dir, qemu in zip(self.rootdirs, self.ids, self.fuzzers, self.fuzzer_param,
                                                     self.seed_dirs, self.qemus):
            if not self.run_helper(rootdir, id, fuzzer, fuzzer_param, seed_dir, qemu):
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

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Removing job ID [{}]".format(self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

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
                    if not self.job_token.qemus:
                        if not util.pprint_decorator_fargs(util.func_wrapper(util.run_afl_cov, self.orthrusdir, rootdir,
                                                                        self.job_token.target, self.job_token.params, True,
                                                                        self.test),
                                                       'Starting afl-cov for {} job ID [{}]'.format(self.job_token.type, id),
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
                                                           format(self.job_token.type,id),
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

        unique_dir = syncDir + "/../unique"
        if os.path.exists(unique_dir):
            triaged_unique = len(glob.glob(unique_dir + "/asan/*id*sig*")) + \
                             len(glob.glob(unique_dir + "/harden/*id*sig*"))
        util.color_print(util.bcolors.OKBLUE, "\t     Triaged crashes : " + str(triaged_unique))
        return True

    def whatsup_abtests(self, sync_list):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Multivariate test status")
        for idx, val in enumerate(sync_list):
            util.color_print(util.bcolors.OKBLUE, "Config {} [{}]".format(idx, self.job_token.jobids[idx]))
            if not self.whatsup(val):
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
            return self.whatsup_abtests('{}/{}/afl-out'.format(self.job_token.rootdir, id) for id in
                                        self.job_token.jobids)

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
                             routine['target'] + " " + routine['params'] +
                             "\n\tNum. cores: {}".format(routine['num_cores']))
            util.color_print(util.bcolors.OKBLUE, "\t" + '-' * 10)
            util.color_print(util.bcolors.OKBLUE, "\t" + "Fuzzer: {}\n"
                                                         "\tFuzzer args: {}\n"
                                                         "\tSeeds dir: {}\n"
                                                         "\tQEMU: {}".
                             format(routine['fuzzers'], routine['fuzzer_args'],
                                    routine['seed_dirs'], routine['qemus'])
                            )
            util.color_print(util.bcolors.OKBLUE, "\t" + '-' * 10)
        for idx, abtest in enumerate(self.abtest_list):
            util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Configured multivariate tests:")
            util.color_print(util.bcolors.OKBLUE, "\t" + str(idx) + ") [" + abtest['id'] + "] " +
                             abtest['target'] + " " + abtest['params'] +
                             "\n\tNum_cores: {}".format(abtest['num_cores']))
            for i in range(0, abtest['num_jobs']):
                alp_idx = string.ascii_uppercase[i]
                util.color_print(util.bcolors.OKBLUE, "\t" + '-' * 10)
                util.color_print(util.bcolors.OKBLUE, "\t" + "Config {} [{}]".format(i, abtest['jobids'][i]))
                util.color_print(util.bcolors.OKBLUE, "\t" + "Fuzzer {}: {}\n"
                                                             "\tFuzzer args: {}\n"
                                                             "\tSeeds dir: {}\n"
                                                             "\tQEMU: {}"
                                 .format(alp_idx, abtest['fuzzers'][i],abtest['fuzzer_args'][i], abtest['seed_dirs'][i],
                                         abtest['qemus'][i]))
            util.color_print(util.bcolors.OKBLUE, "\t" + '-' * 10)
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

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Checking stats and config")

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

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
        self.fail_msg_asan = 'No ASAN binary found. Triage requires an ASAN binary to continue. Please do orthrus ' \
                             'create -asan'
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
            shutil.copy(script, dest)
            os.remove(script)

        return True

    def triage(self, jobroot_dir, inst, indir=None, outdir=None):
        env = os.environ.copy()
        util.triage_asan_options(env)

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

        if not self.test and not self._args.regenerate:
            util.color_print(util.bcolors.WARNING, "[+] Crashes have been triaged once. If you wish "
                                                              "to rerun triaging, pass the -r or --regenerate flag")
            return False

        shutil.move(jobroot_dir + "/unique/", jobroot_dir + "/unique." + time.strftime("%Y-%m-%d-%H:%M:%S"))
        os.mkdir(jobroot_dir + "/unique/")
        # Archive exploitable crashes from prior triaging if necessary
        exp_path = jobroot_dir + "/exploitable"
        if os.path.exists(exp_path):
            shutil.move(exp_path, "{}.{}".format(exp_path, time.strftime("%Y-%m-%d-%H:%M:%S")))
            os.mkdir(exp_path)
        return True

    def make_unique_dirs(self, jobroot_dir):
        unique_dir = '{}/unique'.format(jobroot_dir)
        if not os.path.exists(unique_dir):
            os.mkdir(unique_dir)
            return True
        else:
            return False

    def get_formatted_crashnames(self, path, prefix):
        list = glob.glob('{}/{}/crashes/*id*sig*'.format(path, prefix))
        ## Rename files
        for file in list:
            head, fn = os.path.split(file)
            newfn = '{}:{}'.format(prefix, fn)
            shutil.move(file, os.path.join(head, newfn))
        return glob.glob('{}/{}/crashes/*id*sig*'.format(path, prefix))


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

        # BUGFIX: Second pass may be suboptimal (eliminate HARDEN crashes). Instead simply copy all.
        exp_path = jobroot_dir + "/exploitable"
        uniq_path = jobroot_dir + "/unique"
        if os.path.exists(exp_path):
            exp_all = []
            exp_asan_crashes = self.get_formatted_crashnames(exp_path, 'ASAN')
            exp_harden_crashes = self.get_formatted_crashnames(exp_path, 'HARDEN')
            exp_all.extend(exp_asan_crashes)
            exp_all.extend(exp_harden_crashes)
            for file in exp_all:
                shutil.copy(file, uniq_path)

        triaged_crashes = glob.glob(uniq_path + "/*id*sig*")
        util.color_print(util.bcolors.OKGREEN, "\t\t[+] Triaged " + str(len(triaged_crashes)) + \
                         " crashes. See {}".format(uniq_path))
        if not triaged_crashes:
            util.color_print(util.bcolors.OKBLUE, "\t\t[+] Nothing to do")
            return True

        # Organize unique crashes
        asan_crashes = glob.glob('{}/ASAN*id*sig*'.format(uniq_path))
        harden_crashes = glob.glob('{}/HARDEN*id*sig*'.format(uniq_path))
        if asan_crashes:
            uniq_asan_dir = '{}/asan'.format(uniq_path)
            util.mkdir_p(uniq_asan_dir)
            for file in asan_crashes:
                shutil.move(file, uniq_asan_dir)
        if harden_crashes:
            uniq_harden_dir = '{}/harden'.format(uniq_path)
            util.mkdir_p(uniq_harden_dir)
            for file in harden_crashes:
                shutil.move(file, uniq_harden_dir)

        return True

    def triage_abtests(self):
        count = 0
        for rootdir,id in [('{}/{}'.format(self.job_token.rootdir, jobId), jobId) for jobId in self.job_token.jobids]:
            group = 'Config {}'.format(count)
            count += 1
            if not util.pprint_decorator_fargs(util.func_wrapper(self.triage_wrapper, rootdir, id),
                                               'Triaging crashes in {}'.format(group), indent=2):
                return False

        return True

    def run(self):

        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Triaging crashes for job ID [{}]".format(
            self._args.job_id))

        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you ran orthrus create -asan -fuzz?'):
            return False

        # if not util.pprint_decorator_fargs(self.is_asan, 'Looking for ASAN debug binary', indent=2,
        #                                    fail_msg=self.fail_msg_asan):
        #     return False

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