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

    def seedjob_routine(self):

        if not util.pprint_decorator_fargs(util.func_wrapper(self.copy_samples, self.job.rootdir),
                                          'Adding initial samples for job ID [{}]'.format(self.job.id), 2,
                                          'seed dir or file invalid. No seeds copied'):
            return False

        return True

    def seedjob_abtests(self):

        if not util.pprint_decorator_fargs(util.func_wrapper(self.copy_samples, self.job.rootdir + '/{}'.format(self.job.joba_id)),
                                          'Adding initial samples for job ID [{}]'.format(self.job.joba_id), 2,
                                          'seed dir or file invalid. No seeds copied'):
            return False

        if not util.pprint_decorator_fargs(util.func_wrapper(self.copy_samples, self.job.rootdir + '/{}'.format(self.job.jobb_id)),
                                          'Adding initial samples for job ID [{}]'.format(self.job.jobb_id), 2,
                                          'seed dir or file invalid. No seeds copied'):
            return False

        return True

    def seedjob(self):
        if self.jobtype == 'routine':
            return self.seedjob_routine()
        else:
            return self.seedjob_abtests()

    def write_config(self, config_dict, config_file):
        with open(config_file, 'wb') as file:
            json.dump(config_dict, file)

    def write_asan_config(self, afl_in, afl_out, jobroot_dir, fuzzer=None, fuzzer_params=None):

        ## Create an afl-utils JSON config for AFL-ASAN fuzzing setting it as slave if AFL-HARDEN target exists
        asanjob_config = {}
        asanjob_config['input'] = afl_in
        asanjob_config['output'] = afl_out
        asanjob_config['target'] = ".orthrus/binaries/afl-asan/bin/{}".format(self.job.target)
        asanjob_config['cmdline'] = self.job.params
        asanjob_config['file'] = "@@"
        # asanjob_config.set("afl.ctrl", "file", ".orthrus/jobs/" + self.jobId + "/afl-out/.cur_input_asan")
        asanjob_config['timeout'] = "3000+"

        # See: https://github.com/mirrorer/afl/blob/master/docs/notes_for_asan.txt
        if util.is64bit():
            asanjob_config['mem_limit'] = "30000000"
        else:
            asanjob_config['mem_limit'] = "800"

        asanjob_config['session'] = "SESSION"
        # https://github.com/rc0r/afl-utils/issues/34
        asanjob_config['interactive'] = False

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
        hardenjob_config['file'] = "@@"
        hardenjob_config['timeout'] = "3000+"
        hardenjob_config['mem_limit'] = "800"
        hardenjob_config['session'] = "SESSION"
        hardenjob_config['interactive'] = False

        if fuzzer:
            hardenjob_config['fuzzer'] = fuzzer

        if fuzzer_params:
            hardenjob_config['afl_margs'] = fuzzer_params

        self.write_config(hardenjob_config, "{}/harden-job.conf".format(jobroot_dir))

    def config_wrapper(self, afl_in, afl_out, jobroot_dir, fuzzer=None, fuzzer_params=None):
        self.write_asan_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
        self.write_harden_config(afl_in, afl_out, jobroot_dir, fuzzer, fuzzer_params)
        return True

    def process_routine(self):

        afl_dirs = [self.job.rootdir + '/{}'.format(dirname) for dirname in ['afl-in', 'afl-out']]

        for dir in afl_dirs:
            os.mkdir(dir)

        # afl_in = self.job.rootdir + "/afl-in"
        # afl_out = self.job.rootdir + "/afl-out"
        #
        # os.mkdir(afl_in)
        # os.mkdir(afl_out)

        # HT: http://stackoverflow.com/a/13694053/4712439
        if not util.pprint_decorator_fargs(util.func_wrapper(self.config_wrapper, afl_dirs[0], afl_dirs[1],
                                                             self.job.rootdir), 'Configuring routine job for ID [{}]'.format(self.job.id), 2):
            return False

        return True

        # util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Configuring routine job for [" \
        #                                                     + self.job.target + "]... ")
        # self.write_asan_config(afl_in, afl_out, self.job.rootdir)
        # self.write_harden_config(afl_in, afl_out, self.job.rootdir)
        # util.color_print(util.bcolors.OKGREEN, "done")

    def process_abtests(self):

        jobs = [self.job.joba_id, self.job.jobb_id]
        afl_in = [self.job.rootdir + '/{}/afl-in'.format(job) for job in jobs]
        afl_out = [self.job.rootdir + '/{}/afl-out'.format(job) for job in jobs]

        for entry in afl_in:
            os.mkdir(entry)
        for entry in afl_out:
            os.mkdir(entry)


        if not util.pprint_decorator_fargs(util.func_wrapper(self.config_wrapper, afl_in[0], afl_out[0],
                                                             self.job.rootdir + '/{}'.format(self.job.joba_id),
                                                             self.job.abconf_data['fuzzerA'],
                                                             self.job.abconf_data['fuzzerA_args']),
                                          'Configuring a/b test job for ID [{}]'.format(self.job.joba_id), 2):
            return False


        if not util.pprint_decorator_fargs(util.func_wrapper(self.config_wrapper, afl_in[1], afl_out[1],
                                                             self.job.rootdir + '/{}'.format(self.job.jobb_id),
                                                             self.job.abconf_data['fuzzerB'],
                                                             self.job.abconf_data['fuzzerB_args']),
                                          'Configuring a/b test job for ID [{}]'.format(self.job.jobb_id), 2):
            return False

        return True

        # util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Configuring a/b test job for [" \
        #                                                     + self.job.target + "]... ")
        # self.write_asan_config(afl_in[0], afl_out[0], self.job.rootdir + '/{}'.format(self.job.joba_id),
        #                        self.job.abconf_data['fuzzerA'], self.job.abconf_data['fuzzerA_args'])
        # self.write_harden_config(afl_in[0], afl_out[0], self.job.rootdir + '/{}'.format(self.job.joba_id),
        #                        self.job.abconf_data['fuzzerA'], self.job.abconf_data['fuzzerA_args'])
        # self.write_asan_config(afl_in[1], afl_out[1], self.job.rootdir + '/{}'.format(self.job.jobb_id),
        #                        self.job.abconf_data['fuzzerB'], self.job.abconf_data['fuzzerB_args'])
        # self.write_harden_config(afl_in[1], afl_out[1], self.job.rootdir + '/{}'.format(self.job.jobb_id),
        #                        self.job.abconf_data['fuzzerB'], self.job.abconf_data['fuzzerB_args'])
        #
        # util.color_print(util.bcolors.OKGREEN, "done")


    def processjob(self):

        try:
            self.job = j.job(self._args.job, self.jobtype, self.orthrusdir, self._args.abconf)
        except ValueError:
            util.color_print(util.bcolors.FAIL, "\t\t[+] Are you sure you passed a valid a/b test configuration")
            return False

        if not util.pprint_decorator(self.job.materialize, 'Adding job', 2, 'existing job found!'):
            return False

        if self.jobtype == 'routine':
            return self.process_routine()
        else:
            return self.process_abtests()


    def importjob_routine(self):
        jobId = self.job.id
        next_session = 0

        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Import afl sync dir for job [" + jobId + "]... ")

        if not tarfile.is_tarfile(self._args._import):
            util.color_print(util.bcolors.FAIL, "failed!")
            return False

        if not os.path.exists(self.job.rootdir + "/afl-out/"):
            util.color_print(util.bcolors.FAIL, "failed!")
            return False

        syncDir = os.listdir(self.job.rootdir + "/afl-out/")
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
                outDir = self.job.rootdir + "/afl-out/SESSION" + "{:03d}".format(next_session)
                os.mkdir(outDir)
                tar.extractall(outDir)
            else:
                tmpDir = self.job.rootdir + "/tmp/"
                os.mkdir(tmpDir)
                tar.extractall(tmpDir)
                for directory in os.listdir(self.job.rootdir + "/tmp/"):
                    outDir = self.job.rootdir + '/afl-out/'
                    shutil.move(tmpDir + directory, outDir)
                shutil.rmtree(tmpDir)
        util.color_print(util.bcolors.OKGREEN, "done")

        util.minimize_sync_dir(self.job)
        return True

    def importjob(self):

        if self.jobtype == 'routine':
            return self.importjob_routine()
        else:
            return self.importjob_abtests()

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Adding fuzzing job to Orthrus workspace")


        if not util.pprint_decorator_fargs(util.func_wrapper(os.path.exists, self.orthrusdir + "/binaries/"),
                                          "Checking Orthrus workspace", 2,
                                          'failed. Are you sure you did orthrus create -asan or -fuzz'):
            return False

        # util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Check Orthrus workspace... ")
        #
        # if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/"):
        #     util.color_print(util.bcolors.FAIL, "failed. Are you sure you did orthrus create -asan or -fuzz")
        #     return False
        #
        # util.color_print(util.bcolors.OKGREEN, "done")

        if self._args.abconf:
            self.jobtype = 'abtests'
        else:
            self.jobtype = 'routine'


        if not self.processjob():
            return False
        if self._args._import and not self.importjob():
            return False
        if self._args.sample and not self.seedjob():
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
        if not util.pprint_decorator(job_token.materialize, 'Retrieving job', indent=2,
                                     fail_msg=self.fail_msg):
            return False

        if not util.pprint_decorator_fargs(util.func_wrapper(shutil.move,
                                                             self.orthrusdir + "/jobs/{}/{}".format(job_token.type,
                                                                                                   job_token.id),
                                                             self.orthrusdir + "/archive/" +
                                                                    time.strftime("%Y-%m-%d-%H:%M:%S") + "-"
                                                                    + job_token.id),
                                           'Archiving data for job [{}]'.format(job_token.id),
                                           indent=2):
            return False

        j.remove_id_from_conf(job_token.jobsconf, job_token.id, job_token.type)
        return True

class OrthrusStart(object):
    
    def __init__(self, args, config, test=False):
        self._args = args
        self._config = config
        self.test = test
    
    def _start_fuzzers(self, jobId, available_cores):
        if os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/") == []:
            start_cmd = "start"
        else:
            start_cmd = "resume"

        core_per_subjob = available_cores / 2
        if core_per_subjob == 0:
            core_per_subjob = 1

        cmd = ["cat /proc/sys/kernel/core_pattern"]
        util.color_print_singleline(util.bcolors.OKGREEN, "Checking core_pattern...")
        try:
            if "core" not in subprocess.check_output(" ".join(cmd), shell=True, stderr=subprocess.STDOUT):
                util.color_print(util.bcolors.FAIL, "failed")
                util.color_print(util.bcolors.FAIL, "\t\t\t[-] Please do echo core | "
                                                    "sudo tee /proc/sys/kernel/core_pattern")
                return False
        except subprocess.CalledProcessError as e:
            print e.output
            return False
        util.color_print(util.bcolors.OKGREEN, "okay")

        env = os.environ.copy()
        env.update({'AFL_SKIP_CPUFREQ': '1'})

        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
            util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Starting AFL harden fuzzer job as master...")

            harden_file = self._config['orthrus']['directory'] + "/logs/afl-harden.log"
            cmd = ["afl-multicore", "--config=.orthrus/jobs/" + jobId + "/harden-job.conf",
                                           start_cmd, str(core_per_subjob), "-v"]

            if not util.run_cmd(" ".join(cmd), env, harden_file):
                util.color_print(util.bcolors.FAIL, "failed")
                return False

            util.color_print(util.bcolors.OKGREEN, "done")
            
            output = open(self._config['orthrus']['directory'] + "/logs/afl-harden.log", "r")
            for line in output:
                if "Starting master" in line or "Starting slave" in line:
                    util.color_print(util.bcolors.OKGREEN, "\t\t\t" + line)
                if " Master " in line or " Slave " in line:
                    util.color_print_singleline(util.bcolors.OKGREEN, "\t\t\t\t" + "[+] " + line)
            output.close()
            
            if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-asan"):
                util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Starting AFL ASAN fuzzer job as slave...")
                asan_file = self._config['orthrus']['directory'] + "/logs/afl-asan.log"
                cmd = ["afl-multicore", "--config=.orthrus/jobs/" + jobId + "/asan-job.conf ", "add", \
                                str(core_per_subjob), "-v"]

                if not util.run_cmd(" ".join(cmd), env, asan_file):
                    util.color_print(util.bcolors.FAIL, "failed")
                    return False

                util.color_print(util.bcolors.OKGREEN, "done")

                output2 = open(self._config['orthrus']['directory'] + "/logs/afl-asan.log", "r")
                for line in output2:
                    if "Starting master" in line or "Starting slave" in line:
                        util.color_print(util.bcolors.OKGREEN, "\t\t\t" + line)
                    if " Master " in line or " Slave " in line:
                        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t\t\t" + "[+] " + line)
                output2.close()

        elif os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-asan"):

            util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Starting AFL ASAN fuzzer job as master...")
            asan_file = self._config['orthrus']['directory'] + "/logs/afl-asan.log"
            cmd = ["afl-multicore", "-c", ".orthrus/jobs/" + jobId + "/asan-job.conf", start_cmd, \
                   str(available_cores), "-v"]

            if not util.run_cmd(" ".join(cmd), env, asan_file):
                util.color_print(util.bcolors.FAIL, "failed")
                return False

            util.color_print(util.bcolors.OKGREEN, "done")

            output2 = open(self._config['orthrus']['directory'] + "/logs/afl-asan.log", "r")
            for line in output2:
                if "Starting master" in line or "Starting slave" in line:
                    util.color_print(util.bcolors.OKGREEN, "\t\t\t" + line)
                if " Master " in line or " Slave " in line:
                    util.color_print_singleline(util.bcolors.OKGREEN, "\t\t\t\t" + "[+] " + line)
            output2.close()
                
        return True
    
    def compact_sync_dir(self, jobId):
        syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out"
        for session in os.listdir(syncDir):
            if os.path.isfile(syncDir + "/" + session):
                os.remove(syncDir + "/" + session)
            if os.path.isdir(syncDir + "/" + session):
                for directory in os.listdir(syncDir + "/" + session):
                    if "crashes." in directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + session + "/" + "crashes" + "/" + filename
                            if not os.path.isfile(dst_path):
                                #dst_path += "," + str(num)
                                shutil.move(src_path, dst_path)
                        shutil.rmtree(syncDir + "/" + session + "/" + directory + "/")
                    if "hangs." in directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + session + "/" + "hangs" + "/" + filename
                            if not os.path.isfile(dst_path):
                                #dst_path += "," + str(num)
                                shutil.move(src_path, dst_path)
                        shutil.rmtree(syncDir + "/" + session + "/" + directory + "/")
    #                 if "queue." in directory:
    #                     for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
    #                         src_path = syncDir + "/" + session + "/" + directory + "/" + filename
    #                         dst_path = syncDir + "/" + session + "/" + "queue" + "/" + filename
    #                         if os.path.isfile(dst_path):
    #                             dst_path += "," + str(num)
    #                         shutil.move(src_path, dst_path)
    #                     shutil.rmtree(syncDir + "/" + session + "/" + directory + "/")
        
        for session in os.listdir(syncDir):
            if "SESSION000" != session and os.path.isdir(syncDir + "/" + session):
                for directory in os.listdir(syncDir + "/" + session):
                    if "crashes" == directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + "SESSION000" + "/" + "crashes" + "/" + filename
                            if not os.path.isfile(dst_path):
                                #dst_path += "," + str(num)
                                shutil.move(src_path, dst_path)
                    if "hangs" == directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + "SESSION000" + "/" + "hangs" + "/" + filename
                            if not os.path.isfile(dst_path):
                                #dst_path += "," + str(num)
                                shutil.move(src_path, dst_path)
                    if "queue" == directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + "SESSION000" + "/" + "queue" + "/" + filename
                            if os.path.isdir(src_path):
                                continue
                            if not os.path.isfile(dst_path):
                                #dst_path += "," + str(num)
                                shutil.move(src_path, dst_path)
                shutil.rmtree(syncDir + "/" + session)
                
        return True
                
    def _start_afl_coverage(self, jobId):
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")

        # Run afl-cov as a nohup process
        util.run_afl_cov(self._config['orthrus']['directory'], jobId, job_config.get(jobId, "target"),
                         job_config.get(jobId, "params"), True, self.test)
        
        # target = self._config['orthrus']['directory'] + "/binaries/coverage/bin/" + \
        #          job_config.get(jobId, "target") + " " + job_config.get(jobId, "params").replace("@@","AFL_FILE")
        # cmd = ["nohup", "afl-cov", "-d", ".orthrus/jobs/" + jobId + \
        #        "/afl-out", "--live", "--lcov-path", "/usr/bin/lcov", "--coverage-cmd", "'" + target + \
        #        "'", "--code-dir", ".", "-v"]
        # logfile = self._config['orthrus']['directory'] + "/logs/afl-coverage.log"
        # p = subprocess.Popen(" ".join(cmd), shell=True, executable="/bin/bash")

        return True

    def run(self):
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Starting fuzzing jobs")
        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Check Orthrus workspace... ")

        orthrus_root = self._config['orthrus']['directory']
        if not util.validate_job(orthrus_root, self._args.job_id):
            util.color_print(util.bcolors.FAIL, "failed. Are you sure you have done orthrus add --job or passed the "
                                                "right job ID. orthrus show -j might help")
            return False

        util.color_print(util.bcolors.OKGREEN, "done")

        jobId = self._args.job_id
        total_cores = int(util.getnproc())

        if len(os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/")) > 0:
            util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Tidy fuzzer sync dir... ")

            if not self.compact_sync_dir(jobId):
                util.color_print(util.bcolors.FAIL, "failed")
                return False
            util.color_print(util.bcolors.OKGREEN, "done")

            if self._args.minimize:
                if not util.minimize_sync_dir(self._config, jobId):
                    return False

        util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Start Fuzzers for Job [" + jobId +"]... ")
        if not self._start_fuzzers(jobId, total_cores):
            try:
                subprocess.call("pkill -9 afl-fuzz", shell=True, stderr=subprocess.STDOUT)
            except OSError, subprocess.CalledProcessError:
                return False
            return False

        if self._args.coverage:
            util.color_print_singleline(util.bcolors.OKGREEN, "\t\t[+] Start afl-cov for Job "
                                                              "[" + jobId +"]... ")
            if not self._start_afl_coverage(jobId):
                util.color_print(util.bcolors.FAIL + "failed" + util.bcolors.ENDC + "\n")
                return False
            util.color_print(util.bcolors.OKGREEN, "done")

        return True
    
class OrthrusStop(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config

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

    def run(self):
        util.color_print_singleline(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Stopping fuzzing jobs...")
        kill_fuzz_cmd = ["pkill", "-9", "afl-fuzz"]
        util.run_cmd(" ".join(kill_fuzz_cmd))
        util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "done")
        if self._args.coverage:
            util.color_print_singleline(util.bcolors.BOLD + util.bcolors.HEADER, "[+] Stopping afl-cov for jobs...")
            for pid in self.get_afl_cov_pid():
                kill_aflcov_cmd = ["pkill", "-9", pid]
                util.run_cmd(" ".join(kill_aflcov_cmd))
            util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "done")
        return True

class OrthrusShow(object):
    
    def __init__(self, args, config, test=False):
        self._args = args
        self._config = config
        self.test = test

    def run(self):
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
        if self._args.jobs:
            util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Configured jobs found:")
            for num, section in enumerate(job_config.sections()):
                t = job_config.get(section, "target")
                p = job_config.get(section, "params")
                util.color_print(util.bcolors.OKGREEN, "\t" + str(num) + ") [" + section + "] " + t + " " + p)
        elif self._args.cov:
            for jobId in job_config.sections():
                cov_web_indexhtml = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/" + \
                                    "cov/web/index.html"
                if os.path.exists(cov_web_indexhtml):
                    util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Opening coverage html for job {} "
                                                                              "in a new browser tab".format(jobId))
                    # Early return for tests
                    if self.test:
                        return True
                    webbrowser.open_new_tab(cov_web_indexhtml)
                else:
                    util.color_print(util.bcolors.INFO, "No coverage info at {}. Have you run orthrus coverage or"
                                                        " orthrus start -c already?".format(cov_web_indexhtml))
                    return False
        else:
            util.color_print(util.bcolors.BOLD + util.bcolors.HEADER, "Status of jobs:")
            
            for jobId in job_config.sections():
                syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"
                try:
                    output = subprocess.check_output(["afl-whatsup", "-s", syncDir])
                except subprocess.CalledProcessError as e:
                    print e.output
                    return False
                output = output[output.find("==\n\n") + 4:]
                
                util.color_print(util.bcolors.OKBLUE, "\tJob [" + jobId + "] " + "for target '" +
                                 job_config.get(jobId, "target") + "':")
                for line in output.splitlines():
                    util.color_print(util.bcolors.OKBLUE, "\t" + line)
                triaged_unique = 0
                if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"):
                    triaged_unique = len(glob.glob(self._config['orthrus']['directory'] + "/jobs/" + jobId +
                                                   "/unique/*id*sig*"))
                util.color_print(util.bcolors.OKBLUE, "\t     Triaged crashes : " + str(triaged_unique) + " available")
                
        return True

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