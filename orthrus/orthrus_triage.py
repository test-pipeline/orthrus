'''
Orthrus triage implementation
'''
import os
import shutil
import glob
import time
from orthrusutils import orthrusutils as util
from job import job as j

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
        for rootdir, id in [('{}/{}'.format(self.job_token.rootdir, jobId), jobId) for jobId in self.job_token.jobids]:
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