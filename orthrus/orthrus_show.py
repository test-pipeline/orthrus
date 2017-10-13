'''
Orthrus show implementation
'''
import os
import subprocess
import glob
import webbrowser
import json
import string
from orthrusutils import orthrusutils as util
from job import job as j

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
                                 .format(alp_idx, abtest['fuzzers'][i], abtest['fuzzer_args'][i],
                                         abtest['seed_dirs'][i],
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