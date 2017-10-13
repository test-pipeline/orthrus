'''
Orthrus add implementation
'''
import os
import shutil
import tarfile
import json
from orthrusutils import orthrusutils as util
from job import job as j

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

        for rootdir, id, fuzzer, fuzzer_param, seed_dir, qemu in zip(self.rootdirs, self.ids, self.fuzzers,
                                                                     self.fuzzer_param,
                                                                     self.seed_dirs, self.qemus):
            if not self.run_helper(rootdir, id, fuzzer, fuzzer_param, seed_dir, qemu):
                return False
        return True