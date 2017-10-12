import binascii
import json
import os
import string

'''
What is a job?
It could be a routine (fuzzing) job or an a/b test job
What characteristics of a job would we want to define here?
It can be added, removed, started, stopped, coveraged, triaged, showed
All orthrus subcommands except create and destroy are invoked on specific jobs

I guess a good starting point to define a job would be as a data-type rather than as a functional entity.
As a data-type, a job has an ID, type (routine/abtest), rootdir,

How do we pass jobs around. One way is to make a getter for

'''

JOBCONF = '/jobs/jobs.conf'
ROUTINEDIR = '/jobs/routine'
ABTESTSDIR = '/jobs/abtests'

JOBCONF_DICT = {'routine': [], 'abtests': []}
DEFAULT_NUMCORES = 4


def bootstrap(jobsconf):
    with open(jobsconf, 'wb') as jobconf_fp:
        json.dump(JOBCONF_DICT, jobconf_fp, indent=4)


def does_id_exist(jobsconf, id):
    with open(jobsconf, 'r') as jobconf_fp:
        jobsconf_dict = json.load(jobconf_fp)

    # Check routine list
    routine_jobs = jobsconf_dict['routine']
    val = [item for item in routine_jobs if item['id'] == id]
    if val:
        return val[0]

    # Check abtests list
    abtests_jobs = jobsconf_dict['abtests']
    val = [item for item in abtests_jobs if item['id'] == id]
    if val:
        return val[0]

    return None

def remove_id_from_conf(jobsconf, id, type):
    with open(jobsconf, 'r') as jobconf_fp:
        jobsconf_dict = json.load(jobconf_fp)

    # Find and remove in the typed list
    if type == 'routine':
        [jobsconf_dict['routine'].remove(item) for item in jobsconf_dict['routine'] if item['id'] == id]
    else:
        [jobsconf_dict['abtests'].remove(item) for item in jobsconf_dict['abtests'] if item['id'] == id]

    # Update jobs.conf
    with open(jobsconf, 'w') as jobconf_fp:
        json.dump(jobsconf_dict, jobconf_fp, indent=4)

class job(object):

    def __init__(self, orthrusdir, jobconf):

        self.jobconf = jobconf
        self.orthrusdir = orthrusdir
        self.jobsconf = self.orthrusdir + JOBCONF
        self.jobids = []
        self.fuzzers = []
        self.fuzzer_args = []
        self.seeddirs = []
        self.qemus = []

        ## Bootstap jobs.conf if necessary
        if not os.path.exists(self.jobsconf):
            bootstrap(self.jobsconf)

    def parse_and_validate_jobconf(self):
        with open(self.jobconf, 'rb') as jc_fp:
            self.data = json.load(jc_fp)

        required_keys = ['fuzz_cmd', 'job_type', 'num_jobs', 'job_desc']

        for key in required_keys:
            if key not in self.data:
                raise KeyError

        if not (self.data['job_type'] == 'routine' or self.data['job_type'] == 'abtests'):
            raise ValueError

        self.fuzz_cmd = self.data['fuzz_cmd']
        self.jobtype = self.data['job_type']
        self.num_jobs = self.data['num_jobs']
        self.job_desc = self.data['job_desc']

        if self.jobtype == 'routine' and not (self.num_jobs == 1):
            raise ValueError
        elif self.jobtype == 'abtests' and not (self.num_jobs == len(self.job_desc)):
            raise ValueError
        elif self.jobtype == 'abtests' and self.num_jobs % 2:
            raise ValueError

        required_jobdesc_keys = ['fuzzer', 'fuzzer_args', 'seed_dir']
        for item in self.job_desc:
            for key in required_jobdesc_keys:
                if key not in item:
                    raise KeyError

        ## Break down fuzz_cmd
        self.target = self.fuzz_cmd.split(" ")[0]
        self.params = " ".join(self.fuzz_cmd.split(" ")[1:])

        ## Parse num_cores if necessary
        if 'num_cores' in self.data:
            self.num_cores = self.data['num_cores']
        else:
            self.num_cores = DEFAULT_NUMCORES

        for i in range(0, self.num_jobs):
            self.seeddirs.append(self.job_desc[i]['seed_dir'])
            self.fuzzers.append(self.job_desc[i]['fuzzer'])
            self.fuzzer_args.append(self.job_desc[i]['fuzzer_args'])
            if 'qemu' in self.job_desc[i] and self.job_desc[i]['qemu']:
                self.qemus.append(True)
            else:
                self.qemus.append(False)

        # ID | job id setup
        if self.jobtype == 'routine':
            crcstring = self.fuzz_cmd
            self.id = str(binascii.crc32(crcstring) & 0xffffffff)
            self.rootdir = self.orthrusdir + ROUTINEDIR + '/{}'.format(self.id)
        else:
            crcstring = self.fuzz_cmd
            for i in range(0, self.num_jobs):
                crcstring += self.job_desc[i]['fuzzer'] + self.job_desc[i]['fuzzer_args']
                self.jobids.append(str(binascii.crc32(self.fuzz_cmd+str(i)) & 0xffffffff))
            self.id = str(binascii.crc32(crcstring) & 0xffffffff)
            self.rootdir = self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id)

        return True

    def update_jobs_conf(self):

        with open(self.jobsconf, 'r') as jobconf_fp:
            jobsconf_dict = json.load(jobconf_fp)

        if self.jobtype == 'routine':
            routine_dict = {'id': self.id, 'target': self.target, 'params': self.params, 'type': self.jobtype,
                            'fuzzers': self.fuzzers[0], 'fuzzer_args': self.fuzzer_args[0], 'num_cores': self.num_cores,
                            'seed_dirs': self.seeddirs[0], 'qemus': self.qemus[0], 'num_jobs': self.num_jobs}
            jobsconf_dict['routine'].append(routine_dict)
        elif self.jobtype == 'abtests':
            abtests_dict = {'id': self.id, 'target': self.target, 'params': self.params,
                            'jobids': self.jobids, 'fuzzers': self.fuzzers,
                            'fuzzer_args': self.fuzzer_args, 'type': self.jobtype, 'num_jobs': self.num_jobs,
                            'num_cores': self.num_cores, 'qemus': self.qemus, 'seed_dirs': self.seeddirs}
            jobsconf_dict['abtests'].append(abtests_dict)

        # Overwrites JSON file
        with open(self.jobsconf, 'w') as jobconf_fp:
            json.dump(jobsconf_dict, jobconf_fp, indent=4)

    def create_dirs(self):

        # Routine job and no routine dir
        if self.jobtype == 'routine' and not os.path.exists(self.orthrusdir + ROUTINEDIR):
            os.makedirs(self.orthrusdir + ROUTINEDIR)
        # Abtests job and no abtests dir
        elif self.jobtype == 'abtests' and not os.path.exists(self.orthrusdir + ABTESTSDIR):
            os.makedirs(self.orthrusdir + ABTESTSDIR)

        if self.jobtype == 'routine':
            os.makedirs(self.orthrusdir + ROUTINEDIR + '/{}'.format(self.id))
        elif self.jobtype == 'abtests':
            os.makedirs(self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id))
            for i in range(0, self.num_jobs):
                os.makedirs(self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id) + '/{}'.format(self.jobids[i]))

    def materialize(self):

        # Parse and gen ID
        if not self.parse_and_validate_jobconf():
            return False

        # Check if ID exists in jobs.conf
        if does_id_exist(self.jobsconf, self.id):
            return False

        self.update_jobs_conf()
        self.create_dirs()
        return True


class jobtoken(object):

    def __init__(self, orthrusdir, jobid):
        self.jobsconf = orthrusdir + JOBCONF
        self.id = jobid
        self.orthrusdir = orthrusdir

    def materialize(self):
        ## Bootstap jobs.conf if necessary
        if not os.path.exists(self.jobsconf):
            raise ValueError

        ## Check if jobid exists
        self._jobdesc = does_id_exist(self.jobsconf, self.id)
        if not self._jobdesc:
            raise ValueError
        assert self.id == self._jobdesc['id'], 'Job token ID assertion failed!'

        self.params = self._jobdesc['params']
        self.target = self._jobdesc['target']
        self.type = self._jobdesc['type']
        if self.type == 'abtests':
            self.rootdir = self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id)
            self.jobids = self._jobdesc['jobids']
        else:
            self.rootdir = self.orthrusdir + ROUTINEDIR + '/{}'.format(self.id)

        self.fuzzers = self._jobdesc['fuzzers']
        self.fuzzer_args = self._jobdesc['fuzzer_args']
        self.seed_dirs = self._jobdesc['seed_dirs']
        self.qemus = self._jobdesc['qemus']
        self.num_jobs = self._jobdesc['num_jobs']
        self.num_cores = self._jobdesc['num_cores']

        return True