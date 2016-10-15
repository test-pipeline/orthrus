import binascii
import json
import os

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

    def __init__(self, fuzz_cmd, type, orthrusdir, abconf=None):

        self.abconf = abconf
        self.type = type
        self.orthrusdir = orthrusdir
        self.jobsconf = self.orthrusdir + JOBCONF
        self.fuzz_cmd = fuzz_cmd

        ## Bootstap jobs.conf if necessary
        if not os.path.exists(self.jobsconf):
            bootstrap(self.jobsconf)

    def parse_and_validate_abtest_conf(self):
        with open(self.abconf, 'rb') as abconf_fp:
            self.abconf_data = json.load(abconf_fp)

        if not (self.abconf_data['fuzzerA'] and self.abconf_data['fuzzerB']):
            return False

        # Move dependency check to elsewhere
        # if not (util.which(self.abconf_data['test']['fuzzerA']) and util.which(self.abconf_data['test']['fuzzerB'])):
        #     return False

        return True

    def update_jobs_conf(self):

        with open(self.jobsconf, 'r') as jobconf_fp:
            jobsconf_dict = json.load(jobconf_fp)

        if self.type == 'routine':
            routine_dict = {'id': self.id, 'target': self.target, 'params': self.params, 'type': self.type}
            jobsconf_dict['routine'].append(routine_dict)
        elif self.type == 'abtests':
            abtests_dict = {'id': self.id, 'target': self.target, 'params': self.params,
                            'jobA_id': self.joba_id, 'jobB_id': self.jobb_id,
                            'fuzzerA': self.abconf_data['fuzzerA'],
                            'fuzzerA_args': self.abconf_data['fuzzerA_args'],
                            'fuzzerB': self.abconf_data['fuzzerB'],
                            'fuzzerB_args': self.abconf_data['fuzzerB_args'], 'type': self.type}
            jobsconf_dict['abtests'].append(abtests_dict)

        # Overwrites JSON file
        with open(self.jobsconf, 'w') as jobconf_fp:
            json.dump(jobsconf_dict, jobconf_fp, indent=4)

    def create_dirs(self):

        # Routine job and no routine dir
        if self.type == 'routine' and not os.path.exists(self.orthrusdir + ROUTINEDIR):
            os.makedirs(self.orthrusdir + ROUTINEDIR)
        # Abtests job and no abtests dir
        elif self.type == 'abtests' and not os.path.exists(self.orthrusdir + ABTESTSDIR):
            os.makedirs(self.orthrusdir + ABTESTSDIR)

        if self.type == 'routine':
            os.makedirs(self.orthrusdir + ROUTINEDIR + '/{}'.format(self.id))
        elif self.type == 'abtests':
            os.makedirs(self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id))
            os.makedirs(self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id) + '/{}'.format(self.joba_id))
            os.makedirs(self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id) + '/{}'.format(self.jobb_id))


    def materialize(self):

        if not (self.type == 'routine' or self.type == 'abtests'):
            raise ValueError

        if self.type == 'abtests' and not self.abconf:
            raise ValueError

        if self.type == 'abtests':
            if not self.parse_and_validate_abtest_conf():
                raise ValueError

        ## Break down fuzz_cmd
        self.target = self.fuzz_cmd.split(" ")[0]
        self.params = " ".join(self.fuzz_cmd.split(" ")[1:])

        if self.type == 'routine':
            crcstring = self.fuzz_cmd
            self.id = str(binascii.crc32(crcstring) & 0xffffffff)
            self.rootdir = self.orthrusdir + ROUTINEDIR + '/{}'.format(self.id)
        else:
            crcstring = self.abconf_data['fuzzerA'] + self.abconf_data['fuzzerA_args'] + \
                        self.abconf_data['fuzzerB'] + self.abconf_data['fuzzerB_args'] + \
                        self.fuzz_cmd
            self.id = str(binascii.crc32(crcstring) & 0xffffffff)
            self.joba_id = str(binascii.crc32(self.fuzz_cmd+'control') & 0xffffffff)
            self.jobb_id = str(binascii.crc32(self.fuzz_cmd + 'experiment') & 0xffffffff)
            self.rootdir = self.orthrusdir + ABTESTSDIR + '/{}'.format(self.id)

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
            self.joba_id = self._jobdesc['jobA_id']
            self.jobb_id = self._jobdesc['jobB_id']
            self.fuzzerA = self._jobdesc['fuzzerA']
            self.fuzzerB = self._jobdesc['fuzzerB']
        else:
            self.rootdir = self.orthrusdir + ROUTINEDIR + '/{}'.format(self.id)
        return True