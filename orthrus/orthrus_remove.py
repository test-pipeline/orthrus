import os
import shutil
import time
from orthrusutils import orthrusutils as util
from job import job as j

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
                                           'Archiving data for {} job [{}]'.format(job_token.type, job_token.id),
                                           indent=2):
            return False

        j.remove_id_from_conf(job_token.jobsconf, job_token.id, job_token.type)
        return True