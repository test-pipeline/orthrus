import os
import shutil
from SanitizerReport import ASANReport
import subprocess
from orthrusutils.orthrusutils import import_unique_crashes, get_asan_report, runtime_asan_options, \
                                        func_wrapper, pprint_decorator_fargs, pprint_decorator

class RuntimeAnalyzer(object):

    def __init__(self, jobroot_dir, bin_path, target_cmd, crash_dir, sanitizer):
        self.bin_path = bin_path
        self.target_cmd = target_cmd
        self.crash_dir = crash_dir
        self.sanitizer = sanitizer
        self.env = os.environ.copy()
        if self.sanitizer == 'asan':
            runtime_asan_options(self.env)
        self.outdir = '{}/crash-analysis/runtime/{}'.format(jobroot_dir, sanitizer)
        self.mkdir_or_overwrite()

    def mkdir_or_overwrite(self):
        if os.path.exists(self.outdir):
            shutil.rmtree(self.outdir)
            os.makedirs(self.outdir)
        else:
            os.makedirs(self.outdir)

    def asan_helper(self, crash, count, total_crashes):
        report = ASANReport('.', True, '{}/{}.json'.format(self.outdir, os.path.basename(crash)))
        mystderr = []

        if not pprint_decorator_fargs(func_wrapper(get_asan_report, self.target_cmd.replace('@@', crash),
                                                   mystderr, self.env), 'Analyzing ASAN crash {} of {}'.
                                              format(count, total_crashes), indent=3):
            return False

        if not pprint_decorator_fargs(func_wrapper(report.parse, mystderr[0]), 'JSONifying ASAN report', indent=3):
            return False
        return True

    def harden_helper(self, crash, count, total_crashes):

        outfile = '{}/{}'.format(self.outdir, os.path.basename(crash))
        params = self.target_cmd.replace(self.bin_path, '').replace('@@', crash)

        ## Instead of parsing gdb output, obtain JSON via orthrus GDB plugin
        cmd = ['gdb',  '-q',  "-ex=set args {}".format(params), '-ex=r', '-ex=call $jsonify("{}.json")'.
            format(outfile), '-ex=quit', self.bin_path]
        ret = subprocess.Popen(cmd, stdout=None, stderr=subprocess.STDOUT).wait()
        if not pprint_decorator_fargs((ret == 0), 'JSONifying HARDEN crash {} of {}'.format(count, total_crashes),
                                      indent=3):
            return False
        return True

        # report = GdbExtractor(self.bin_path, params, '{}/{}.json'.format(self.outdir, os.path.basename(crash)))
        #
        # if not pprint_decorator(report.run, 'JSONifying HARDEN crash {} of {}'.format(count, total_crashes), indent=3):
        #     return False
        # return True

    def run(self):
        afl_crashes = import_unique_crashes(self.crash_dir)
        total_crashes = len(afl_crashes)
        count = 0
        for crash in afl_crashes:
            count += 1
            # FIXME: Error handling
            if self.sanitizer == 'asan':
                self.asan_helper(crash, count, total_crashes)
            elif self.sanitizer == 'harden':
                self.harden_helper(crash, count, total_crashes)
        return True