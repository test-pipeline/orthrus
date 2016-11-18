#!/usr/bin/env python2

from shutil import rmtree
from sys import argv
import re
import glob
import os
import collections
import json
from spectrum import __version__
from orthrusutils.orthrusutils import import_unique_crashes, import_test_cases, spectrum_asan_options

try:
    import subprocess32 as subprocess
except ImportError:
    import subprocess


class AFLSancovReporter:
    """Base class for the AFL Sancov reporter"""

    Version = __version__
    Want_Output = True
    No_Output = False

    # func_cov_regex = re.compile(r"^(?P<filepath>[^:]+):(?P<linenum>\d+)\s" \
    #                             "(?P<function>[\w|\-|\:]+)$", re.MULTILINE)
    #
    line_cov_regex = re.compile(r"^(?P<function>[\w|\-|\:]+)$\n"
                                r"^(?P<filepath>[^:]+):(?P<linenum>\d+):(?P<colnum>\d+)$",
                                re.MULTILINE)

    # Is_Crash_Regex     = re.compile(r"id.*,(sig:\d{2}),.*")
    # find_crash_parent_regex = re.compile(r"^(HARDEN\-|ASAN\-)?(?P<session>[\w|\-]+):id.*?"
    #                                      r"(sync:(?P<sync>[\w|\-]+))?,src:(?P<id>\d+).*$")


    # This regex merges legacy Is_Crash_Regex and namesake
    # old_find_crash_parent_regex = re.compile(r"^(HARDEN\-|ASAN\-)?((?P<session>[\w|\-]+):)?id:\d+,sig:\d+,"
    #                                      r"(sync:(?P<sync>[\w|\-]+),)?src:(?P<id>\d+).*$")
    find_queue_parent_regex = re.compile(r"id:\d+,(sync:(?P<sync>[\w|\-]+),)?src:(?P<id>\d+).*$")

    # For proposed successor of current naming convention
    find_crash_parent_regex = re.compile(r"^(HARDEN:|ASAN:)?((?P<session>[\w|\-]+):)?id:\d+,sig:\d+,"
                                         r"(sync:(?P<sync>[\w|\-]+),)?src:(?P<id>\d+).*$")


    def __init__(self, parsed_args, cov_cmd, bin_path, crash_dir, afl_out, sanitizer):

        self.args = parsed_args
        self.coverage_cmd = cov_cmd
        self.bin_path = bin_path
        self.crash_dir = crash_dir
        self.afl_fuzzing_dir = afl_out
        self.sanitizer = sanitizer

        self.cov_paths = {}

        ### global coverage tracking dictionary
        self.global_pos_report = set()
        self.global_zero_report = set()

        ### For diffs between two consecutive queue files
        self.curr_pos_report = set()
        self.curr_zero_report = set()
        self.prev_pos_report = set()
        self.prev_zero_report = set()

        ### For use in dd-mode
        self.crashdd_pos_report = set()
        # self.crashdd_zero_report = set()
        self.parentdd_pos_report = set()
        # self.parentdd_zero_report = set()

        ### List of all tuples singularly in crash positive reports
        self.crashdd_pos_list = []

    def setup_parsing(self):
        self.bin_name = os.path.basename(self.bin_path)
        self.sancov_filename_regex = re.compile(r"%s.\d+.sancov" % self.bin_name)

    def run(self):
        if self.args.version:
            print "afl-sancov-" + self.Version
            return 0

        if not self.validate_args():
            return 1

        if not self.init_tracking():
            return 1

        self.setup_parsing()

        if self.args.dd_num == 1:
            rv = self.process_afl_crashes()
        else:
            rv = self.process_afl_crashes_deep()

        return not rv

    def join_tuples_in_list(self, list):
        for idx, tpl in enumerate(list):
            list[idx] = ':'.join(str(val) for val in tpl)
        return

    def jsonify_slice(self, slice_list, crashfile, jsonfilename):
        dict = {"crashing-input": crashfile, "slice-node-spec": []}
        self.join_tuples_in_list(slice_list)
        counter = collections.Counter(slice_list)
        sorted_list = counter.most_common()
        for tpl in sorted_list:
            dict['slice-node-spec'].append({'line': tpl[0], 'count': tpl[1]})
        dict['slice-linecount'] = len(sorted_list)

        self.jsonify_dict(jsonfilename, dict)

    def jsonify_dice(self, crashfile, jsonfilename, parentfile=None):

        if parentfile:
            dict = {"crashing-input": crashfile, "parent-input": parentfile, "diff-node-spec": []}
        else:
            dict = {"crashing-input": crashfile, "diff-node-spec": []}

        self.join_tuples_in_list(self.crashdd_pos_list)

        counter = collections.Counter(self.crashdd_pos_list)

        sorted_list = counter.most_common()
        for tpl in sorted_list:
            dict['diff-node-spec'].append({'line': tpl[0], 'count': tpl[1]})

        # self.prev_pos_report contains crash file's exec slice
        slice_linecount = len(self.prev_pos_report)
        dice_linecount = len(sorted_list)

        dict['slice-linecount'] = slice_linecount
        dict['dice-linecount'] = dice_linecount
        dict['shrink-percent'] = 100 - (float(dice_linecount)/slice_linecount)*100

        self.jsonify_dict(jsonfilename, dict)

        return

    def jsonify_dict(self, filename, dict):
        with open(filename, "w") as file:
            json.dump(dict, file, indent=4)

    def write_dice_as_json(self, cbasename, pbasename=None):
        crashdd_outfile = self.cov_paths['dice_dir'] + '/' + cbasename + '.json'

        # header = "diff crash ({}) -> parent ({})".format(cbasename, pbasename)
        # self.write_file(header, crashdd_outfile)
        if pbasename:
            self.jsonify_dice(cbasename, crashdd_outfile, pbasename)
        else:
            self.jsonify_dice(cbasename, crashdd_outfile)

        ## Reset state to be safe
        self.crashdd_pos_list = []

    def cleanup(self):
        ### Stash away all raw sancov files
        stash_dst = self.cov_paths['dd_stash_dir']
        if os.path.isdir(stash_dst):
            for file in sorted(glob.glob(self.cov_paths['dice_dir'] + '/*.sancov')):
                os.rename(file, stash_dst + '/' + os.path.basename(file))

        # Remove covered.txt
        covered = self.cov_paths['dice_dir'] + '/covered.txt'
        if os.path.isfile(covered):
            os.remove(covered)

    def parent_identical_or_crashes(self, crash, parent):

        # Base names
        cbasename = os.path.basename(crash)
        pbasename = os.path.basename(parent)

        ## Filter queue filenames with sig info
        if self.find_crash_parent_regex.match(pbasename):
            self.logr("Parent ({}) looks like crashing input!".format(pbasename))
            return True

        try:
            diff_out = subprocess.check_output("diff -q {} {}".format(crash, parent),
                                               stderr=subprocess.STDOUT, shell=True)
        except Exception, e:
            diff_out = e.output

        if not diff_out.rstrip("\n"):
            self.logr("Crash file ({}) and parent ({}) are identical!"
                      .format(cbasename, pbasename))
            return True

        cov_cmd = self.coverage_cmd.replace('AFL_FILE', parent)

        ### Dry-run to make sure parent doesn't cause a crash
        if self.does_dry_run_throw_error(cov_cmd):
            self.logr("Parent ({}) crashes binary!".format(pbasename))
            return True

        return False

    def generate_cov_for_parent(self, parent_fname):
        pbasename = os.path.basename(parent_fname)

        #### The output should be written to delta-diff dir
        #### as afl_input namesake witha sancov extension
        ### raw sancov file
        self.cov_paths['parent_sancov_raw'] = self.cov_paths['dice_dir'] + \
                                              '/' + pbasename + '.sancov'
        self.cov_paths['parent_afl'] = pbasename

        cov_cmd = self.coverage_cmd.replace('AFL_FILE', parent_fname)
        ### execute the command to generate code coverage stats
        ### for the current AFL test case file
        sancov_env = self.get_sancov_env(self.cov_paths['parent_sancov_raw'], pbasename)

        self.run_cmd(cov_cmd, self.No_Output, sancov_env)

        if self.args.sancov_bug:
            sancovfile = "".join(glob.glob("*.sancov"))
            cov_cmd = 'mv {} {}'.format(sancovfile, self.cov_paths['dice_dir'])
            self.run_cmd(cov_cmd, self.No_Output)

        # This renames default sancov file to specified filename
        # and populates self.curr* report with non-crashing input's
        # linecov info.
        if not self.rename_and_extract_linecov(self.cov_paths['parent_sancov_raw']):
            self.logr("Error generating cov info for parent {}".format(pbasename))
            return False

        return True

    def generate_cov_for_crash(self, crash_fname):

        cbasename = os.path.basename(crash_fname)

        self.cov_paths['crash_sancov_raw'] = self.cov_paths['dice_dir'] + \
                                             '/' + cbasename + '.sancov'

        self.cov_paths['crash_afl'] = cbasename

        ### Make sure crashing input indeed triggers a program crash
        cov_cmd = self.coverage_cmd.replace('AFL_FILE', crash_fname)

        if not self.does_dry_run_throw_error(cov_cmd):
            self.logr("Crash input ({}) does not crash the program! Filtering crash file."
                      .format(cbasename))
            os.rename(crash_fname, self.cov_paths['dd_filter_dir'] + '/' + cbasename)
            return False

        ### execute the command to generate code coverage stats
        ### for the current AFL test case file
        sancov_env = self.get_sancov_env(self.cov_paths['crash_sancov_raw'], cbasename)

        self.run_cmd(cov_cmd, self.No_Output, sancov_env)

        if self.args.sancov_bug:
            rawfilename = "".join(glob.glob("*.sancov.raw"))
            mapfilename = "".join(glob.glob("*.sancov.map"))

            cov_cmd = 'mv {} {} {}'.format(rawfilename, mapfilename,
                                            self.cov_paths['dice_dir'])
            self.run_cmd(cov_cmd, self.No_Output)

        globstrraw = os.path.basename("".join(glob.glob(self.cov_paths['dice_dir'] + "/*.sancov.raw")))
        globstrmap = os.path.basename("".join(glob.glob(self.cov_paths['dice_dir'] + "/*.sancov.map")))
        ### Run pysancov rawunpack before calling rename
        self.run_cmd("cd {}; pysancov rawunpack {} ; rm {} {}".format(self.cov_paths['dice_dir'],
                                                                      globstrraw, globstrraw, globstrmap),
                     self.No_Output)
        # self.run_cmd("cd pysancov rawunpack " + globstrraw + " ; rm " + globstrraw + " " + globstrmap, self.No_Output)

        # This renames default sancov file to specified filename
        # and populates self.curr* report with non-crashing input's
        # linecov info.
        if not self.rename_and_extract_linecov(self.cov_paths['crash_sancov_raw']):
            self.logr("Error generating coverage info for crash file {}".format(cbasename))
            return False

        return True

    def process_afl_crashes_deep(self):

        '''
        1. Process crash file
        2. Pick and process crash file's parent and N other randomly selected queue files
        3. Do a repeated intersection of s.difference(t)
        :return:
        '''

        crash_files = import_unique_crashes(self.crash_dir)
        num_crash_files = len(crash_files)

        self.logr("\n*** Imported %d new crash files from: %s\n" \
                  % (num_crash_files, (self.afl_fuzzing_dir + '/unique')))

        if not self.import_afl_dirs():
            return False

        fuzzdirs = self.cov_paths['dirs'].keys()
        queue_files = []
        for val in fuzzdirs:
            queue_files.extend(import_test_cases(val + '/queue'))

        crash_file_counter = 0

        for crash_fname in crash_files:

            crash_file_counter += 1
            self.logr("[+] Processing crash file ({}/{})".format(crash_file_counter, num_crash_files))

            cbasename = os.path.basename(crash_fname)

            if not self.generate_cov_for_crash(crash_fname):
                continue

            # Store this in self.prev_pos_report
            self.prev_pos_report = self.curr_pos_report

            queue_cnt = 0
            # Find parent
            pname = self.find_parent_crashing(crash_fname)

            while queue_cnt < self.args.dd_num:

                if queue_cnt > 0:
                    pname = self.find_queue_parent(pname)
                    if not pname:
                        self.logr("Cannot find ancestors of crash file {}. Bailing out".format(cbasename))
                        break

                while pname and self.parent_identical_or_crashes(crash_fname, pname):
                    self.logr("Looking up ancestors of crash file {}".format(cbasename))
                    pname = self.find_queue_parent(pname)

                if not pname:
                    self.logr("Cannot find ancestors of crash file {}. Bailing out".format(cbasename))
                    break

                # Select a random queue file
                # pname = random.choice(queue_files)

                # if self.parent_identical_or_crashes(crash_fname, pname):
                #     self.logr("Skipping parent of crash file {}".format(cbasename))
                #     continue

                if not self.generate_cov_for_parent(pname):
                    self.logr("Error generating cov info for parent of {}".format(cbasename))
                    continue

                # Increment queue_cnt
                queue_cnt += 1
                self.logr("Processing parent {}/{}".format(queue_cnt, self.args.dd_num))

                # Obtain Pc.difference(Pnc) and write to file
                self.crashdd_pos_report = self.prev_pos_report.difference(self.curr_pos_report)
                self.crashdd_pos_report = sorted(self.crashdd_pos_report, \
                                                 key=lambda cov_entry: (cov_entry[0], cov_entry[2], cov_entry[3]))

                # Extend the global list with current crash delta diff
                self.crashdd_pos_list.extend(self.crashdd_pos_report)

            self.write_dice_as_json(cbasename)
            # Write Crash coverage to slice dir
            self.jsonify_slice(list(self.prev_pos_report), cbasename,
                               self.cov_paths['slice_dir'] + '/' + cbasename + '.json')

        self.cleanup()
        return True

    def process_afl_crashes(self):

        '''
        1. Process crash file
        2. Pick and process crash file's parent
        3. Do a s.difference(t)
        :return:
        '''

        crash_files = import_unique_crashes(self.crash_dir)
        num_crash_files = len(crash_files)

        self.logr("\n*** Imported %d new crash files from: %s\n" \
                  % (num_crash_files, (self.afl_fuzzing_dir + '/unique')))

        crash_file_counter = 0

        for crash_fname in crash_files:

            crash_file_counter += 1
            self.logr("[+] Processing crash file ({}/{})".format(crash_file_counter, num_crash_files))

            # Find parent
            pname = self.find_parent_crashing(crash_fname)
            cbasename = os.path.basename(crash_fname)

            ### AFL corpus sometimes contains parent file that is identical to crash file
            ### or a parent (in queue) that also crashes the program. In case we bump into
            ### such parents, we try to recursively find their parent i.e., the crash file's
            ### ancestor.
            while pname and self.parent_identical_or_crashes(crash_fname, pname):
                self.logr("Looking up ancestors of crash file {}".format(cbasename))
                pname = self.find_queue_parent(pname)

            if not pname:
                self.logr("No non-identical parent of crash file {} found. Bailing out!".format(cbasename))
                continue

            pbasename = os.path.basename(pname)

            if not self.generate_cov_for_parent(pname):
                self.logr("Error generating cov info for parent of {}".format(cbasename))
                continue

            self.prev_pos_report = self.curr_pos_report
            self.prev_zero_report = self.curr_zero_report

            if not self.generate_cov_for_crash(crash_fname):
                continue

            # Obtain Pc.difference(Pnc) and write to file
            self.crashdd_pos_report = self.curr_pos_report.difference(self.prev_pos_report)

            self.crashdd_pos_list = sorted(self.crashdd_pos_report, \
                                           key=lambda cov_entry: (cov_entry[0], cov_entry[2], cov_entry[3]))

            self.write_dice_as_json(cbasename, pbasename)

            # Write Crash coverage to slice dir
            self.jsonify_slice(list(self.curr_pos_report), cbasename,
                               self.cov_paths['slice_dir'] + '/' + cbasename + '.json')

        self.cleanup()
        return True

    def get_parent(self, filepath, isCrash=True):

        dirname, basename = os.path.split(filepath)

        if isCrash:
            match = self.find_crash_parent_regex.match(basename)
            # (_, _, session, _, syncname, src_id) = match.groups()
            (_, _, session, _, syncname, src_id) = match.groups()

            searchdir = self.afl_fuzzing_dir
            # if syncname:
            #     searchdir += '/' + syncname + '/queue'
            if session:
                searchdir += '/' + session + '/queue'
            else:
                assert False, "Parent of crash file {} cannot be found".format(basename)


        else:
            match = self.find_queue_parent_regex.match(basename)
            if not match:
                self.logr("No parent could be found for {}".format(basename))
                return None

            (_, syncname, src_id) = match.groups()

            searchdir = dirname

            if syncname:
                searchdir += '/../../' + syncname + '/queue'


        search_cmd = "find " + searchdir + " -maxdepth 1" + " -name id:" + src_id + "*"

        parent_fname = subprocess.check_output(search_cmd, stderr=subprocess.STDOUT, shell=True)

        parent_list = filter(None, parent_fname.split("\n"))
        if (len(parent_list) == 0):
            self.logr("No parents found for file {}".format(basename))
            return None

        if (len(parent_list) > 1):
            self.logr("Multiple parents found for file {}. Selecting first.".format(basename))

        return os.path.abspath(parent_list[0].rstrip("\n"))

    def find_queue_parent(self, queue_fname):
        return self.get_parent(queue_fname, False)

    def find_parent_crashing(self, crash_fname):
        return self.get_parent(crash_fname)

    def init_tracking(self):

        self.cov_paths['top_dir'] = self.afl_fuzzing_dir + '/../crash-analysis/spectrum/{}'.format(self.sanitizer)
        self.cov_paths['log_file'] = self.cov_paths['top_dir'] + '/afl-sancov.log'
        self.cov_paths['tmp_out'] = self.cov_paths['top_dir'] + '/cmd-out.tmp'

        ### global coverage results
        self.cov_paths['zero_cov'] = self.cov_paths['top_dir'] + '/zero-cov'
        self.cov_paths['pos_cov'] = self.cov_paths['top_dir'] + '/pos-cov'

        self.cov_paths['dirs'] = {}
        self.cov_paths['parent_afl'] = ''
        self.cov_paths['crash_afl'] = ''
        self.cov_paths['parent_sancov_raw'] = ''
        self.cov_paths['crash_sancov_raw'] = ''
        # Diff in delta debug mode
        self.cov_paths['slice_dir'] = self.cov_paths['top_dir'] + '/slice'
        self.cov_paths['dice_dir'] = self.cov_paths['top_dir'] + '/dice'
        self.cov_paths['dd_stash_dir'] = self.cov_paths['dice_dir'] + '/.raw'
        self.cov_paths['dd_filter_dir'] = self.cov_paths['dice_dir'] + '/.filter'
        self.cov_paths['dd_final_stats'] = self.cov_paths['dice_dir'] + '/final_stats.dd'

        if self.args.overwrite:
            self.init_mkdirs()
        else:
            if self.is_dir(self.cov_paths['top_dir']):
                print "[*] Existing coverage dir %s found, use --overwrite to " \
                      "re-calculate coverage" % (self.cov_paths['top_dir'])
                return False
            else:
                self.init_mkdirs()

        self.write_status(self.cov_paths['top_dir'] + '/afl-sancov-status')
        return True

    def import_afl_dirs(self):

        if not self.afl_fuzzing_dir:
            print "[*] Must specify AFL fuzzing dir with --afl-fuzzing-dir or -d"
            return False

        assert 'top_dir' in self.cov_paths, "Trying to import fuzzing data without sancov dir"

        def_dir = self.afl_fuzzing_dir

        if self.is_dir(def_dir + '/queue'):
            if def_dir not in self.cov_paths['dirs']:
                self.add_fuzz_dir(def_dir)
        else:
            for p in os.listdir(def_dir):
                fuzz_dir = def_dir + '/' + p
                if self.is_dir(fuzz_dir):
                    if self.is_dir(fuzz_dir + '/queue'):
                        ### found an AFL fuzzing directory instance
                        if fuzz_dir not in self.cov_paths['dirs']:
                            self.add_fuzz_dir(fuzz_dir)

        return True

    def get_sancov_env(self, sancov_output, afl_input):

        fpath, fname = os.path.split(sancov_output)

        sancov_env = os.environ.copy()
        if self.sanitizer == "asan":
            if self.find_crash_parent_regex.match(afl_input):
                if not self.args.sancov_bug:
                    spectrum_asan_options(sancov_env, 'coverage=1:coverage_direct=1:coverage_dir={}'.format(fpath))
                else:
                    spectrum_asan_options(sancov_env, 'coverage=1:coverage_direct=1')
            else:
                if not self.args.sancov_bug:
                    spectrum_asan_options(sancov_env, 'coverage=1:coverage_dir={}'.format(fpath))
                else:
                    spectrum_asan_options(sancov_env, 'coverage=1')
        else:
            if self.find_crash_parent_regex.match(afl_input):
                if not self.args.sancov_bug:
                    sancov_env['UBSAN_OPTIONS'] = 'coverage=1:coverage_direct=1:' \
                                              'coverage_dir=%s' % fpath
                else:
                    sancov_env['UBSAN_OPTIONS'] = 'coverage=1:coverage_direct=1'
            else:
                if not self.args.sancov_bug:
                    sancov_env['UBSAN_OPTIONS'] = 'coverage=1:coverage_dir=%s' % fpath
                else:
                    sancov_env['UBSAN_OPTIONS'] = 'coverage=1'

        return sancov_env

    # Rename <binary_name>.<pid>.sancov to user-supplied `sancov_fname`
    # Extract linecov info into self.curr* report
    def rename_and_extract_linecov(self, sancov_fname):
        out_lines = []

        # Raw sancov file in fpath
        fpath, fname = os.path.split(sancov_fname)
        # Find and rename sancov file
        if not self.find_sancov_file_and_rename(fpath, sancov_fname):
            return False

        # Positive line coverage
        # sancov -obj torture_test -print torture_test.28801.sancov 2>/dev/null | llvm-symbolizer -obj torture_test > out
        out_lines = self.run_cmd(self.args.sancov_path \
                                 + " -obj " + self.bin_path \
                                 + " -print " + sancov_fname \
                                 + " 2>/dev/null" \
                                 + " | " + self.args.llvm_sym_path \
                                 + " -obj " + self.bin_path,
                                 self.Want_Output)

        # Pos line coverage
        # self.write_file("\n".join(out_lines), cp['pos_line_cov'])
        # In-memory representation
        self.curr_pos_report = self.linecov_report("\n".join(out_lines))
        if not self.curr_pos_report:
            return False

        # Zero line coverage
        # pysancov print cp['sancov_raw'] > covered.txt
        # pysancov missing bin_path < covered.txt 2>/dev/null | llvm-symbolizer -obj bin_path > cp['zero_line_cov']
        covered = os.path.join(fpath, "covered.txt")
        out_lines = self.run_cmd(self.args.pysancov_path \
                                 + " print " + sancov_fname + " > " + covered + ";" \
                                 + " " + self.args.pysancov_path + " missing " + self.bin_path \
                                 + " < " + covered + " 2>/dev/null | " \
                                 + self.args.llvm_sym_path + " -obj " + self.bin_path,
                                 self.Want_Output)
        self.curr_zero_report = self.linecov_report("\n".join(out_lines))

        # Pos func coverage
        # sancov -demangle -obj bin_path -covered-functions cp['sancov_raw'] 2>/dev/null
        # out_lines = self.run_cmd(self.args.sancov_path \
        #                          + " -demangle" + " -obj " + self.bin_path \
        #                          + " -covered-functions " + cp['sancov_raw'] + " 2>/dev/null",
        #                          self.Want_Output)
        # # self.write_file("\n".join(out_lines), cp['pos_func_cov'])
        # self.curr_reports.append(FuncCov_Report("\n".join(out_lines)))

        # Zero func coverage
        # sancov -demangle -obj bin_path -not-covered-functions cp['sancov_raw'] 2>/dev/null
        # out_lines = self.run_cmd(self.args.sancov_path \
        #                          + " -demangle" + " -obj " + self.bin_path \
        #                          + " -not-covered-functions " + cp['sancov_raw'] + " 2>/dev/null",
        #                          self.Want_Output)
        # # self.write_file("\n".join(out_lines), cp['zero_func_cov'])
        # self.curr_reports.append(FuncCov_Report("\n".join(out_lines)))
        return True

    def linecov_report(self, repstr):
        return set((fp, func, ln, col) for (func, fp, ln, col) \
                   in re.findall(self.line_cov_regex, repstr))
        # Don't do this if you want to keep sets
        # return sorted(s, key=lambda cov_entry: cov_entry[0])

    def find_sancov_file_and_rename(self, searchdir, newname):

        for filename in os.listdir(searchdir):
            match = self.sancov_filename_regex.match(filename)
            if match and match.group(0):
                src = os.path.join(searchdir, match.group(0))
                if os.path.isfile(src):
                    os.rename(src, newname)
                    return True
                assert False, "sancov file is a directory!"

        # assert False, "sancov file {} not found!".format(newname)
        self.logr("Could not generate coverage info for parent {}. Bailing out!".format(newname))
        return False

    # Credit: http://stackoverflow.com/a/1104641/4712439
    def does_dry_run_throw_error(self, cmd):

        env = os.environ.copy()
        if self.sanitizer == 'asan':
            spectrum_asan_options(env)

        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, shell=True, env=env)
        except Exception, e:
            # OR condition is bug fix for compute shell returning negative instead of positive code
            return (e.returncode > 128 or e.returncode < 0)

        return False

    def run_cmd(self, cmd, collect, env=None):

        out = []

        if self.args.verbose:
            self.logr("    CMD: %s" % cmd)

        fh = None
        if self.args.disable_cmd_redirection or collect == self.Want_Output:
            fh = open(self.cov_paths['tmp_out'], 'w')
        else:
            fh = open(os.devnull, 'w')

        if env is None:
            subprocess.call(cmd, stdin=None,
                            stdout=fh, stderr=subprocess.STDOUT, shell=True, executable='/bin/bash')
        else:
            subprocess.call(cmd, stdin=None,
                            stdout=fh, stderr=subprocess.STDOUT, shell=True, env=env, executable='/bin/bash')

        fh.close()

        if self.args.disable_cmd_redirection or collect == self.Want_Output:
            with open(self.cov_paths['tmp_out'], 'r') as f:
                for line in f:
                    out.append(line.rstrip('\n'))

        return out

    def validate_args(self):
        if self.coverage_cmd:
            if 'AFL_FILE' not in self.coverage_cmd:
                print "[*] --coverage-cmd must contain AFL_FILE"
                return False
        else:
            print "[*] --coverage-cmd missing"
            return False

        if not self.afl_fuzzing_dir:
            print "[*] --afl-fuzzing-dir missing"
            return False

        if not self.crash_dir or not os.path.isdir(self.crash_dir):
            print "[*] --crash-dir missing or not a dir"
            return False

        if not self.bin_path:
            print "[*] Please provide path to coverage " \
                  "instrumented binary using the --bin-path argument"
            return False

        if not self.which(self.bin_path):
            print "[*] Could not find an executable binary in " \
                  "--bin-path '%s'" % self.bin_path
            return False

        if not self.which(self.args.sancov_path):
            print "[*] sancov command not found: %s" % (self.args.sancov_path)
            return False

        if not self.which(self.args.pysancov_path):
            print "[*] sancov.py script not found: %s" % (self.args.pysancov_path)
            return False

        if not self.which(self.args.llvm_sym_path):
            print "[*] llvm-symbolizer command not found: %s" % (self.args.llvm_sym_path)
            return False

        # if self.args.dd_mode and not self.args.dd_raw_queue_path:
        #     print "[*] --dd-mode requires --dd-raw-queue-path to be set"
        #     return False

        # if self.args.dd_mode and not self.args.dd_crash_file:
        #     print "[*] Pass crashing input to --dd-crash-file"
        #     return False

        return True

    ### credit: http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
    @staticmethod
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    @classmethod
    def which(cls, prog):
        fpath, fname = os.path.split(prog)
        if fpath:
            if cls.is_exe(prog):
                return prog
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path, prog)
                if cls.is_exe(exe_file):
                    return exe_file

        return None

    def add_fuzz_dir(self, fdir):
        self.cov_paths['dirs'][fdir] = {}
        self.cov_paths['dirs'][fdir]['prev_file'] = ''
        return

    def init_mkdirs(self):

        # lcov renamed cons and delta-diff dir added
        create_cov_dirs = 0
        if self.is_dir(self.cov_paths['top_dir']):
            if self.args.overwrite:
                rmtree(self.cov_paths['top_dir'])
                create_cov_dirs = 1
        else:
            create_cov_dirs = 1

        if create_cov_dirs:
            for k in ['top_dir']:
                os.makedirs(self.cov_paths[k])
            for k in ['slice_dir', 'dice_dir', 'dd_stash_dir', 'dd_filter_dir']:
                os.mkdir(self.cov_paths[k])
        return

    @staticmethod
    def is_dir(dpath):
        return os.path.exists(dpath) and os.path.isdir(dpath)

    def logr(self, pstr):
        if not self.args.quiet:
            print "    " + pstr
        self.append_file(pstr, self.cov_paths['log_file'])
        return

    @staticmethod
    def append_file(pstr, path):
        f = open(path, 'a')
        f.write("%s\n" % pstr)
        f.close()
        return

    @classmethod
    def write_status(cls, status_file):
        f = open(status_file, 'w')
        f.write("afl_sancov_pid     : %d\n" % os.getpid())
        f.write("afl_sancov_version : %s\n" % cls.Version)
        f.write("command_line       : %s\n" % ' '.join(argv))
        f.close()
        return