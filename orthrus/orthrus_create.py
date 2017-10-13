'''
Orthrus create implementation
'''
import os
import sys
import shutil
import subprocess
import random
import time
from orthrusutils import orthrusutils as util
from builder import builder as b

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