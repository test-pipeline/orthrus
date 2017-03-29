import sys
import subprocess
import os
import shutil
import ConfigParser
from argparse import ArgumentParser
import errno
import glob
import logging

CREATE_HELP = """Create an orthrus workspace"""
ADD_HELP = """Add a fuzzing job"""
REMOVE_HELP = """Remove a fuzzing job"""
START_HELP = """Start a fuzzing jobs"""
STOP_HELP = """Stop a fuzzing jobs"""
SHOW_HELP = """Show what's currently going on"""
TRIAGE_HELP = """Triage crash corpus"""
COVERAGE_HELP = """Run afl-cov on existing AFL corpus"""
SPECTRUM_HELP = """Run spectrum based analysis on existing AFL corpus"""
RUNTIME_HELP = """Perform dynamic analysis of existing AFL corpus"""
DESTROY_HELP = """Destroy an orthrus workspace"""
VALIDATE_HELP = """Check if all Orthrus dependencies are met"""
## A/B Tests
ABTEST_ADD_HELP = """Add an A/B test job based on supplied config"""

TEST_SLEEP = 5

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    INFO = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def color_print(color, msg):
    sys.stdout.write(color + msg + bcolors.ENDC + "\n")
    sys.stdout.flush()

def color_print_singleline(color, msg):
    sys.stdout.write(color + msg + bcolors.ENDC)
    sys.stdout.flush()

def run_cmd(command, env=None, logfile=None):
    if not logfile:
        logfile = os.devnull

    if not env:
        env = os.environ.copy()

    logfh = open(logfile, 'w')
    proc = subprocess.Popen(command, shell=True, executable='/bin/bash',
                            env=env, stdout=logfh, stderr=subprocess.STDOUT)
    ret = proc.wait()
    logfh.close()

    if ret != 0:
        return False
    return True


def return_elf_binaries(inpath=None):

    if not inpath:
        # Search everywhere in working dir except in .orthrus
        command = "find -type f -executable -not -path \"./.orthrus/*\"" \
                  " -exec file -i '{}' \; | grep 'x-executable; charset=binary' | cut -d':' -f1"
    else:
        # Search everywhere in specified path
        command = "find {} -type f ".format(inpath) + "-executable -exec file -i '{}' \; | " \
                                                     "grep 'x-executable; charset=binary' | " \
                                                     "cut -d':' -f1"
    output = subprocess.check_output(command, shell=True)
    return filter(None, output.split("\n"))

def copy_binaries(dest):
    # Create bin dir if it doesn't exist
    mkdir_p(dest)
    # if not os.path.isdir(dest):
    #     os.makedirs(dest)

    binaries = return_elf_binaries()
    # Overwriting existing binaries is fine
    for f in binaries:
        if not os.path.isfile(dest + os.path.basename(f)):
            shutil.copy(f, dest)


def parse_cmdline(description, args, createfunc=None, addfunc=None, removefunc=None,
                  startfunc=None, stopfunc=None, showfunc=None, triagefunc=None,
                  coveragefunc=None, spectrumfunc=None, runtimefunc=None, destroyfunc=None, validatefunc=None):
    argParser = ArgumentParser(description)

    argParser.add_argument('-v', '--verbose',
                           action='store_true',
                           help="""Verbose mode, print information about the progress""",
                           default=False)

    subparsers = argParser.add_subparsers(description="Orthrus subcommands")

    # Command 'create'
    create_parser = subparsers.add_parser('create', help=CREATE_HELP)
    create_parser.add_argument('-asan', '--afl-asan',
                               action='store_true',
                               help="""Setup binaries for afl with AddressSanitizer""",
                               default=False)
    create_parser.add_argument('-asanblacklist', '--afl-asan-blacklist', action='store_true',
                               help="""Setup binaries for afl with AddressSanitizer with issue supression.""",
                               default=False)
    create_parser.add_argument('-fuzz', '--afl-harden',
                               action='store_true',
                               help="""Setup binaries for afl in 'harden' mode (stack-protector, fortify)""",
                               default=False)
    create_parser.add_argument('-cov', '--coverage',
                               action='store_true',
                               help="""Setup binaries to collect coverage information""",
                               default=False)
    create_parser.add_argument('-sancov', '--san-coverage',
                               action='store_true',
                               help="""Setup binaries to collect sanitizer coverage information""",
                               default=False)
    create_parser.add_argument('-dict', '--dictionary',
                               action='store_true',
                               help="""Generate input dictionary for fuzzing""",
                               default=False)
    create_parser.add_argument('-d', '--configure-flags', nargs='?',
                               type=str, default="",
                               help='Additional flags for configuring the source')
    create_parser.set_defaults(func=createfunc)

    # Command 'add'
    add_parser = subparsers.add_parser('add', help=ADD_HELP)
    add_parser.add_argument('-n', '--job', required=True, type=str,
                            help='Add a job with executable command line invocation string')
    # add_parser.add_argument('-j', '--job-id', nargs='?',
    #                         type=str, default="",
    #                         help='Job Id for the job which should be selected')
    add_parser.add_argument('-i', '--import', dest='_import', nargs='?',
                            type=str, default="",
                            help='Import an AFL fuzzing output directory provided as tar.gz')
    add_parser.add_argument('-s', '--sample', nargs='?',
                            type=str, default="",
                            help='A single file or directory of afl testcases for fuzzing')
    add_parser.add_argument('-abtest-conf', '--abconf', nargs='?', type=str,
                            default="", help=ABTEST_ADD_HELP)
    add_parser.set_defaults(func=addfunc)

    # Command 'remove'
    remove_parser = subparsers.add_parser('remove', help=REMOVE_HELP)
    remove_parser.add_argument('-j', '--job-id', required=True,
                               type=str, help='Job Id for the job which should be removed')
    remove_parser.set_defaults(func=removefunc)

    # Command 'start'
    start_parser = subparsers.add_parser('start', help=START_HELP)
    start_parser.add_argument('-j', '--job-id', required=True,
                              type=str, help='Job Id for the job which should be started')
    start_parser.add_argument('-c', '--coverage',
                              action='store_true',
                              help="""Collect coverage information while fuzzing""",
                              default=False)
    start_parser.add_argument('-m', '--minimize',
                              action='store_true',
                              help="""Minimize corpus before start""",
                              default=False)
    start_parser.set_defaults(func=startfunc)

    # Command 'stop'
    stop_parser = subparsers.add_parser('stop', help=STOP_HELP)
    stop_parser.add_argument('-c', '--coverage',
                             action='store_true',
                             help="""Stop afl-cov instances on stop""",
                             default=False)
    stop_parser.add_argument('-j', '--job-id', required=True,
                              type=str, help='Job Id for the job which should be stopped')
    stop_parser.set_defaults(func=stopfunc)

    # Command 'show'
    show_parser = subparsers.add_parser('show', help=SHOW_HELP)
    show_parser.add_argument('-j', '--job-id', type=str, help='Job Id for the job which should be stopped')
    show_parser.add_argument('-conf', '--conf', action='store_true', help="""Show configured jobs""", default=False)
    show_parser.add_argument('-cov', '--cov', action='store_true', help="""Show coverage of job""", default=False)
    show_parser.set_defaults(func=showfunc)

    # Command 'triage'
    triage_parser = subparsers.add_parser('triage', help=TRIAGE_HELP)
    triage_parser.add_argument('-j', '--job-id', required=True,
                               type=str, default="",
                               help="""Job Id for the job which should be triaged""")
    triage_parser.set_defaults(func=triagefunc)

    # Command 'coverage'
    coverage_parser = subparsers.add_parser('coverage', help=COVERAGE_HELP)
    coverage_parser.add_argument('-j', '--job-id', type=str, default="", required=True,
                               help="""Job Id for checking coverage""")
    coverage_parser.set_defaults(func=coveragefunc)

    # Command 'spectrum': Merges afl-sancov functionality
    spectrum_parser = subparsers.add_parser('spectrum', help=SPECTRUM_HELP)
    spectrum_parser.add_argument('-j', '--job-id', type=str, default="", required=True,
                               help="""Job Id for spectrum based analysis""")

    spectrum_parser.add_argument("-O", "--overwrite", action='store_true',
                                 help="Overwrite existing coverage results", default=False)
    spectrum_parser.add_argument("--disable-cmd-redirection", action='store_true',
                                 help="Disable redirection of command results to /dev/null",
                                 default=False)
    spectrum_parser.add_argument("--coverage-include-lines", action='store_true',
                                 help="Include lines in zero-coverage status files",
                                 default=False)
    spectrum_parser.add_argument("--preserve-all-sancov-files", action='store_true',
                                 help="Keep all sancov files (not usually necessary)",
                                 default=False)
    spectrum_parser.add_argument("-v", "--verbose", action='store_true',
                                 help="Verbose mode", default=False)
    spectrum_parser.add_argument("-V", "--version", action='store_true',
                                 help="Print version and exit", default=False)
    spectrum_parser.add_argument("-q", "--quiet", action='store_true',
                                 help="Quiet mode", default=False)
    spectrum_parser.add_argument("--sancov-path", type=str,
                                 help="Path to sancov binary", default=which('sancov-3.8'))
    spectrum_parser.add_argument("--pysancov-path", type=str,
                                 help="Path to sancov.py script (in clang compiler-rt)",
                                 default=which("pysancov"))
    spectrum_parser.add_argument("--llvm-sym-path", type=str,
                                 help="Path to llvm-symbolizer", default=which("llvm-symbolizer-3.8"))
    spectrum_parser.add_argument("--dd-num", type=int,
                                 help="Experimental! Perform more compute intensive analysis of crashing input by comparing its"
                                      "path profile with aggregated path profiles of N=dd-num randomly selected non-crashing inputs",
                                 default=1)
    spectrum_parser.add_argument("--sancov-bug", action='store_true',
                                 help="Sancov bug that occurs for certain coverage_dir env vars", default=False)
    spectrum_parser.set_defaults(func=spectrumfunc)

    # Command 'runtime'
    runtime_parser = subparsers.add_parser('runtime', help=RUNTIME_HELP)
    runtime_parser.add_argument('-j', '--job-id', type=str, default="", required=True,
                               help="""Job Id for dynamic analysis""")
    runtime_parser.add_argument("-regen", "--regenerate", action='store_true',
                                 help="Regenerate dynamic info, archiving old results", default=False)
    runtime_parser.set_defaults(func=runtimefunc)

    # Command 'destroy'
    destroy_parser = subparsers.add_parser('destroy', help=DESTROY_HELP)
    destroy_parser.set_defaults(func=destroyfunc)

    # Command 'validate'
    validate_parser = subparsers.add_parser('validate', help=VALIDATE_HELP)
    validate_parser.set_defaults(func=validatefunc)

    return argParser.parse_args(args)

def parse_config(configfile=None):
    config = {}
    if not configfile:
        configfile = os.path.expanduser('~/.orthrus/orthrus.conf')

    configparser = ConfigParser.ConfigParser()
    configparser.read(configfile)

    config['orthrus'] = {}
    config['orthrus']['directory'] = configparser.get("orthrus", "directory")

    config['dependencies'] = configparser.items("dependencies")

    return config

def min_or_reseed_setup(orthrus_dir, target, params):
    export = {}
    export['PYTHONUNBUFFERED'] = "1"
    env = os.environ.copy()
    env.update(export)
    isasan = False

    if os.path.exists(orthrus_dir + "/binaries/afl-harden"):
        launch = orthrus_dir + "/binaries/afl-harden/bin/" + target + " " + \
                 params.replace("&", "\&")
    else:
        isasan = True
        launch = orthrus_dir + "/binaries/afl-asan/bin/" + target + " " + \
                 params

    if isasan and is64bit():
        mem_limit = 30000000
    else:
        mem_limit = 800
    return (env, launch, mem_limit)

def minimize_sync_dir(orthrus_dir, jobroot_dir, job_id, target, params):
    color_print(bcolors.OKGREEN, "\t\t[+] Minimizing corpus for job [" + job_id + "]...")

    env, launch, mem_limit = min_or_reseed_setup(orthrus_dir, target, params)

    cmin = " ".join(
        ["afl-minimize", "-c", jobroot_dir + "/collect", "--cmin",
         "--cmin-mem-limit={}".format(mem_limit), "--cmin-timeout=5000", "--dry-run",
         jobroot_dir + "/afl-out", "--", "'" + launch + "'"])
    p = subprocess.Popen(cmin, bufsize=0, shell=True, executable='/bin/bash', env=env, stdout=subprocess.PIPE)
    for line in p.stdout:
        if "[*]" in line or "[!]" in line:
            color_print(bcolors.OKGREEN, "\t\t\t" + line)
    return True

def reseed_sync_dir(orthrus_dir, jobroot_dir, job_id, target, params):
    color_print(bcolors.OKGREEN, "\t\t[+] Reseeding job [" + job_id + "]...")

    env, launch, mem_limit = min_or_reseed_setup(orthrus_dir, target, params)

    reseed_cmd = " ".join(
        ["afl-minimize", "-c", jobroot_dir + "/collect.cmin",
         "--reseed", jobroot_dir + "/afl-out", "--",
         "'" + launch + "'"])
    p = subprocess.Popen(reseed_cmd, bufsize=0, shell=True, executable='/bin/bash', env=env, stdout=subprocess.PIPE)
    for line in p.stdout:
        if "[*]" in line or "[!]" in line:
            color_print(bcolors.OKGREEN, "\t\t\t" + line)

    if os.path.exists(jobroot_dir + "/collect"):
        shutil.rmtree(jobroot_dir + "/collect")
    if os.path.exists(jobroot_dir + "/collect.cmin"):
        shutil.rmtree(jobroot_dir + "/collect.cmin")
    return True

def minimize_and_reseed(orthrus_dir, jobroot_dir, job_id, target, params):
    minimize_sync_dir(orthrus_dir, jobroot_dir, job_id, target, params)
    reseed_sync_dir(orthrus_dir, jobroot_dir, job_id, target, params)
    return True

def is64bit():
    cmd = 'uname -m'
    try:
        if 'x86_64' in subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT):
            return True
    except subprocess.CalledProcessError as e:
        print e.output
    return False

def getnproc():
    cmd = 'nproc'
    try:
        nproc = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return 1
    return nproc.rstrip()

# def printfile(filename):
#     cmd = 'cat ' + filename
#     print subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

def which(progname):
    cmd = 'which ' + progname
    try:
        path = os.path.expanduser(subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).rstrip())
    except subprocess.CalledProcessError as e:
        print e.output
        return ''
    return os.path.abspath(path)

def run_afl_cov(orthrus_dir, jobroot_dir, target_arg, params, livemode=False, test=False):
    target = orthrus_dir + "/binaries/coverage/gcc/bin/" + \
             target_arg + " " + params.replace("@@", "AFL_FILE")

    if livemode:
        cmd = ["nohup", "afl-cov", "-d", jobroot_dir + "/afl-out", "--live", "--lcov-path", which('lcov'),
               "--genhtml-path", which('genhtml'), "--coverage-cmd", "'" + target + "'", "--code-dir", "."]
        if test:
            cmd.extend(['--sleep', str(TEST_SLEEP)])
    else:
        cmd = ["nohup", "afl-cov", "-d", jobroot_dir + "/afl-out", "--lcov-path", which('lcov'), "--genhtml-path",
               which('genhtml'), "--coverage-cmd", "'" + target + "'", "--code-dir", "."]
    logfile = orthrus_dir + "/logs/afl-coverage.log"
    p = subprocess.Popen(" ".join(cmd), shell=True, executable="/bin/bash", stdout=open(logfile, 'w'),
                         stderr=subprocess.STDOUT)
    return True

def validate_inst(config):

    if not config['dependencies']:
        return False

    for program, mode in config['dependencies']:
        if mode == 'on' and not which(program):
            color_print(bcolors.FAIL, "\t\t\t[-] Could not locate {}. Perhaps modifying the PATH variable helps?".
                        format(program))
            return False
    return True

def func_wrapper(function, *args):
    try:
        rv = function(*args)
        if rv is None or rv:
            return True
        else:
            return False
    except:
        logging.basicConfig(level=logging.ERROR, filename='.pyexp')
        logging.exception('Traceback of an exception raised during Orthrus invocation follows')
        return False

def pprint_decorator_fargs(predicate, prologue, indent=0, fail_msg='failed', success_msg='done'):

    color_print_singleline(bcolors.OKGREEN, '\t'*indent + '[+] {}... '.format(prologue))

    if not predicate:
        color_print(bcolors.FAIL, fail_msg)
        return False
    else:
        color_print(bcolors.OKGREEN, success_msg)
        return True

def pprint_decorator(function, prologue, indent=0, fail_msg='failed', success_msg='done'):

    color_print_singleline(bcolors.OKGREEN, '\t'*indent + '[+] {}... '.format(prologue))

    try:
        rv = function()
        if rv is None or rv:
            color_print(bcolors.OKGREEN, success_msg)
            return True
        else:
            color_print(bcolors.FAIL, fail_msg)
            return False
    except:
        logging.basicConfig(level=logging.ERROR, filename='.pyexp')
        logging.exception('Traceback of an exception raised during Orthrus invocation follows')
        color_print(bcolors.FAIL, fail_msg)
        return False

# HT: http://stackoverflow.com/a/600612/4712439
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

def import_test_cases(qdir):
    return sorted(glob.glob(qdir + "/id:*"))

def import_unique_crashes(dir):
    return sorted(glob.glob(dir + "/*id:*"))

def get_asan_report(cmd, strbuf, env=None):

    if not env:
        env = os.environ.copy()


    proc = subprocess.Popen(cmd, shell=True, executable='/bin/bash',
                            env=env, stdout=open(os.devnull), stderr=subprocess.PIPE)
    strbuf.append(proc.communicate()[1])

    return True

def overrride_default_afl_asan_options(env):
    env.update({'ASAN_OPTIONS': 'abort_on_error=1:detect_leaks=0:symbolize=0:handle_segv=0:allocator_may_return_null=1'})

def triage_asan_options(env):
    env.update({'ASAN_OPTIONS': 'abort_on_error=1:detect_leaks=0:symbolize=1:handle_segv=0:allocator_may_return_null=1:'
                                'disable_core=1'})

def spectrum_asan_options(env, extra=None):
    if extra:
        env.update({'ASAN_OPTIONS': 'abort_on_error=1:detect_leaks=0:symbolize=1:handle_segv=0:allocator_may_return_null=1:'
                                'disable_core=1:{}'.format(extra)})
    else:
        triage_asan_options(env)

def runtime_asan_options(env):
    env.update({'ASAN_OPTIONS': 'detect_leaks=0:symbolize=1:allocator_may_return_null=1'})