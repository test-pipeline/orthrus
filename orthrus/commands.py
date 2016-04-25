'''
Orthrus create subcommand implementation
'''
import os
import sys
import shutil
import subprocess
import binascii
import ConfigParser
import tarfile
import time
import mmap
from time import sleep

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
    
class OrthrusCreate(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Create Orthrus workspace" + bcolors.ENDC + "\n")
        
        if not os.path.exists(self._config['orthrus']['directory']):
            os.mkdir(self._config['orthrus']['directory'])
            os.mkdir(self._config['orthrus']['directory'] + "/binaries/")
            os.mkdir(self._config['orthrus']['directory'] + "/conf/")
            os.mkdir(self._config['orthrus']['directory'] + "/logs/")
            os.mkdir(self._config['orthrus']['directory'] + "/jobs/")
            os.mkdir(self._config['orthrus']['directory'] + "/archive/")
        else:
            sys.stdout.write(bcolors.ERROR + "Error: Orthrus workspace already exists!\n" + bcolors.ENDC)
            return False
        
        #
        # Creating joern Neo4j database
        #
        sys.stdout.write(bcolors.HEADER + "\t[+] Setting up Neo4j with Joern" + bcolors.ENDC + "\n")
        if not os.path.isfile(self._config['joern']['joern_path'] + "/joern.jar"):
            sys.stdout.write(bcolors.ERROR + "Error: Can't find joern binary!\n" + bcolors.ENDC)
            return False
          
        sys.stdout.write("\t\t[+] Cleaning project... ")
        sys.stdout.flush()
        if not self._clean_project():
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
            return False
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
              
        sys.stdout.write("\t\t[+] Create Neo4j database for project... ")
        sys.stdout.flush()
        args = [os.path.normpath(os.path.abspath("./")), "-outdir", ".orthrus/joernIndex"]
        if not self._create_joern_db(self._config['joern']['joern_path'] + "/joern.jar", args, open(self._config['orthrus']['directory'] + "/logs/joern.log", 'w')):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
            return False
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
          
        sys.stdout.write("\t\t[+] Patching Neo4j server configuration... ")
        sys.stdout.flush()
        if not os.path.isfile(self._config['neo4j']['neo4j_path'] + "/conf/neo4j-wrapper.conf"):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
            return False
          
        alreadyPatched = False
        with open(self._config['neo4j']['neo4j_path'] + "/conf/neo4j-wrapper.conf", 'r+') as neo4j_file:
            neo4j_config = ""
            for line in neo4j_file:
                if "-Dorg.neo4j.server.properties=" in line:
                    if line.startswith("#"):
                        alreadyPatched = True
                    else:
                        line = "#" + line
                          
                neo4j_config += line
            neo4j_file.seek(0)
            neo4j_file.write(neo4j_config)
            neo4j_file.truncate()
            neo4j_file.close()
        if not alreadyPatched:
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            sys.stdout.write(bcolors.INFO + "\t\t\tInfo: To revert the patch open conf/neo4-wrapper.conf\n" \
                                            "\t\t\tand uncomment the first line (-Dorg.neo4j.server.properties=)!\n" + bcolors.ENDC)
        else:
            sys.stdout.write(bcolors.OKBLUE + "already patched" + bcolors.ENDC + "\n")
          
          
        sys.stdout.write("\t\t[+] Copy default Neo4j server configuration... ")
        sys.stdout.flush()
        if not os.path.isfile(self._config['neo4j']['neo4j_path'] + "/conf/neo4j-server.properties"):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
            return False
        shutil.copy(self._config['neo4j']['neo4j_path'] + "/conf/neo4j-server.properties", ".orthrus/conf/")
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
          
        sys.stdout.write("\t\t[+] Update Neo4j server configuration... ")
        sys.stdout.flush()
        if not os.path.isfile(".orthrus/conf/neo4j-server.properties"):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
            return False
          
        with open(".orthrus/conf/neo4j-server.properties", 'r+') as neo4j_file:
            neo4j_config = ""
            for line in neo4j_file:
                if "org.neo4j.server.database.location=" in line:
                    line = "org.neo4j.server.database.location=" + os.path.abspath(".orthrus/joernIndex") + "\n"
                neo4j_config += line
            neo4j_file.seek(0)
            neo4j_file.write(neo4j_config)
            neo4j_file.truncate()
            neo4j_file.close()
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
        
        if self._args.afl_asan:
            sys.stdout.write(bcolors.HEADER + "\t[+] Installing binaries for afl-fuzz with AddressSanitizer" + bcolors.ENDC + "\n")
            
            export_vars = {}
            install_path = self._config['orthrus']['directory'] + "/binaries/afl-asan/"
            os.mkdir(install_path)
            
            sys.stdout.write("\t\t[+] Cleaning project... ")
            sys.stdout.flush()
            if not self._clean_project():
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Configure... ")
            sys.stdout.flush() 
            export_vars['CC'] = 'afl-gcc'
            export_vars['CXX'] = 'afl-g++'
            export_vars['AFL_USE_ASAN'] = '1'
            export_vars['CFLAGS'] = '-O2' + ' ' + self._args.cflags
            if not self._configure_project(export_vars, ['--prefix=' + os.path.abspath(install_path), '--exec-prefix=' + os.path.abspath(install_path)] + self._args.configure_flags.split(" ")):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Compiling and install... ")
            sys.stdout.flush()
            if not self._make_install(export_vars, open(self._config['orthrus']['directory'] + "/logs/afl-asan_inst.log", 'w')):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            self._copy_additional_binaries(install_path + "bin/")
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            
            #
            # ASAN Debug 
            #
            sys.stdout.write(bcolors.HEADER + "\t[+] Installing binaries for debug with AddressSanitizer" + bcolors.ENDC + "\n")
            export_vars = {}
            install_path = self._config['orthrus']['directory'] + "/binaries/asan-dbg/"
            os.mkdir(install_path)
            
            sys.stdout.write("\t\t[+] Cleaning project... ")
            sys.stdout.flush() 
            if not self._clean_project():
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")

            sys.stdout.write("\t\t[+] Configure... ")
            sys.stdout.flush() 
            export_vars['CC'] = 'gcc'
            export_vars['CXX'] = 'g++'
            export_vars['CFLAGS'] = '-g -O0 -fsanitize=address -fno-omit-frame-pointer' + ' ' + self._args.cflags
            if not self._configure_project(export_vars, ['--prefix=' + os.path.abspath(install_path), '--exec-prefix=' + os.path.abspath(install_path)] + self._args.configure_flags.split(" ")):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Compiling and install... ")
            sys.stdout.flush() 
            if not self._make_install(export_vars):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            self._copy_additional_binaries(install_path + "bin/")
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                
        if self._args.afl_harden:
            sys.stdout.write(bcolors.HEADER + "\t[+] Installing binaries for afl-fuzz in harden mode" + bcolors.ENDC + "\n")
            export_vars = {}
            install_path = self._config['orthrus']['directory'] + "/binaries/afl-harden/"
            os.mkdir(install_path)
            
            sys.stdout.write("\t\t[+] Cleaning project... ")
            sys.stdout.flush() 
            if not self._clean_project():
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")

            sys.stdout.write("\t\t[+] Configure... ") 
            export_vars['CC'] = 'afl-gcc'
            export_vars['CXX'] = 'afl-g++'
            export_vars['AFL_HARDEN'] = '1'
            export_vars['CFLAGS'] = '-O2' + ' ' + self._args.cflags
            if not self._configure_project(export_vars, ['--prefix=' + os.path.abspath(install_path), '--exec-prefix=' + os.path.abspath(install_path)] + self._args.configure_flags.split(" ")):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Compiling and install... ")
            sys.stdout.flush()
            if not self._make_install(export_vars):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            self._copy_additional_binaries(install_path + "bin/")
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            #
            # Harden Debug 
            #
            sys.stdout.write(bcolors.HEADER + "\t[+] Installing binaries for debug in harden mode" + bcolors.ENDC + "\n")
            export_vars = {}
            install_path = self._config['orthrus']['directory'] + "/binaries/harden-dbg/"
            os.mkdir(install_path)
            
            sys.stdout.write("\t\t[+] Cleaning project... ")
            sys.stdout.flush()
            if not self._clean_project():
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")

            sys.stdout.write("\t\t[+] Configure... ")
            sys.stdout.flush() 
            export_vars['CC'] = 'gcc'
            export_vars['CXX'] = 'g++'
            export_vars['CFLAGS'] = '-g -O0 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-omit-frame-pointer' + ' ' + self._args.cflags
            if not self._configure_project(export_vars, ['--prefix=' + os.path.abspath(install_path), '--exec-prefix=' + os.path.abspath(install_path)] + self._args.configure_flags.split(" ")):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Compiling and install... ")
            sys.stdout.flush() 
            if not self._make_install(export_vars):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            self._copy_additional_binaries(install_path + "bin/")
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                
        if self._args.coverage:
            sys.stdout.write(bcolors.HEADER + "\t[+] Installing binaries for coverage information" + bcolors.ENDC + "\n")
            export_vars = {}
            install_path = self._config['orthrus']['directory'] + "/binaries/coverage/"
            os.mkdir(install_path)
            
            sys.stdout.write("\t\t[+] Cleaning project... ")
            sys.stdout.flush() 
            if not self._clean_project():
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")

            sys.stdout.write("\t\t[+] Configure... ")
            sys.stdout.flush() 
            export_vars['CC'] = 'gcc'
            export_vars['CXX'] = 'g++'
            export_vars['CFLAGS'] = '-g -O0 -fprofile-arcs -ftest-coverage' + ' ' + self._args.cflags
            if not self._configure_project(export_vars, ['--prefix=' + os.path.abspath(install_path), '--exec-prefix=' + os.path.abspath(install_path)] + self._args.configure_flags.split(" ")):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Compiling and install... ")
            sys.stdout.flush() 
            if not self._make_install(export_vars):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            self._copy_additional_binaries(install_path + "bin/")
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
    
    def _create_joern_db(self, binary, args, logfile = None):
        if not logfile:
            logfile = open(os.devnull, 'w')
            
        command = ["java -Xmx4g -jar " + binary + " " + " ".join(args)]
        proc = subprocess.Popen(command, shell=True, executable='/bin/bash', stdout=logfile, stderr=subprocess.STDOUT)
        
        ret = proc.wait()
        logfile.close()
        if ret != 0:
            return False
        
        return True
    
    def _configure_project(self, export_vars, args, logfile = None):
        if not os.path.isfile("configure"):
            return False
        if not logfile:
            logfile = open(os.devnull, 'w')
        
        configure_env = os.environ.copy()
        configure_env.update(export_vars)
        command = ["./configure " + " ".join(args)]
        proc = subprocess.Popen(command, shell=True, executable='/bin/bash', env=configure_env, stdout=logfile, stderr=subprocess.STDOUT)
        
        ret = proc.wait()
        logfile.close()
        if ret != 0:
            return False
        
        return True
        
    def _make_install(self, export_vars, logfile = None):
        if not os.path.isfile("Makefile"):
            return False
        if not logfile:
            logfile = open(os.devnull, 'w')
            
        make_env = os.environ.copy()
        make_env.update(export_vars)
        command = ["make all install"]
        proc = subprocess.Popen(command, shell=True, executable='/bin/bash', env=make_env, stdout=logfile, stderr=subprocess.STDOUT)
        
        ret = proc.wait()
        logfile.close()
        if ret != 0:
            return False
        
        return True
    
    def _is_elf_executable(self, file_path):
        output = subprocess.check_output(["/usr/bin/file", "-b", file_path])
        if "ELF" in output and "executable" in output:
            return True
        return False
    
    def _copy_additional_binaries(self, dest):
        binaries = []
        for dirpath, dirnames, filenames in os.walk('./'):
            for fn in filenames:
                fpath = os.path.join(dirpath, fn)
                if os.path.isfile(fpath) and self._is_elf_executable(fpath):
                    binaries.append(fpath)
                
            if ".orthrus" in dirnames:
                dirnames.remove('.orthrus')
        
        for f in binaries:
            head, tail = os.path.split(f)
            if not os.path.exists(dest + tail):
                shutil.copy(f, dest)
    
    def _clean_project(self, logfile = None):
        if not logfile:
            logfile = open(os.devnull, 'w')
        
        command = ["make clean distclean"]
        proc = subprocess.Popen(command, shell=True, executable='/bin/bash', stdout=logfile, stderr=subprocess.STDOUT)
        
        ret = proc.wait()
        logfile.close()
        if ret != 0 and ret != 2:
            return False
        
        return True

class OrthrusAdd(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Adding fuzzing job to Orthrus workspace" + bcolors.ENDC + "\n")
        
        sys.stdout.write("\t\t[+] Check Orthrus workspace... ")
        sys.stdout.flush() 
        if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/"):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
        
        if self._args.job:
            jobId = str(binascii.crc32(self._args.job) & 0xffffffff)
            jobTarget = self._args.job.split(" ")[0]
            jobParams = " ".join(self._args.job.split(" ")[1:])
            sys.stdout.write("\t\t[+] Adding job for [" + jobTarget + "]... ")
            sys.stdout.flush()
            
            if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId):
                sys.stdout.write(bcolors.FAIL + "already exists!" + bcolors.ENDC + "\n")
                return False
            os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId)
            os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-in")
            os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out")
            
            job_config = ConfigParser.ConfigParser()
            job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
            job_config.add_section(jobId)
            job_config.set(jobId, "target", jobTarget)
            job_config.set(jobId, "params", jobParams)
            with open(self._config['orthrus']['directory'] + "/jobs/jobs.conf", 'wb') as job_file:
                job_config.write(job_file)
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Configuring job for [" + jobTarget + "]... ")
            sys.stdout.flush()
            
            asanjob_config = ConfigParser.ConfigParser()
            asanjob_config.add_section("afl.dirs")
            asanjob_config.set("afl.dirs", "input", ".orthrus/jobs/" + jobId + "/afl-in")
            asanjob_config.set("afl.dirs", "output", ".orthrus/jobs/" + jobId + "/afl-out")
            asanjob_config.add_section("target")
            asanjob_config.set("target", "target", ".orthrus/binaries/afl-asan/bin/" + jobTarget)
            asanjob_config.set("target", "cmdline", jobParams)
            asanjob_config.add_section("afl.ctrl")
            asanjob_config.set("afl.ctrl", "file", ".orthrus/jobs/" + jobId + "/afl-out/.cur_input_asan")
            asanjob_config.set("afl.ctrl", "timeout", "3000+")
            asanjob_config.set("afl.ctrl", "mem_limit", "800")
            asanjob_config.add_section("job")
            asanjob_config.set("job", "session", "SESSION")
            if os.path.exists(self._config['orthrus']['directory'] + "binaries/afl-harden"):
                asanjob_config.set("job", "slave_only", "on")
            with open(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/asan-job.conf", 'wb') as job_file:
                asanjob_config.write(job_file)
                
            hardenjob_config = ConfigParser.ConfigParser()
            hardenjob_config.add_section("afl.dirs")
            hardenjob_config.set("afl.dirs", "input", ".orthrus/jobs/" + jobId + "/afl-in")
            hardenjob_config.set("afl.dirs", "output", ".orthrus/jobs/" + jobId + "/afl-out")
            hardenjob_config.add_section("target")
            hardenjob_config.set("target", "target", ".orthrus/binaries/afl-harden/bin/" + jobTarget)
            hardenjob_config.set("target", "cmdline", jobParams)
            hardenjob_config.add_section("afl.ctrl")
            hardenjob_config.set("afl.ctrl", "file", ".orthrus/jobs/" + jobId + "/afl-out/.cur_input_harden")
            hardenjob_config.set("afl.ctrl", "timeout", "3000+")
            hardenjob_config.set("afl.ctrl", "mem_limit", "800")
            hardenjob_config.add_section("job")
            hardenjob_config.set("job", "session", "SESSION")
            with open(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/harden-job.conf", 'wb') as job_file:
                hardenjob_config.write(job_file)
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            if self._args.sample:
                sys.stdout.write("\t\t[+] Adding initial samples for job [" + jobTarget + "]... ")
                sys.stdout.flush()
                if os.path.isdir(self._args.sample):
                    for dirpath, dirnames, filenames in os.walk(self._args.sample):
                        for fn in filenames:
                            fpath = os.path.join(dirpath, fn)
                            if os.path.isfile(fpath):
                                shutil.copy(fpath, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-in/")
                elif os.path.isfile(self._args.sample):
                    shutil.copy(self._args.sample, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-in/")
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
        if self._args.job_id:
            if self._args.sample:
                jobId = self._args.job_id
                sys.stdout.write("\t\t[+] Adding samples for job [" + jobId + "]... ")
                sys.stdout.flush()
                if os.path.isdir(self._args.sample):
                    for dirpath, dirnames, filenames in os.walk(self._args.sample):
                        for fn in filenames:
                            fpath = os.path.join(dirpath, fn)
                            if os.path.isfile(fpath):
                                shutil.copy(fpath, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-in/")
                elif os.path.isfile(self._args.sample):
                    shutil.copy(self._args.sample, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-in/")
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            if self._args._import:
                jobId = self._args.job_id
                next_session = 0
                
                sys.stdout.write("\t\t[+] Import afl sync dir for job [" + jobId + "]... ")
                sys.stdout.flush()
                if not tarfile.is_tarfile(self._args._import):
                    sys.stdout.write(bcolors.FAIL + "failed!" + bcolors.ENDC + "\n")
                    return False
                if not os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"):
                    sys.stdout.write(bcolors.FAIL + "failed!" + bcolors.ENDC + "\n")
                    return False
                
                syncDir = os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/")
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
                        outDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/SESSION" + "{:03d}".format(next_session)
                        os.mkdir(outDir)
                        tar.extractall(outDir)
                    else:
                        tmpDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/tmp/"
                        os.mkdir(tmpDir)
                        tar.extractall(tmpDir)
                        for directory in os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/tmp/"):
                            outDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/SESSION" + "{:03d}".format(next_session)
                            shutil.move(tmpDir + directory, outDir)
                            next_session += 1
                        shutil.rmtree(tmpDir)
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                
                sys.stdout.write("\t\t[+] Minimizing corpus for job [" + jobId + "]... \n")
                sys.stdout.flush()
                
                job_config = ConfigParser.ConfigParser()
                job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
                launch = ""
                if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
                    launch = self._config['orthrus']['directory'] + "/binaries/afl-harden/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params")
                else:
                    launch = self._config['orthrus']['directory'] + "/binaries/afl-asan/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params")
                cmin = " ".join(["afl-minimize", "-c", self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect", "--cmin", "--cmin-mem-limit=800", "--cmin-timeout=5000", "--reseed", self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out", "--", "'" + launch + "'"])
                subprocess.call(cmin, shell=True)
                
                if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect"):
                    shutil.rmtree(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect")
                if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect.cmin"):
                    shutil.rmtree(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect.cmin")
        return True

class OrthrusRemove(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Removing fuzzing job from Orthrus workspace" + bcolors.ENDC + "\n")
        
        sys.stdout.write("\t\t[+] Check Orthrus workspace... ")
        sys.stdout.flush() 
        if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/"):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
        
        if self._args.job_id:
            sys.stdout.write("\t\t[+] Archiving data for job [" + self._args.job_id + "]... ")
            sys.stdout.flush()
            if not os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + self._args.job_id):
                sys.stdout.write(bcolors.FAIL + "failed!" + bcolors.ENDC + "\n")
                return False
            shutil.move(self._config['orthrus']['directory'] + "/jobs/" + self._args.job_id, self._config['orthrus']['directory'] + "/archive/" + time.strftime("%Y-%m-%d-%H:%M:%S") + "-" + self._args.job_id)
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Removing job for [" + self._args.job_id + "]... ")
            sys.stdout.flush()
            job_config = ConfigParser.ConfigParser()
            job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
            job_config.remove_section(self._args.job_id)
            with open(self._config['orthrus']['directory'] + "/jobs/jobs.conf", 'wb') as job_file:
                job_config.write(job_file)
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
        return True

class OrthrusStart(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def _get_cpu_core_info(self):
        num_cores = 0
        info = subprocess.check_output("afl-gotcpu", shell=True, stderr=subprocess.STDOUT)
        for line in info:
            if "Core" in line:
                num_cores += 1
        return num_cores
    
    def _start_fuzzers(self, jobId, available_cores):
        start_cmd = ""
        if os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/") == []:
            start_cmd = "start"
        else:
            start_cmd = "resume"

        core_per_subjob = available_cores / 2
        if core_per_subjob == 0:
            core_per_subjob = 1

        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
            harden_file = open(self._config['orthrus']['directory'] + "/logs/afl-harden.log", "w")
            p = subprocess.Popen(" ".join(["afl-multicore", "--config=.orthrus/jobs/" + jobId + "/harden-job.conf", start_cmd, str(core_per_subjob), "-v"]), shell=True, stdout=harden_file, stderr=subprocess.PIPE)
            p.wait()
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            output = open(self._config['orthrus']['directory'] + "/logs/afl-harden.log", "r")
            for line in output:
                if "Starting master" in line or "Starting slave" in line:
                    sys.stdout.write("\t\t\t" + line)
                if " Master " in line or " Slave " in line:
                    sys.stdout.write("\t\t\t\t" + bcolors.OKGREEN + "[+]" + bcolors.ENDC + line)
            output.close()
            
            if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-asan"):
                asan_file = open(self._config['orthrus']['directory'] + "/logs/afl-asan.log", "w")
                p = subprocess.Popen("afl-multicore --config=.orthrus/jobs/" + jobId + "/asan-job.conf " + "add" + " " + str(core_per_subjob) +" -v", shell=True, stdout=asan_file, stderr=subprocess.STDOUT)
                p.wait()
                output2 = open(self._config['orthrus']['directory'] + "/logs/afl-asan.log", "r")
                for line in output2:
                    if "Starting master" in line or "Starting slave" in line:
                        sys.stdout.write("\t\t\t" + line)
                    if " Master " in line or " Slave " in line:
                        sys.stdout.write("\t\t\t\t" + bcolors.OKGREEN + "[+]" + bcolors.ENDC + line)
                output2.close()
        elif os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-asan"):
            asan_file = open(self._config['orthrus']['directory'] + "/logs/afl-asan.log", "w")
            p = subprocess.Popen("afl-multicore --config=.orthrus/jobs/" + jobId + "/asan-job.conf " + start_cmd + " " + str(available_cores) +" -v", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            p.wait()
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            output2 = open(self._config['orthrus']['directory'] + "/logs/afl-asan.log", "r")
            for line in output2:
                if "Starting master" in line or "Starting slave" in line:
                    sys.stdout.write("\t\t\t" + line)
                if " Master " in line or " Slave " in line:
                    sys.stdout.write("\t\t\t\t" + bcolors.OKGREEN + "[+]" + bcolors.ENDC + line)
            output2.close()
                
        return True
    
    def _tidy_sync_dir(self, jobId):
        syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out"
        for session in os.listdir(syncDir):
            for directory in os.listdir(syncDir + "/" + session):
                if "crashes." in directory:
                    for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                        src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                        dst_path = syncDir + "/" + session + "/" + "crashes" + "/" + filename
                        if os.path.isfile(dst_path):
                            dst_path += "," + str(num)
                        shutil.move(src_path, dst_path)
                    shutil.rmtree(syncDir + "/" + session + "/" + directory + "/")
                if "hangs." in directory:
                    for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                        src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                        dst_path = syncDir + "/" + session + "/" + "hangs" + "/" + filename
                        if os.path.isfile(dst_path):
                            dst_path += "," + str(num)
                        shutil.move(src_path, dst_path)
                    shutil.rmtree(syncDir + "/" + session + "/" + directory + "/")
#                 if "queue." in directory:
#                     for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
#                         src_path = syncDir + "/" + session + "/" + directory + "/" + filename
#                         dst_path = syncDir + "/" + session + "/" + "queue" + "/" + filename
#                         if os.path.isfile(dst_path):
#                             dst_path += "," + str(num)
#                         shutil.move(src_path, dst_path)
#                     shutil.rmtree(syncDir + "/" + session + "/" + directory + "/")
        
        for session in os.listdir(syncDir):
            if "SESSION000" != session:
                for directory in os.listdir(syncDir + "/" + session):
                    if "crashes" == directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + "SESSION000" + "/" + "crashes" + "/" + filename
                            if os.path.isfile(dst_path):
                                dst_path += "," + str(num)
                            shutil.move(src_path, dst_path)
                    if "hangs" == directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + "SESSION000" + "/" + "hangs" + "/" + filename
                            if os.path.isfile(dst_path):
                                dst_path += "," + str(num)
                            shutil.move(src_path, dst_path)
                    if "queue" == directory:
                        for num, filename in enumerate(os.listdir(syncDir + "/" + session + "/" + directory)):
                            src_path = syncDir + "/" + session + "/" + directory + "/" + filename
                            dst_path = syncDir + "/" + "SESSION000" + "/" + "queue" + "/" + filename
                            if os.path.isdir(src_path):
                                continue
                            if os.path.isfile(dst_path):
                                dst_path += "," + str(num)
                            shutil.move(src_path, dst_path)
                shutil.rmtree(syncDir + "/" + session)
                
        return True
                
    def _minimize_sync(self, jobId):
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")

        launch = ""
        if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
            launch = self._config['orthrus']['directory'] + "/binaries/afl-harden/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params")
        else:
            launch = self._config['orthrus']['directory'] + "/binaries/afl-asan/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params")
        
        export = {}
        export['PYTHONUNBUFFERED'] = "1"
        env = os.environ.copy()
        env.update(export)
        cmin = " ".join(["afl-minimize", "-c", self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect", "--cmin", "--cmin-mem-limit=800", "--cmin-timeout=5000", "--reseed", self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out", "--", "'" + launch + "'"])
        p = subprocess.Popen(cmin, bufsize=0, shell=True, executable='/bin/bash', env=env, stdout=subprocess.PIPE)
        for line in p.stdout:
            if "[*]" in line or "[!]" in line:
                sys.stdout.write("\t\t\t" + line)
            
        if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect"):
            shutil.rmtree(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect")
        if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect.cmin"):
            shutil.rmtree(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/collect.cmin")
            
        return True
     
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Starting fuzzing jobs" + bcolors.ENDC + "\n")
        
        sys.stdout.write("\t\t[+] Check Orthrus workspace... ")
        sys.stdout.flush()
        if not os.path.exists(self._config['orthrus']['directory'] + "/jobs/jobs.conf"):
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
        if os.path.getsize(self._config['orthrus']['directory'] + "/jobs/jobs.conf") < 1:
            sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
        sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
        
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
        
        total_cores = self._get_cpu_core_info()
        for jobId in job_config.sections():
            if len(os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/")) > 0:
                sys.stdout.write("\t\t[+] Tidy fuzzer sync dir... ")
                sys.stdout.flush()
                if not self._tidy_sync_dir(jobId):
                    sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                    return False
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                
                if self._args.minimize:
                    sys.stdout.write("\t\t[+] Minimize fuzzer sync dir... \n")
                    if not self._minimize_sync(jobId):
                        return False
                
            sys.stdout.write("\t\t[+] Start Fuzzers for Job [" + jobId +"]... ")
            sys.stdout.flush()
            if not self._start_fuzzers(jobId, total_cores):
                subprocess.call("afl-multikill")
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            
        return True
    
class OrthrusStop(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "Stopping fuzzing jobs:" + bcolors.ENDC + "\n")
        p = subprocess.Popen("afl-multikill", shell=True, stdout=subprocess.PIPE)
        p.wait()
        output = p.communicate()[0]
        sys.stdout.write("\t" + "\n".join(output.splitlines()[2:]))
        
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
            
        if self._args.minimize:
            pass
                    
        sys.stdout.write("\n")
        
        return True
    
class OrthrusShow(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def run(self):
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
        if self._args.jobs:
            sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "Configured jobs found:" + bcolors.ENDC + "\n")
            for num, section in enumerate(job_config.sections()):
                t = job_config.get(section, "target")
                p = job_config.get(section, "params")
                sys.stdout.write("\t" + str(num) + ") [" + section + "] " + t + " " + p + "\n")
        else:
            sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "Status of jobs:" + bcolors.ENDC + "\n")
            
            for jobId in job_config.sections():
                syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"
                output = subprocess.check_output(["afl-whatsup", "-s", syncDir])
                output = output[output.find("==\n\n") + 4:]
                
                sys.stdout.write(bcolors.OKBLUE + "\tJob [" + jobId + "] " + "for target '" + job_config.get(jobId, "target") + "':\n" + bcolors.ENDC)
                for line in output.splitlines():
                    sys.stdout.write("\t" + line + "\n")
                triaged_unique = 0
                if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"):
                    triaged_unique = len(os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"))
                sys.stdout.write("\t     Triaged crashes : " + str(triaged_unique) + " available\n")
                
        return True
    
class OrthrusTriage(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def _add_crash_to_crash_graph(self, jobId, crash_file):
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
        
        dev_null = open(os.devnull, "w")
        logfile = open(self._config['orthrus']['directory'] + "/logs/crash_graph.log", "a")
        if "HARDEN" in crash_file:
            if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/harden-dbg"):
                return False
            p1_cmd = " ".join(["gdb", "-q", "-ex='set args " + job_config.get(jobId, "params").replace("@@", crash_file) + "'", "-ex='run'", "-ex='orthrus'", "-ex='gcore core'", "-ex='quit'", "--args", self._config['orthrus']['directory'] + "/binaries/harden-dbg/bin/" + job_config.get(jobId, "target")])
            p1 = subprocess.Popen(p1_cmd, shell=True, stdout=subprocess.PIPE, stderr=dev_null)
            
            p2_cmd = "joern-runtime-info -r -v -g -l"
            p2 = subprocess.Popen(p2_cmd, shell=True, stdin=p1.stdout, stdout=logfile, stderr=subprocess.STDOUT)
            p2.wait()
            
        elif "ASAN" in crash_file:
            if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/asan-dbg"):
                return False
            p1_cmd = "ulimit -c 1024000; " + self._config['orthrus']['directory'] + "/binaries/asan-dbg/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params").replace("@@", crash_file)
            export = {}
            export['ASAN_SYMBOLIZER_PATH'] = "/usr/local/bin/llvm-symbolizer"
            export['ASAN_OPTIONS'] = "abort_on_error=1:symbolize=1:print_cmdline=1"
            env = os.environ.copy()
            env.update(export)
            p1 = subprocess.Popen(p1_cmd, shell=True, executable="/bin/bash", env=env, stdout=dev_null, stderr=subprocess.PIPE)

            p2_cmd = "joern-runtime-info -r -v -g -l"
            # Injecting the command line string ist a hack for gcc, there the ASAN option 'print_cmdline' is not available.
            # Plus, Gdb offers only a truncated command line string
            cmdline = "Command: " + self._config['orthrus']['directory'] + "/binaries/asan-dbg/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params").replace("@@", crash_file)
            p2 = subprocess.Popen(p2_cmd, shell=True, stdin=subprocess.PIPE, stdout=logfile, stderr=subprocess.STDOUT)
            p2.communicate(p1.stderr.read() + cmdline)
            p2.wait()
            
        dev_null.close()
        logfile.close()
        
        return True
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Triaging crashes for job [" + self._args.job_id + "]" + bcolors.ENDC + "\n")
        if self._args.job_id:
            jobId = self._args.job_id
            if not os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"):
                os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/")
            else:
                shutil.move(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/", self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique." + time.strftime("%Y-%m-%d-%H:%M:%S"))
                os.mkdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/")
            
            job_config = ConfigParser.ConfigParser()
            job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
                
            if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-harden"):
                sys.stdout.write("\t\t[+] Collect and verify 'harden' mode crashes... ")
                sys.stdout.flush()
                 
                syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"
                outDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_harden"
                launch = self._config['orthrus']['directory'] + "/binaries/harden-dbg/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params")
                cmd = " ".join(["afl-collect", "-r", syncDir, outDir, "--", launch])
                logfile = open(os.devnull, "w")
                p = subprocess.Popen(cmd, shell=True, stdout=logfile, stderr=subprocess.STDOUT)
                p.wait()
                logfile.close()
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                 
            if os.path.exists(self._config['orthrus']['directory'] + "/binaries/afl-asan"):
                sys.stdout.write("\t\t[+] Collect and verify 'asan' mode crashes... ")
                sys.stdout.flush()
                 
                env = os.environ.copy()
                asan_flag = {}
                asan_flag['ASAN_OPTIONS'] = "abort_on_error=1"
                env.update(asan_flag)
                syncDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/afl-out/"
                outDir =self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_asan"
                launch = self._config['orthrus']['directory'] + "/binaries/asan-dbg/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params")
                cmd = " ".join(["afl-collect", "-r", syncDir, outDir, "--", launch])
                p = subprocess.Popen(cmd, env=env, shell=True)
                p.wait()
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                 
            if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_harden/"):
                sys.stdout.write("\t\t[+] Deduplicate 'harden' mode crashes... ")
                sys.stdout.flush()
                 
                crash_files = os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_harden/")
                if crash_files:
                    hashes = []
                    for crash_file in crash_files:
                        crash_file = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_harden/" + crash_file
                        cmd = " ".join(["gdb", "-q", "-ex='set args " + job_config.get(jobId, "params").replace("@@", crash_file) + "'", "-ex='run'", "-ex='orthrus'", "-ex='quit'", "--args", self._config['orthrus']['directory'] + "/binaries/harden-dbg/bin/" + job_config.get(jobId, "target")])
                        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        output = p.communicate()[0]
                        output = output[output.find("Hash: ") + 6:]
                        crash_hash = output[:output.find(".")]
                        if crash_hash in hashes:
                            os.remove(crash_file)
                        else:
                            hashes.append(crash_hash)
                            shutil.copy(crash_file, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/HARDEN-" + os.path.basename(crash_file))
                shutil.rmtree(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_harden/")
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                 
            if os.path.exists(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_asan/"):
                sys.stdout.write("\t\t[+] Deduplicate 'asan' mode crashes... ")
                sys.stdout.flush()
                 
                crash_files = os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_asan/")
                if crash_files:
                    hashes = []
                    for crash_file in crash_files:
                        env = os.environ.copy()
                        asan_flag = {}
                        asan_flag['ASAN_OPTIONS'] = "abort_on_error=1"
                        env.update(asan_flag)
                        crash_file = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_asan/" + crash_file
                        cmd = " ".join(["gdb", "-q", "-ex='set args " + job_config.get(jobId, "params").replace("@@", crash_file) + "'", "-ex='run'", "-ex='orthrus'", "-ex='quit'", "--args", self._config['orthrus']['directory'] + "/binaries/asan-dbg/bin/" + job_config.get(jobId, "target")])
                        p = subprocess.Popen(cmd, shell=True, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                        output = p.communicate()[0]
                        output = output[output.find("Hash: ") + 6:]
                        crash_hash = output[:output.find(".")]
                        if crash_hash in hashes:
                            os.remove(crash_file)
                        else:
                            hashes.append(crash_hash)
                            shutil.copy(crash_file, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/ASAN-" + os.path.basename(crash_file))
                shutil.rmtree(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/crash_asan/")
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                 
            dedub_crashes = os.listdir(self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/")
            sys.stdout.write("\t\t[+] Upload " + str(len(dedub_crashes)) + " crashes to database for further triaging... ")
            sys.stdout.flush()
            if not dedub_crashes:
                sys.stdout.write(bcolors.OKBLUE + "nothing to do" + bcolors.ENDC + "\n")
                return
            sys.stdout.write("\n")
            
            for crash in dedub_crashes:
                sys.stdout.write("\t\t\t[+] Adding " + crash + " ... ")
                sys.stdout.flush()
                if not self._add_crash_to_crash_graph(jobId, self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/" + crash):
                    sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                    continue
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                
        return True

class OrthrusDatabase(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def _start_joern(self, binary, configfile):
        export = {}
        export['wrapper_java_additional'] = "-Dorg.neo4j.server.properties=" + configfile
        env = os.environ.copy()
        env.update(export)
        command = binary + " start"
        p = subprocess.Popen(command, shell=True, executable='/bin/bash', env=env, stdout=subprocess.PIPE)
        p.wait()
        if p.returncode != 0:
            return False
        return True
    
    def _stop_joern(self, binary):
        command = binary + " stop"
        p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        p.wait()
        if p.returncode != 0:
            return False
        return True
    
    def _upload_crash(self, jobId, crash_file):
        job_config = ConfigParser.ConfigParser()
        job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
        
        dev_null = open(os.devnull, "w")
        logfile = open(self._config['orthrus']['directory'] + "/logs/upload.log", "a")
        if "HARDEN" in crash_file:
            if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/harden-dbg"):
                return False
            p1_cmd = " ".join(["gdb", "-q", "-ex='set args " + job_config.get(jobId, "params").replace("@@", crash_file) + "'", "-ex='run'", "-ex='orthrus'", "-ex='gcore core'", "-ex='quit'", "--args", self._config['orthrus']['directory'] + "/binaries/harden-dbg/bin/" + job_config.get(jobId, "target")])
            p1 = subprocess.Popen(p1_cmd, shell=True, stdout=subprocess.PIPE, stderr=dev_null)
            
            p2_cmd = "joern-runtime-info -r -v -l"
            p2 = subprocess.Popen(p2_cmd, shell=True, stdin=p1.stdout, stdout=logfile, stderr=subprocess.STDOUT)
            p2.wait()
            
        elif "ASAN" in crash_file:
            if not os.path.exists(self._config['orthrus']['directory'] + "/binaries/asan-dbg"):
                return False
            p1_cmd = "ulimit -c 1024000; " + self._config['orthrus']['directory'] + "/binaries/asan-dbg/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params").replace("@@", crash_file)
            export = {}
            export['ASAN_SYMBOLIZER_PATH'] = "/usr/local/bin/llvm-symbolizer"
            export['ASAN_OPTIONS'] = "abort_on_error=1:symbolize=1:print_cmdline=1"
            env = os.environ.copy()
            env.update(export)
            p1 = subprocess.Popen(p1_cmd, shell=True, executable="/bin/bash", env=env, stdout=dev_null, stderr=subprocess.PIPE)

            p2_cmd = "joern-runtime-info -r -v -l"
            # Injecting the command line string ist a hack for gcc, there the ASAN option 'print_cmdline' is not available.
            # Plus, Gdb offers only a truncated command line string
            cmdline = "Command: " + self._config['orthrus']['directory'] + "/binaries/asan-dbg/bin/" + job_config.get(jobId, "target") + " " + job_config.get(jobId, "params").replace("@@", crash_file)
            p2 = subprocess.Popen(p2_cmd, shell=True, stdin=subprocess.PIPE, stdout=logfile, stderr=subprocess.STDOUT)
            p2.communicate(p1.stderr.read() + cmdline)
            p2.wait()
            
        dev_null.close()
        logfile.close()
        
        return True
    
    def _unload_crash(self, pid):
        cmd = " ".join(["joern-runtime-info", "-v -u"])
        p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        
        output = p.communicate(pid)[0]
        if not output:
            return False
        else:
            for line in output.splitlines():
                if pid in line:
                    return True
        
        return False
        
    def _get_all_crash_pids(self):
        query = "queryNodeIndex('type:RtCrash').pid"
        
        cmd = " ".join(["joern-lookup", "-g"])
        p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        
        output = p.communicate(query)[0]
        if not output:
            return []
        else:
            return output.splitlines()
        
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Performing database operation" + bcolors.ENDC + "\n")
        
        if self._args.startup:
            sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "\t[+] Joern Neo4j database" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Check Orthrus workspace... ")
            sys.stdout.flush()
            if not os.path.exists(self._config['orthrus']['directory'] + "/conf/neo4j-server.properties"):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Starting Joern Neo4j database instance... ")
            sys.stdout.flush()
            configfile = os.path.abspath(self._config['orthrus']['directory'] + "/conf/neo4j-server.properties")
            if not self._start_joern(self._config['neo4j']['neo4j_path'] + "/bin/neo4j", configfile):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            return True
        
        if self._args.shutdown:
            sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "\t[+] Joern Neo4j database" + bcolors.ENDC + "\n")
            
            sys.stdout.write("\t\t[+] Stopping Joern Neo4j database instance... ")
            sys.stdout.flush()
            if not self._stop_joern(self._config['neo4j']['neo4j_path'] + "/bin/neo4j"):
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                return False
            sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            
            return True
        
        if self._args.load_crashes:
            job_config = ConfigParser.ConfigParser()
            job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
            if self._args.all:
                return False
            elif self._args.job_id:
                jobId = self._args.job_id
                sys.stdout.write("\t[+] Checking triaged crash samples... ")
                sys.stdout.flush()
                
                uniqueDir = self._config['orthrus']['directory'] + "/jobs/" + jobId + "/unique/"
                
                if not os.path.exists(uniqueDir) or not len(os.listdir(uniqueDir)):
                    sys.stdout.write(bcolors.WARNING + "no crashes" + bcolors.ENDC + "\n")
                    return True
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                
                crashes = os.listdir(uniqueDir)
                sys.stdout.write("\t[+] Processing " + str(len(crashes)) + " crash samples... \n")
                
                for crash in crashes:
                    crash_path = uniqueDir + crash
                    sys.stdout.write("\t\t[+] Upload crash " + crash + "... ")
                    sys.stdout.flush()
                    if not self._upload_crash(jobId, crash_path):
                        sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                        continue
                    sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            else:
                return False
        elif self._args.unload_crashes:
            job_config = ConfigParser.ConfigParser()
            job_config.read(self._config['orthrus']['directory'] + "/jobs/jobs.conf")
            if self._args.all:
                sys.stdout.write("\t[+] Removing all crash nodes from database... ")
                sys.stdout.flush()
                
                pids = self._get_all_crash_pids()
                if not pids:
                    sys.stdout.write(bcolors.WARNING + "no crashes" + bcolors.ENDC + "\n")
                    return True
                sys.stdout.write(bcolors.OKBLUE + "found " + str(len(pids)) + " crashes" + bcolors.ENDC + "\n")
                
                for pid in pids:
                    sys.stdout.write("\t\t[+] Removing crash for PID " + pid + "... ")
                    sys.stdout.flush()
                    if not self._unload_crash(pid):
                        sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
                        continue
                    sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
                return True
            elif self._args.job_id:
                return False
            
        if self._args.load_coverage:
            pass
        
        return True
    
class OrthrusDestroy(object):
    
    def __init__(self, args, config):
        self._args = args
        self._config = config
    
    def run(self):
        sys.stdout.write(bcolors.BOLD + bcolors.HEADER + "[+] Destroy Orthrus workspace" + bcolors.ENDC + "\n")
        sys.stdout.write("[?] Delete complete workspace? [y/n]...: ")
        sys.stdout.flush()
        if 'y' not in sys.stdin.readline()[0]:
            return True
        
        sys.stdout.write("\t\t[+] Deleting all files... ")
        sys.stdout.flush() 
        if not os.path.exists(self._config['orthrus']['directory']):
            sys.stdout.write(bcolors.OKBLUE + "destroyed already" + bcolors.ENDC + "\n")
        else:
            shutil.rmtree(self._config['orthrus']['directory'])
            if not os.path.isdir(self._config['orthrus']['directory']):
                sys.stdout.write(bcolors.OKGREEN + "done" + bcolors.ENDC + "\n")
            else:
                sys.stdout.write(bcolors.FAIL + "failed" + bcolors.ENDC + "\n")
        return