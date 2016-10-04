# Orthrus [![Build Status](https://travis-ci.org/test-pipeline/orthrus.svg?branch=master)](https://travis-ci.org/test-pipeline/orthrus) [![License](http://img.shields.io/:license-gpl3-blue.svg?style=flat-square)](http://www.gnu.org/licenses/gpl-3.0.html) [![Coverage Status](https://coveralls.io/repos/github/test-pipeline/orthrus/badge.svg?branch=master)](https://coveralls.io/github/test-pipeline/orthrus?branch=master)

Orthrus is a tool for managing, conducting, and assessing security (fuzz) testing. At the moment, it supports Clang/LLVM instrumentation and the AFL ecosystem (afl-fuzz, afl-utils, afl-cov). The ultimate aim is for Orthrus to be a generic wrapper around state-of-the-art fuzz and instrumentation tools.

# Pre-requisites

- [afl-fuzz][1]
- [afl-utils][2] (v1.27a)
```bash
$ cd $HOME
$ wget -q https://github.com/rc0r/afl-utils/archive/v1.27a.tar.gz && tar xzf v1.27a.tar.gz
$ rm v1.27a.tar.gz && cd afl-utils-1.27a
$ sudo mkdir -p /usr/lib/python3.4/site-packages && sudo python3 setup.py install
$ cd ../
$ echo "source /usr/lib/python3.4/site-packages/exploitable-1.32_rcor-py3.4.egg/exploitable/exploitable.py" >> ~/.gdbinit
$ sudo rm -rf afl-utils-1.27a
```

- [afl-cov][3]
- Clang/LLVM toolchain
- gcov/lcov
- An autotools open-source project for fuzzing

Command line installation for the last two (tested on Ubuntu 14.04):
```bash
$ sudo apt-get install lcov
$ curl -sSL "http://apt.llvm.org/llvm-snapshot.gpg.key" | sudo -E apt-key add -
$ echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.8 main" | sudo tee -a /etc/apt/sources.list > /dev/null
$ sudo apt-get update
$ sudo apt-get --no-install-suggests --no-install-recommends --force-yes install clang-3.8 libclang-common-3.8-dev llvm-3.8-runtime llvm-3.8
```

# Workflow

## Step 1: Create instrumented binaries

- Creates the following binaries
  - ASAN+AFL instrumentation (fuzzing)
  - AFL+HARDEN instrumentation only (fuzzing)
  - ASAN Debug (triage)
  - HARDEN Debug (triage)
  - Gcov (coverage)
- All binaries installed in `.orthrus/binaries` subdir relative to WD root

```bash
$ cd $AUTOTOOLS_PROJECT_WD
$ orthrus create -fuzz -asan -cov
[+] Create Orthrus workspace
        [+] Installing binaries for afl-fuzz with AddressSanitizer
                [+] Configure... done
                [+] Compile and install... done
                [+] Verifying instrumentation... done
        [+] Installing binaries for debug with AddressSanitizer
                [+] Configure... done
                [+] Compile and install... done
                [+] Verifying instrumentation... done
        [+] Installing binaries for afl-fuzz in harden mode
                [+] Configure... done
                [+] Compile and install... done
                [+] Verifying instrumentation... done
        [+] Installing binaries for debug in harden mode
                [+] Configure... done
                [+] Compile and install... done
                [+] Verifying instrumentation... done
        [+] Installing binaries for obtaining test coverage information
                [+] Configure... done
                [+] Compile and install... done
                [+] Verifying instrumentation... done
```

## Step 2: Add/Remove fuzzing job

- Sets up config for (local) multi-core job with AFL+HARDEN (master) and 
ASAN+AFL (slave)
- Each job allocated an independent data directory
  - Can be operated (started, stopped, managed) independently

```bash
$ orthrus add --job="main @@"
[+] Adding fuzzing job to Orthrus workspace
                [+] Check Orthrus workspace... done
                [+] Adding job for [main]... done
                [+] Configuring job for [main]... done
```

- To remove an existing job, you need to look up the job ID first...
```bash
$ ls .orthrus/jobs/
1167520733  jobs.conf
```
- ...and pass the job ID as an argument to orthrus remove
```bash
$ orthrus remove -j 1167520733
[+] Removing fuzzing job from Orthrus workspace
                [+] Check Orthrus workspace... done
                [+] Archiving data for job [1167520733]... done
                [+] Removing job for [1167520733]... done
```

- You can also import an existing AFL generated corpus tarball (contents of 
afl-sync-dir e.g., SESSION000, SESSION001, etc.)

```bash
$ orthrus add --job="main @@" -i=./afl-out.tar.gz
[+] Adding fuzzing job to Orthrus workspace
                [+] Check Orthrus workspace... done
                [+] Adding job for [main]... done
                [+] Configuring job for [main]... done
                [+] Import afl sync dir for job [1167520733]... done
                [+] Minimizing corpus for job [1167520733]...
                        [*] Looking for fuzzing queues in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Projec
t/.orthrus/jobs/1167520733/afl-out'.

                        [*] Found 4 fuzzers, collecting samples.

                        [*] Successfully indexed 5 samples.

                        [*] Copying 5 samples into collection directory...

                        [*] Executing: afl-cmin -i /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthr
us/jobs/1167520733/collect -o /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/co
llect.cmin -- /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/binaries/afl-harden/bin/main @@

                        [*] Testing the target binary...

                        [*] Obtaining traces for input files in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/collect'...

                        [*] Sorting trace sets (this may take a while)...

                        [*] Finding best candidates for each tuple...

                        [*] Sorting candidate list (be patient)...

                        [*] Processing candidates and writing output files...

                        [*] Performing dry-run in /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/collect.cmin...

                        [!] Be patient! Depending on the corpus size this step can take hours...

                        [!] Collection directory exists and is not empty!

                        [!] Skipping collection step...

                        [*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/afl-out/SESSION003/queue

                        [*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/afl-out/SESSION002/queue

                        [*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/afl-out/SESSION000/queue

                        [*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/afl-out/SESSION001/queue

```

- You can seed a job, like so
```bash
$ orthrus add --job="main @@" -s=./seeds
[+] Adding fuzzing job to Orthrus workspace
                [+] Check Orthrus workspace... done
                [+] Adding job for [main]... done
                [+] Configuring job for [main]... done
                [+] Adding initial samples for job [main]... done
                [+] Adding initial samples for job [main]... done
```


## Step 3: Start/Stop afl fuzzers (via afl-utils)

- To start fuzzing for a pre-defined job, you do
```bash
$ orthrus start -j 1167520733
[+] Starting fuzzing jobs
                [+] Check Orthrus workspace... done
                [+] Start Fuzzers for Job [1167520733]... Checking core_pattern...okay
                [+] Starting AFL harden fuzzer job as master...done
                        [*] Starting master instance...

                                [+]  Master 000 started (PID: 15969)
                        [*] Starting slave instances...

                                [+]  Slave 001 started (PID: 15970)
                [+] Starting AFL ASAN fuzzer job as slave...done
                        [*] Starting slave instances...

                                [+]  Slave 001 started (PID: 16151)
                                [+]  Slave 002 started (PID: 16155)
```

- To stop fuzzing, you do
```bash
$ orthrus stop
[+] Stopping fuzzing jobs...done
```

- To resume an earlier session, do
```bash
$ orthrus start -j 1167520733 -m
[+] Starting fuzzing jobs
                [+] Check Orthrus workspace... done
                [+] Tidy fuzzer sync dir... done
                [+] Minimizing corpus for job [1167520733]...
                        [*] Looking for fuzzing queues in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Projec
t/.orthrus/jobs/1167520733/afl-out'.

                        [*] Found 1 fuzzers, collecting samples.

                        [*] Successfully indexed 3 samples.

                        [*] Copying 3 samples into collection directory...

                        [*] Executing: afl-cmin -i /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthr
us/jobs/1167520733/collect -o /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/co
llect.cmin -- /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/binaries/afl-harden/bin/main @@

                        [*] Testing the target binary...

                        [*] Obtaining traces for input files in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/collect'...

                        [*] Sorting trace sets (this may take a while)...

                        [*] Finding best candidates for each tuple...

                        [*] Sorting candidate list (be patient)...

                        [*] Processing candidates and writing output files...

                        [*] Performing dry-run in /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/collect.cmin...

                        [!] Be patient! Depending on the corpus size this step can take hours...

                        [!] Collection directory exists and is not empty!

                        [!] Skipping collection step...

                        [*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/1167520733/afl-out/SESSION000/queue

                [+] Start Fuzzers for Job [1167520733]... Checking core_pattern...okay
                [+] Starting AFL harden fuzzer job as master...done
                        [*] Starting master instance...

                                [+]  Master 000 started (PID: 28501)
                        [*] Starting slave instances...

                                [+]  Slave 001 started (PID: 28502)
                [+] Starting AFL ASAN fuzzer job as slave...done
                        [*] Starting slave instances...

                                [+]  Slave 001 started (PID: 28809)
                                [+]  Slave 002 started (PID: 28813)


- The `-m` flag minimizes the existing AFL corpus, archives the existing queue
dir, reseeds it with the minimized seeds, and resumes fuzzing

## Step 4: Monitor test coverage (via afl-cov)

WIP

## Step 5: Triage crashes (via afl-utils/exploitable)

- To triage an existing AFL corpus, do
```bash
$ orthrus triage -j 1167520733
[+] Triaging crashes for job [1167520733]
                [+] Collect and verify 'harden' mode crashes... done
                [+] Tidying crash dir...done!
                [+] Collect and verify 'asan' mode crashes... done
                [+] Tidying crash dir...done!
                [+] Collect and verify 'all' mode crashes... done
                [+] Tidying crash dir...done!
                [+] Triaged 15 crashes. See .orthrus/jobs/1167520733/unique/
```

## Step 6: Destroy orthrus session

- This permanently deletes all orthrus data (under `.orthrus`)
```bash
$ orthrus destroy
[+] Destroy Orthrus workspace
[?] Delete complete workspace? [y/n]...: y
                [+] Deleting all files... done
```

# Credits

Orthrus was possible due to excellent work by

- lcamtuf (afl-fuzz)
- rc0r (afl-utils)
- Michael Rash (afl-cov)
- Clang/LLVM sanitization projects
- Folks at afl users community and beyond

[1]: http://lcamtuf.coredump.cx/afl/
[2]: https://github.com/rc0r/afl-utils/tree/v1.27a
[3]: https://github.com/mrash/afl-cov/

