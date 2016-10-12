# Basics

- A/B testing of fuzzers or fuzzing variations supported at the moment
  - You can A/B test afl-fuzz vs afl-fuzz-fast
  - You can A/B test afl-fuzz vs afl-fuzz -d
  - You **cannot** A/B test program1 vs program 2
  - You **cannot** A/B test program1 --arg1 vs program1 --arg2
- Please bear in mind that the test program, arguments, and fuzz configuaration are identical for both the control (A) and experiment (B) groups
  - The only thing that is going to be different is the fuzzer used and/or arguments passed to it
  - It is your sole responsibility to use the A/B test interface meaningfully

## Step 1: Validate dependencies for A/B testing

If you have already validated Orthrus before, you only need to validate incremental dependencies of A/B testing. For instance, you may want to use afl-fuzz-fast for A/B tests with afl-fuzz. For validating dependencies introduced by A/B testing, simply add the dependency in the (already existing) `dependencies` section in `~/.orthrus/orthrus.conf`, like so
```
[dependencies]
clang = on
gcc = on
...

afl-fuzz-fast = on

```
$ orthrus validate
[+] Validating Orthrus dependencies
                [+] The following programs have been marked as required in ~/.orthrus/orthrus.conf
                        [+] clang
                        [+] gcc
                        [+] afl-fuzz
                        [+] afl-clang
                        [+] afl-clang++
                        [+] afl-collect
                        [+] afl-multicore
                        [+] afl-minimize
                        [+] gdb
                        [+] afl-cov
                        [+] lcov
                        [+] genhtml
			[+] afl-fuzz-fast
                [+] Checking if requirements are met.
                [+] All requirements met. Orthrus is ready for use!
```

## Step 2: Create instrumented binaries

Creating binaries is no different for A/B testing. Please read step 2 of [docs/Workflow.md](Workflow.md) if you haven't already. Please note that fuzzed binaries are identical for both the control (A) and experiment (B) groups.


## Step 3: Add/Remove fuzzing job

Adding/removing a/b test jobs is identical to their routine counterparts, except for the `--abtest=PATH_TO_CONFIG` argument. For instance, you can do
```
$ cat abtest.conf
[test1]
name = "Test 1"
fuzzerA = "afl-fuzz"
fuzzerA_args = ""
fuzzerB = "afl-fuzz-fast"
fuzzerB_args = ""
$ orthrus add --job="main @@" -s=./seeds --abtest=./abtest.conf

```

This sets up an A/B testing job in which identical fuzzing jobs will be created for both control and experiment groups.


## Step 4: Start/Stop afl fuzzers (via afl-utils)

- To start fuzzing for a pre-defined job, you do
```
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
```
$ orthrus stop
[+] Stopping fuzzing jobs...done
```

- To resume an earlier session, do
```
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
```


- The `-m` flag minimizes the existing AFL corpus, archives the existing queue
dir, reseeds it with the minimized seeds, and resumes fuzzing

## Step 5: Monitor test coverage (via afl-cov)

You can either:

- Monitor test coverage during a live fuzzing session
```
$ orthrus start -j 1167520733 -c
[+] Starting fuzzing jobs
                [+] Check Orthrus workspace... done
                [+] Start afl-cov for Job [1167520733]... done
                [+] Start Fuzzers for Job [1167520733]... Checking core_pattern...okay
                [+] Starting AFL harden fuzzer job as master...done
                        [*] Starting master instance...

                                [+]  Master 000 started (PID: 25378)
                        [*] Starting slave instances...

                                [+]  Slave 001 started (PID: 25379)
```

- OR check test coverage post testing (when all instances of afl-fuzz are dead)
```
$ orthrus coverage -j 1167520733
[+] Checking test coverage for job [1167520733]... done
                [+] Please check .orthrus/jobs/1167520733/afl-out/cov for coverage info
```

You may force stop a live afl-cov instance along with all fuzz sessions, like so
```
$ orthrus stop -c
[+] Stopping fuzzing jobs...done
[+] Stopping afl-cov for jobs...done
```

## Step 6: Triage crashes (via afl-utils/exploitable)

- To triage an existing AFL corpus, do
```
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

## Step 7: User interface for fuzz status and coverage

- You may view configured jobs, like so
```
$ orthrus show -j
Configured jobs found:
        0) [1167520733] main @@
```

- You may view the current status of afl-fuzz instances (via afl-whatsup)
```
$ orthrus show
Status of jobs:
        Job [1167520733] for target 'main':
               Fuzzers alive : 0
              Dead or remote : 2 (excluded from stats)
              Total run time : 0 days, 0 hours
                 Total execs : 0 million
            Cumulative speed : 0 execs/sec
               Pending paths : 0 faves, 0 total
               Crashes found : 0 locally unique

             Triaged crashes : 0 available
```

- You may view coverage report (via afl-cov)
```
$ orthrus show -c
Opening coverage html for job 1167520733 in a new browser tab
```

## Step 8: Destroy orthrus session

- This permanently deletes all orthrus data (under `.orthrus`)
```
$ orthrus destroy
[+] Destroy Orthrus workspace
[?] Delete complete workspace? [y/n]...: y
                [+] Deleting all files... done
```
