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

Adding/removing a/b test jobs is identical to their routine counterparts, except for the `--abtest=PATH_TO_CONFIG` argument that is appended to the `orthrus add` command. For instance, you can do
```
$ cat abtest.conf
[test1]
name = "Test 1"
fuzzerA = "afl-fuzz"
fuzzerA_args = ""
fuzzerB = "afl-fuzz-fast"
fuzzerB_args = ""
$ orthrus add --job="main @@" -s=./seeds --abtest=./abtest.conf
[+] Adding fuzzing job to Orthrus workspace
		[+] Checking Orthrus workspace... done
		[+] Adding job... done
		[+] Configuring abtests job for ID [1178951622]... done
		[+] Adding initial samples for job ID [1178951622]... done
		[+] Configuring abtests job for ID [3911664828]... done
		[+] Adding initial samples for job ID [3911664828]... done
$ orthrus remove -j 1271685425
[+] Removing fuzzing job from Orthrus workspace
		[+] Retrieving job [1271685425]... done
		[+] Archiving data for abtests job [1271685425]... done
```

This sets up an A/B testing job in which identical fuzzing jobs will be created for both control (e.g. `afl-fuzz`) and experiment (e.g. `afl-fuzz-fast`) groups. **It is strongly recommended that you have at least 4 processor cores for a/b testing**. This ensures that each job has at least 1 master and 1 slave instance. This is particularly relevant for gauging the efficiency of deterministic fuzzing. See [1].

Note that there are three IDs involved. You can ID the configured a/b test via the top-level ID `1271685425`, the control group via ID `1178951622` and the experiment group via ID `3911664828`. For subsequent a/b test subcommands, you always pass the top-level (a/b test) ID e.g., `1271685425`.


## Step 4: Start/Stop afl fuzzers (via afl-utils)

- To start fuzzing for a pre-defined a/b test job, you do
```
$ orthrus start -j 1271685425
[+] Starting fuzzing jobs
		[+] Retrieving job ID [1271685425]... done
		[+] Tidying afl sync dir for abtests job ID [1178951622]... done
		[+] Checking core_pattern... done
		[+] Starting AFL ASAN fuzzer as master... done
			[*] Starting master instance...

				[+]  Master 000 started (PID: 4725)
			[*] Starting slave instances...

				[+]  Slave 001 started (PID: 4726)
		[+] Starting fuzzer for abtests job ID [1178951622]... done
		[+] Tidying afl sync dir for abtests job ID [3911664828]... done
		[+] Checking core_pattern... done
		[+] Starting AFL ASAN fuzzer as master... done
			[*] Starting master instance...

				[+]  Master 000 started (PID: 4730)
			[*] Starting slave instances...

				[+]  Slave 001 started (PID: 4731)
		[+] Starting fuzzer for abtests job ID [3911664828]... done
```

- To stop fuzzing, you do
```
$ orthrus stop -j 1271685425
[+] Stopping fuzzing jobs
		[+] Retrieving job ID [1271685425]... done
		[+] Stopping abtests job for ID [1271685425]... done
```

- To resume an earlier session, do
```
$ orthrus start -j 1271685425 -m
[+] Starting fuzzing jobs
		[+] Retrieving job ID [1271685425]... done
		[+] Tidying afl sync dir for abtests job ID [1178951622]... done
		[+] Minimizing corpus for job [1178951622]...
			[*] Looking for fuzzing queues in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/1178951622/afl-out'.

			[*] Found 1 fuzzers, collecting samples.

			[*] Successfully indexed 5 samples.

			[*] Copying 5 samples into collection directory...

			[*] Executing: afl-cmin -i /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/1178951622/collect -o /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/1178951622/collect.cmin -- /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/binaries/afl-asan/bin/main @@

			[*] Testing the target binary...

			[*] Obtaining traces for input files in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/1178951622/collect'...

			[*] Sorting trace sets (this may take a while)...

			[*] Finding best candidates for each tuple...

			[*] Sorting candidate list (be patient)...

			[*] Processing candidates and writing output files...

			[!] WARNING: All test cases had the same traces, check syntax!

			[*] Performing dry-run in /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/1178951622/collect.cmin...

			[!] Be patient! Depending on the corpus size this step can take hours...

			[!] Collection directory exists and is not empty!

			[!] Skipping collection step...

			[*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/1178951622/afl-out/SESSION000/queue

		[+] Minimizing afl sync dir for abtests job ID [1178951622]... done
		[+] Checking core_pattern... done
		[+] Starting AFL ASAN fuzzer as master... done
			[*] Starting master instance...

				[+]  Master 000 started (PID: 8251)
			[*] Starting slave instances...

				[+]  Slave 001 started (PID: 8253)
		[+] Starting fuzzer for abtests job ID [1178951622]... done
		[+] Tidying afl sync dir for abtests job ID [3911664828]... done
		[+] Minimizing corpus for job [3911664828]...
			[*] Looking for fuzzing queues in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/3911664828/afl-out'.

			[*] Found 1 fuzzers, collecting samples.

			[*] Successfully indexed 4 samples.

			[*] Copying 4 samples into collection directory...

			[*] Executing: afl-cmin -i /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/3911664828/collect -o /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/3911664828/collect.cmin -- /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/binaries/afl-asan/bin/main @@

			[*] Testing the target binary...

			[*] Obtaining traces for input files in '/home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/3911664828/collect'...

			[*] Sorting trace sets (this may take a while)...

			[*] Finding best candidates for each tuple...

			[*] Sorting candidate list (be patient)...

			[*] Processing candidates and writing output files...

			[!] WARNING: All test cases had the same traces, check syntax!

			[*] Performing dry-run in /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/3911664828/collect.cmin...

			[!] Be patient! Depending on the corpus size this step can take hours...

			[!] Collection directory exists and is not empty!

			[!] Skipping collection step...

			[*] Reseeding collect.cmin into queue /home/bhargava/work/gitlab/orthrus/testdata/Automake-Autoconf-Template-Project/.orthrus/jobs/abtests/1271685425/3911664828/afl-out/SESSION000/queue

		[+] Minimizing afl sync dir for abtests job ID [3911664828]... done
		[+] Checking core_pattern... done
		[+] Starting AFL ASAN fuzzer as master... done
			[*] Starting master instance...

				[+]  Master 000 started (PID: 9597)
			[*] Starting slave instances...

				[+]  Slave 001 started (PID: 9598)
		[+] Starting fuzzer for abtests job ID [3911664828]... done
```


- The `-m` flag minimizes the existing AFL corpus, archives the existing queue
dir, reseeds it with the minimized seeds, and resumes fuzzing

## Step 5: Monitor test coverage (via afl-cov)

Monitoring test coverage for a/b tests is WIP

## Step 6: Triage crashes (via afl-utils/exploitable)

Triaging crashes for A/B tests is WIP

## Step 7: User interface for fuzz status and coverage

- You may view configured jobs, like so
```
$ orthrus show -conf
Configured a/b tests:
	0) [1271685425] main @@
	Control group
	Fuzzer A: afl-fuzz	 Fuzzer A args: 
	Experiment group
	Fuzzer B: afl-fuzz-fast	 Fuzzer B args: 
```

- You may view the current status of afl-fuzz instances (via afl-whatsup)
```
$ orthrus show -j 1271685425
A/B test status
Control group
	       Fuzzers alive : 2
	      Total run time : 0 days, 0 hours
	         Total execs : 0 million
	    Cumulative speed : 0 execs/sec
	       Pending paths : 2 faves, 2 total
	  Pending per fuzzer : 1 faves, 1 total (on average)
	       Crashes found : 0 locally unique
	
	     Triaged crashes : 0
Experiment group
	       Fuzzers alive : 2
	      Total run time : 0 days, 0 hours
	         Total execs : 0 million
	    Cumulative speed : 0 execs/sec
	       Pending paths : 2 faves, 2 total
	  Pending per fuzzer : 1 faves, 1 total (on average)
	       Crashes found : 0 locally unique
	
	     Triaged crashes : 0
```

- Coverage measurement for A/B tests is WIP.

## Step 8: Destroy orthrus session

See [Step 8 of Workflow]()

[1]: https://groups.google.com/d/msg/afl-users/fOPeb62FZUg/LYxgPYheDwAJ
