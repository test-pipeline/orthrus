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
$ orthrus start -j 1167520733

```

- To stop fuzzing, you do
```
$ orthrus stop -j 
[+] Stopping fuzzing jobs...done
```

- To resume an earlier session, do
```
$ orthrus start -j 1167520733 -m

```


- The `-m` flag minimizes the existing AFL corpus, archives the existing queue
dir, reseeds it with the minimized seeds, and resumes fuzzing

## Step 5: Monitor test coverage (via afl-cov)

You can monitor the coverage of your a/b test jobs offline. To do so, type:

```
$ orthrus coverage -j 1167520733
[+] Checking test coverage for job [1167520733]... done
                [+] Please check .orthrus/jobs/1167520733/afl-out/cov for coverage info
```

Note that live AFL coverage via afl-cov is unsupported for a/b test jobs.

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

[1]: 
