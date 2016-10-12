# Orthrus [![Build Status](https://travis-ci.org/test-pipeline/orthrus.svg?branch=master)](https://travis-ci.org/test-pipeline/orthrus) [![License](http://img.shields.io/:license-gpl3-blue.svg?style=flat-square)](http://www.gnu.org/licenses/gpl-3.0.html) [![Coverage Status](https://coveralls.io/repos/github/test-pipeline/orthrus/badge.svg?branch=master)](https://coveralls.io/github/test-pipeline/orthrus?branch=master)

Orthrus is a tool for managing, conducting, and assessing security (fuzz) testing for [autotools][4] projects. At the moment, it supports Clang/LLVM instrumentation and the AFL ecosystem (afl-fuzz, afl-utils, afl-cov). The ultimate aim is for Orthrus to be a generic wrapper around state-of-the-art fuzz and instrumentation tools on the one hand, and disparate build systems on the other.

# Installation

See [docs/Getting_started.md](docs/Getting_started.md)

# Workflow

See [docs/Workflow.md](docs/Workflow.md)

## A/B testing

See [docs/Workflow_abtests.md](docs/Workflow_abtests.md)

# Full usage
```
$ orthrus -h
usage: A tool to manage, conduct, and assess security testing of autotools projects.
       [-h] [-v]
       {create,add,remove,start,stop,show,triage,coverage,destroy} ...

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode, print information about the progress

subcommands:
  Orthrus subcommands

  {create,add,remove,start,stop,show,triage,coverage,destroy}
    create              Create an orthrus workspace
    add                 Add a fuzzing job
    remove              Remove a fuzzing job
    start               Start the fuzzing jobs
    stop                Stop the fuzzing jobs
    show                Show whats currently going on
    triage              Triage crash samples
    coverage            Run afl-cov on existing AFL corpus
    destroy             Destroy the orthrus workspace

# For subcommand help
$ orthrus create -h
usage: A tool to manage, conduct, and assess security testing of autotools projects. create
       [-h] [-asan] [-fuzz] [-cov] [-d [CONFIGURE_FLAGS]]

optional arguments:
  -h, --help            show this help message and exit
  -asan, --afl-asan     Setup binaries for afl with AddressSanitizer
  -fuzz, --afl-harden   Setup binaries for afl in 'harden' mode (stack-
                        protector, fortify)
  -cov, --coverage      Setup binaries to collect coverage information
  -d [CONFIGURE_FLAGS], --configure-flags [CONFIGURE_FLAGS]
                        Additional flags for configuring the source

```

# Issues and PRs

- Feel free to file an issue if something doesn't work as expected :-)
  - Attaching logs from `.orthrus/logs` would be helpful 
- PRs for interesting workflows are much appreciated!

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
[4]: https://en.wikipedia.org/wiki/GNU_Build_System

