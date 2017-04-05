# Orthrus [![Build Status](https://travis-ci.org/test-pipeline/orthrus.svg?branch=master)](https://travis-ci.org/test-pipeline/orthrus) [![License](http://img.shields.io/:license-gpl3-blue.svg?style=flat-square)](http://www.gnu.org/licenses/gpl-3.0.html) [![Coverage Status](https://coveralls.io/repos/github/test-pipeline/orthrus/badge.svg?branch=master)](https://coveralls.io/github/test-pipeline/orthrus?branch=master)

Orthrus is a tool for managing, conducting, and assessing dictionary-based security (fuzz) testing for [autotools][1] projects. At the moment, it supports Clang/LLVM instrumentation and the AFL ecosystem (afl-fuzz, afl-utils, afl-cov). The ultimate aim is for Orthrus to be a generic wrapper around state-of-the-art fuzz and instrumentation tools on the one hand, and disparate build systems on the other.

**NEW**: The dictionary-based fuzzing feature is new. Do `orthrus create -dict` to generate a fuzzing dictionary and `orthrus add --jobconf` to specify fuzz options (e.g., `-x dict`) for making use of the generated dictionary for fuzzing.

# Installation

Please read [docs/Getting_started.md](docs/Getting_started.md).

# Workflow

Orthrus currently supports two workflows. In a routine workflow, you work with a single fuzzing job end-to-end i.e., from source code instrumentation, until crash triage. In a A/B test workflow, you work with a single A/B test end-to-end.

## Routine

Please read [docs/Workflow.md](docs/Workflow.md).

## A/B testing

Please read [docs/Workflow_abtests.md](docs/Workflow_abtests.md).

# Full usage
```
$ orthrus -h
usage: Orthrus 1.1 by Bhargava Shastry, and Markus Leutner <https://github.com/test-pipeline/orthrus> 
       [-h] [-v]
       {create,add,remove,start,stop,show,triage,coverage,spectrum,runtime,destroy,validate}
       ...

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode, print information about the progress

subcommands:
  Orthrus subcommands

  {create,add,remove,start,stop,show,triage,coverage,spectrum,runtime,destroy,validate}
    create              Create an orthrus workspace
    add                 Add a fuzzing job
    remove              Remove a fuzzing job
    start               Start a fuzzing jobs
    stop                Stop a fuzzing jobs
    show                Show what's currently going on
    triage              Triage crash corpus
    coverage            Run afl-cov on existing AFL corpus
    spectrum            Run spectrum based analysis on existing AFL corpus
    runtime             Perform dynamic analysis of existing AFL corpus
    destroy             Destroy an orthrus workspace
    validate            Check if all Orthrus dependencies are met
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

[1]: https://en.wikipedia.org/wiki/GNU_Build_System

