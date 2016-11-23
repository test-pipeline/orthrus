### v1.2

- Upgraded to afl-cov v0.6 (and 1.32a afl-utils for a/b tests)
- Added a/b tests feature to orthrus subcommands
  - This systematizes a/b experiments
- Added spectrum and runtime features
  - Spectrum merges the feature set of afl-sancov, albeit only for routine jobs
  - Runtime introduces a new feature that allows ASAN crash reports to be jsonified
- Major refactoring and additional test cases 
- Bug fixes
  - Compact sync dir leads to incorrect resumes
  - Start fuzzer not using all available cores optimally
  - Use afl-multikill instead of a hacky `pkill -9` to terminate multicore fuzzing sessions
    - This fixes bug related to shared mem segments (that afl-fuzz requests via shmget()) that were not getting freed

### v1.1

- Upgraded to afl-utils 1.31a (JSON config instead of ini config)

### v1.0

- First release
