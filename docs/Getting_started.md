# Pre-requisites

- python
  - 2.7 for orthrus
  - 3.X for afl-utils
- [afl-fuzz][1]
- [afl-utils][2] (latest: v1.31a, v1.32a (experimental) for a/b test support)
- virtualenv and virtualenvwrapper (optional but highly recommended)

```bash
$ pip install virtualenv && pip install virtualenvwrapper
```

- Clang/LLVM toolchain (Tested with v3.8)
```bash
$ sudo apt-get install lcov
$ curl -sSL "http://apt.llvm.org/llvm-snapshot.gpg.key" | sudo -E apt-key add -
$ echo "deb http://apt.llvm.org/trusty/ llvm-toolchain-trusty-3.8 main" | sudo tee -a /etc/apt/sources.list > /dev/null
$ sudo apt-get update
$ sudo apt-get --no-install-suggests --no-install-recommends --force-yes install clang-3.8 libclang-common-3.8-dev llvm-3.8-runtime llvm-3.8
```
- lcov
```bash
$ sudo apt-get install lcov
```
- An autotools open-source project for fuzzing

# Python package dependencies

You can install Orthus' python dependencies (afl-utils, and afl-cov) via virtualenvwrapper or natively. The former is recommended.

## Using Virtualenvwrapper

All steps that work assume that you are creating and working with the `afl` virtualenv (`workon afl`)

- afl-utils (use 1.32a instead of 1.31a for a/b testing)

```bash
$ mkvirtualenv -p /usr/bin/python3.4 afl
$ wget -q https://github.com/rc0r/afl-utils/archive/v1.31a.tar.gz && tar xzf v1.31a.tar.gz
$ rm v1.31a.tar.gz && cd afl-utils-1.31a
$ python setup.py install
```

- afl-cov (v0.6)

```bash
$ wget -q https://github.com/mrash/afl-cov/archive/0.6.tar.gz && tar xzf 0.6.tar.gz
$ rm 0.6.tar.gz && cd afl-cov-0.6
$ cp afl-cov ~/.virtualenvs/afl/bin/
```


## Native installation

- afl-utils (use 1.32a instead of 1.31a for a/b testing)
```bash
$ cd $HOME
$ wget -q https://github.com/rc0r/afl-utils/archive/v1.31a.tar.gz && tar xzf v1.31a.tar.gz
$ rm v1.31a.tar.gz && cd afl-utils-1.31a
$ sudo mkdir -p /usr/lib/python3.4/site-packages && sudo python3 setup.py install
$ cd ../
$ echo "source /usr/lib/python3.4/site-packages/exploitable-1.32_rcor-py3.4.egg/exploitable/expl
$ sudo rm -rf afl-utils-1.31a
```

- afl-cov (v0.6)
```bash
$ wget -q https://github.com/mrash/afl-cov/archive/0.6.tar.gz && tar xzf 0.6.tar.gz
$ rm 0.6.tar.gz && cd afl-cov-0.6
$ sudo cp afl-cov /usr/local/bin/
$ cd .. && rm -rf afl-cov-0.6
```

# Installation

## Using Virtualenvwrapper

- For a/b test sandwich `-b dev` between `git clone` and the git URL

```bash
$ mkdir -p ~/.virtualenvs/afl/lib/python2.7/site-packages/
$ export PYTHONPATH=$HOME/.virtualenvs/afl/lib/python2.7/site-packages
$ git clone https://github.com/test-pipeline/orthrus.git && cd orthrus
$ python2.7 setup.py install --prefix ~/.virtualenvs/afl
```

A convenient alias would be something like this appended to `~/.bash_aliases`
```
# Uses the right PYTHONPATH before invoking orthrus
alias orthrus=`PYTHONPATH=$HOME/.virtualenvs/afl/lib/python2.7/site-packages orthrus`
```

Whenever you want to fuzz an autotools codebase, you may simply summon orthrus, afl-utils, and afl-cov by doing `workon afl`.

## Native installation

```
$ (sudo) python2.7 setup.py install
```

[1]: http://lcamtuf.coredump.cx/afl/
[2]: https://github.com/rc0r/afl-utils/tree/v1.27a
[3]: https://github.com/mrash/afl-cov/

