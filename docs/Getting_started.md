# Pre-requisites

- python
  - 2.7 for orthrus
  - 3.X for afl-utils
- [afl-fuzz][1]
- [afl-utils][2] (latest: v1.31a, v1.32a (experimental) for a/b test support)
```bash
$ cd $HOME
$ wget -q https://github.com/rc0r/afl-utils/archive/v1.31a.tar.gz && tar xzf v1.31a.tar.gz
$ rm v1.31a.tar.gz && cd afl-utils-1.31a
$ sudo mkdir -p /usr/lib/python3.4/site-packages && sudo python3 setup.py install
$ cd ../
$ echo "source /usr/lib/python3.4/site-packages/exploitable-1.32_rcor-py3.4.egg/exploitable/exploitable.py" >> ~/.gdbinit
$ sudo rm -rf afl-utils-1.31a
```

- [afl-cov][3] (latest: v0.6)
```bash
wget -q https://github.com/mrash/afl-cov/archive/0.6.tar.gz && tar xzf 0.6.tar.gz
rm 0.6.tar.gz && cd afl-cov-0.6
sudo cp afl-cov /usr/local/bin/
cd .. && rm -rf afl-cov-0.6
```

- Clang/LLVM toolchain
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

# Installation

```
$ (sudo) python2.7 setup.py install
```
