#!/usr/bin/env bash
echo -e "\t[+] Fetching afl-latest"
wget -q http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz &> /dev/null
tar xzf afl-latest.tgz &> /dev/null
rm -f afl-latest.tgz && cd afl-*
echo -e "\t[+] Installing afl"
sudo make install
cd ..
echo -e "\t[+] Install aflfast"
git clone https://github.com/mboehme/aflfast.git
cd aflfast
make && sudo mv afl-fuzz /usr/local/bin/afl-fuzz-fast
cd ..
echo -e "\t[+] Setting core_pattern"
echo core | sudo tee /proc/sys/kernel/core_pattern
echo -e "\t[+] Running autotools in test dir"
cd testdata/Automake-Autoconf-Template-Project
libtoolize --force
aclocal && automake --force-missing --add-missing && autoconf
cd ../../
echo -e "\t[+] Installing afl-utils"
wget -q https://github.com/rc0r/afl-utils/archive/v1.32a.tar.gz && tar xzf v1.32a.tar.gz
rm v1.32a.tar.gz && cd afl-utils-1.32a
sudo mkdir -p /usr/lib/python3.4/site-packages && sudo python3 setup.py install
cd ../
echo -e "\t[+] Setting up GDB and exploitable"
cat <<EOF >> ~/.gdbinit
source /usr/lib/python3.4/site-packages/exploitable-1.32_rcor-py3.4.egg/exploitable/exploitable.py
source ~/.orthrus/gdb_orthrus.py
define hook-quit
    set confirm off
end
set pagination off
EOF
echo -e "\t[+] Installing afl-cov"
wget -q https://github.com/mrash/afl-cov/archive/0.6.tar.gz && tar xzf 0.6.tar.gz
rm 0.6.tar.gz && cd afl-cov-0.6
sudo cp afl-cov /usr/local/bin/
cd ..
echo -e "\t[+] Installing pysancov"
wget -q https://raw.githubusercontent.com/llvm-mirror/compiler-rt/release_38/lib/sanitizer_common/scripts/sancov.py &> /dev/null
chmod +x sancov.py &> /dev/null
sudo mv sancov.py /usr/local/bin/pysancov &> /dev/null
echo -e "\t[+] Copy gdb-orthrus.py to orthrus-local"
mkdir -p $HOME/.orthrus
wget https://raw.githubusercontent.com/test-pipeline/orthrus/master/gdb-orthrus/gdb_orthrus.py -P $HOME/.orthrus
CLANG_SDICT_DB="https://www.dropbox.com/s/lqayfheheo3coag/fork-6173707-6216-gb24cc33-153448-2017-04-10.tar.gz?dl=0"
curl -o clang.tar.gz -L "$CLANG_SDICT_DB" && tar xzf clang.tar.gz -C $HOME && chmod +x $HOME/local/bin/clang-sdict
echo -e "\t[+] Install bear v2.1.5"
wget https://launchpadlibrarian.net/240291131/bear_2.1.5.orig.tar.gz && tar xzf bear_2.1.5.orig.tar.gz && rm bear_2.1.5.orig.tar.gz
mkdir Bear-2.1.5.build && cd Bear-2.1.5.build && cmake ../Bear-2.1.5 && make -j all && sudo make install && cd .. && rm -rf Bear-2.1.5 Bear-2.1.5.build
