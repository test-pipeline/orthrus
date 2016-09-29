#!/usr/bin/env bash
echo -e "\t[+] Fetching afl-latest"
wget -q http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz &> /dev/null
tar xzf afl-latest.tgz &> /dev/null
rm -f afl-latest.tgz && cd afl-*
echo -e "\t[+] Installing afl"
sudo make install
cd ..
echo -e "\t[+] Setting core_pattern"
echo core | sudo tee /proc/sys/kernel/core_pattern
echo -e "\t[+] Running autotools in test dir"
cd testdata/Automake-Autoconf-Template-Project
libtoolize --force
aclocal && automake --force-missing --add-missing && autoconf
cd ../../
echo -e "\t[+] Installing afl-utils"
git clone https://github.com/rc0r/afl-utils.git
cd afl-utils && sudo python3 setup.py install
cd ../
