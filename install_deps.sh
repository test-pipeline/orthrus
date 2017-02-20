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
