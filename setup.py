from setuptools import setup, find_packages
import os

setup(
    name = "orthrus",
    version = "0.1 (alpha)",
    author = "Markus Leutner",
    author_email = "markus.leutner@campus.tu-berlin.de",
    description = "A tool for extended analysis of fuzzed applications.",
    license = "GPLv3",
    url = "https://gitlab.sec.t-labs.tu-berlin.de/mleutner/orthrus/",
    long_description = open('./README.md', 'r').read(),
    packages = find_packages(),
    data_files=[('/usr/share/gdb/gdb-orthrus', ['gdb-orthrus/orthrus.py']),
                (os.path.expanduser('~') + '/.orthrus', ['conf/orthrus.conf'])],
    scripts = ['tool/orthrus'],
    install_requires = [],
    zip_safe = False
)