from setuptools import setup, find_packages
import os
import orthrus

setup(
    name = "orthrus",
    version = orthrus.__version__,
    author = "Bhargava Shastry, and Markus Leutner",
    author_email = "bshastry@sec.t-labs.tu-berlin.de",
    description = "A tool for end-to-end security testing.",
    license = "GPLv3",
    url = "https://github.com/test-pipeline/orthrus.git",
    long_description = open('./README.md', 'r').read(),
    packages = find_packages(),
    data_files=[(os.path.expanduser('~') + '/.orthrus', ['conf/orthrus.conf', 'gdb-orthrus/gdb_orthrus.py'])],
    classifiers=["Topic :: Security",
                 "Programming Language :: Python :: 2",
                 "Operating System :: POSIX :: Linux"],
    scripts = ['tool/orthrus'],
    keywords=[ 'Fuzzing',
               'American Fuzzy Lop',
               'Triage'
                ],
    test_suite='tests',
    zip_safe = False
)
