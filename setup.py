from setuptools import setup, find_packages
import os

setup(
    name = "orthrus",
    version = "0.1 (pre-alpha)",
    author = "Markus Leutner, and Bhargava Shastry",
    author_email = "bshastry@sec.t-labs.tu-berlin.de",
    description = "A tool for end-to-end security testing.",
    license = "GPLv3",
    url = "https://gitlab.sec.t-labs.tu-berlin.de/collaboration/Orthrus.git",
    long_description = open('./README.md', 'r').read(),
    packages = find_packages(),
    data_files=[(os.path.expanduser('~') + '/.orthrus', ['conf/orthrus.conf'])],
    classifiers=["Development Status :: 2 - Pre-Alpha",
                 "Topic :: Security",
                 "Programming Language :: Python :: 2",
                 "Operating System :: POSIX :: Linux"],
    scripts = ['tool/orthrus'],
    install_requires = ['afl-utils'],
    dependency_links = ['https://github.com/rc0r/afl-utils/tarball/master#egg=afl-utils-v1.30a'],
                        #'https://github.com/mrash/afl-cov/tarball/master#egg=afl-cov-0.6'],
    keywords=[ 'Fuzzing',
               'American Fuzzy Lop',
               'Triage'
                ],
    test_suite='tests',
    zip_safe = False
)