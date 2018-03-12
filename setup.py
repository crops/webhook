import sys

from setuptools import setup

# python 3.3 fails with newer versions of pytest
if sys.version_info[:2] == (3, 3):
    pytest_runner = ['pytest-runner<=3.0.1']
else:
    pytest_runner = ['pytest-runner']

setup(
    name="crops-webhook",
    version="0.0.1",
    author="Randy Witt",
    author_email="randy.e.witt@linux.intel.com",
    license="GPLv2",
    install_requires=['Flask>=0.9'],
    setup_requires=pytest_runner,
    tests_require=['pytest-pep8'],
    packages=['.'],
)
