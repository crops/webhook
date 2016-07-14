from setuptools import setup

setup(
    name="crops-webhook",
    version="0.0.1",
    author="Randy Witt",
    author_email="randy.e.witt@linux.intel.com",
    license="GPLv2",
    install_requires=['Flask>=0.9'],
    setup_requires=['pytest-runner'],
    tests_require=['pytest-pep8'],
    packages=['.'],
)
