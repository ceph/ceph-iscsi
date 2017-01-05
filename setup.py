#!/usr/bin/python

from setuptools import setup
import distutils.command.install_scripts
import shutil
import os

if os.path.exists('README'):
    with open('README') as readme_file:
        long_description = readme_file.read().strip()
else:
    long_description = ''


# idea from http://stackoverflow.com/a/11400431/2139420
class StripExtension(distutils.command.install_scripts.install_scripts):
    """
    Class to handle the stripping of .py extensions in for executable file names
    making them more user friendly
    """
    def run(self):
        distutils.command.install_scripts.install_scripts.run(self)
        for script in self.get_outputs():
            if script.endswith(".py"):
                shutil.move(script, script[:-3])


setup(
    name="gwcli",
    version="2.0",
    description="cli interface to iscsi gateways based on configshell_fb modules",
    long_description=long_description,
    author="Paul Cuzner",
    author_email="pcuzner@redhat.com",
    url="http://github.com/pcuzner/ceph-iscsi-cli",
    license="GPLv3",
    packages=[
        "gwcli"
        ],
    scripts=[
        'gwcli.py',
        'rbd-target-api.py'
    ],
    cmdclass={
        "install_scripts": StripExtension
    }
)
