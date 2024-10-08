import io
import os
from setuptools import setup

def read(*paths, **kwargs):
      """Read the contents of a text file safely.
      >>> read("project_name", "VERSION")
      '0.1.0'
      >>> read("README.md")
      ...
      """

      content = ""
      with io.open(
              os.path.join(os.path.dirname(__file__), *paths),
              encoding=kwargs.get("encoding", "utf8"),
      ) as open_file:
            content = open_file.read().strip()
      return content


def read_requirements(path):
      return [
            line.strip()
            for line in read(path).split("\n")
            if not line.startswith(('"', "#", "-", "git+"))
      ]


setup(name='did-vc',
      version='0.1',
      description='Test lib to sign VCs with DIDs',
      author='pduchesne',
      license='MIT',
      packages=['didvc', 'didvc.signatures'],
      #scripts=['bin/did_vc.py'],
      install_requires=read_requirements("requirements.txt"),
      zip_safe=False)