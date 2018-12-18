from setuptools import setup
from distutils.core import setup

with open('README.rst') as file:
    long_description= file.read()

setup(
    name='hadoop_ranger_audit',
    version='0.2',
    packages=['hadoop_ranger_audit'],
    url='https://github.com/jackscodemonkey/hadoop_ranger_audit',
    license='MIT',
    author='Marcus Robb',
    author_email='marcus.robb@initworx.com',
    description="""Generates a stand alone web based report for Hadoop Apache Ranger policies.
                Performs reverse lookups against Active Directory to match users with Ranger resources that have been
                provision with AD Groups.""",
    long_description=long_description,
    install_requires=[
        'alabaster',
        'Babel',
        'certifi',
        'chardet',
        'docutils',
        'idna',
        'imagesize',
        'Jinja2',
        'ldap3',
        'MarkupSafe',
        'packaging',
        'pyasn1',
        'Pygments',
        'pyparsing',
        'pytz',
        'requests',
        'six',
        'snowballstemmer',
        'Sphinx',
        'sphinx-rtd-theme',
        'sphinx-theme',
        'sphinxcontrib-websupport',
        'urllib3'
      ],
    scripts=['hadoop_ranger_audit/hadoop_ranger_audit.py',
             'hadoop_ranger_audit/report_template.html'],
    include_package_data=True,
)
