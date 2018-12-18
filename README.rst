hadoop_ranger_audit
===================

Generates a stand alone web based report for Hadoop Apache Ranger policies.
Performs reverse lookups against Active Directory to match users with Ranger resources that have been
provision with AD Groups.


Installation from GIT source:
-----------------------------

Clone the repo::

    $ git clone https://github.com/jackscodemonkey/hadoop_ranger_audit

Create a new virtual environment::

    $ virtualenv -p python3 hadoop_ranger_audit_env

Activate the new environment::

    $ source hadoop_ranger_audit_env/bin/activate

Your command prompt should now have the environment prefix showing::

   $ (hadoop_ranger_audit_env):

Quickly install hadoop_ranger_audit into your new environment via `setuptools`_
Change to the directory where you downloaded this package and run::

   $ (hadoop_ranger_audit_env)python setup.py install


Requirements
^^^^^^^^^^^^

.. include:: ../../requirements.txt

Compatibility
-------------

These admin scripts are written in Python 2.7 to conform with the
current release of Greenplum 5.5

Licence
-------

Authors
-------

`hadoop_ranger_audit` was written by `Marcus Robb <marcus.robb@initworx.com>`_.


.. _`setuptools`: http://pypi.python.org/pypi/setuptools