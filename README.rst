hadoop_ranger_audit
===================

Generates a stand alone web based report for Hadoop Apache Ranger policies.
Performs reverse lookups against Active Directory to match users with Ranger resources that have been
provision with AD Groups.

Currently provides a report the following policies:
HDFS
HIVE
KNOX
YARN

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


Usage:
------
hadoop_ranger_audit.py::

 Switch                  | Description                       | Required
 ======================================================================
 --ranger_url            | Ranger API URL                    | Yes
 --ranger_user           | Ranger API Username               | Yes
 --ranger_password       | Ranger API Password               | Yes
 --ad_controller         | Active Directory Server Hostname  | Yes
 --ad_user               | Read Only AD user - basic account | Yes
 --ad_password           | AD user password                  | Yes
 --ad_search_base        | DN root to start search from      | Yes
 --output_file           | Output HTML file                  | Yes
 --cluster_name          | Name of cluster for the report    | Yes
 -h / --help             | Print command help                | No


Requirements
^^^^^^^^^^^^

.. include:: requirements.txt

Compatibility
-------------

hadoop_ranger_audit is written and tested in Python 3.6.

Licence
-------

Licensed under the MIT license.

Authors
-------

`hadoop_ranger_audit` was written by `Marcus Robb <marcus.robb@initworx.com>`_.


.. _`setuptools`: http://pypi.python.org/pypi/setuptools