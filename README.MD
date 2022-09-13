# Purpose
This python script performs checks using netapp ontap rest api's.  On a fail it can trigger an snmp trap and/or mail message.

# Config file
The config file has 4 parts

* clusters : a list of clusters with connection details and description
* checks : a list of checks using ontap api.  Using jq queries you can filter and format.  It finds a value in the json and matches (or negative match) with a predefined value.  Every check can have its own snmp trap settings.  Currently it has 2 sample traps to check metrocluster isl's and bgp interfaces.  The trap 1.3.6.1.4.1.789.0.13 is an ontap critical alert (netapp oid).  The object 1.3.6.1.2.1.2.2.1 is a network interface (generic oid)
* snmp : the snmp server
* smtp : the mail server

# Usage

```
python3 checker.py config.yml
```

# How to install

Example on centos 7.  Most of the libraries are simple to install.  Only the jq requires some dev and compiling libraries to succesfully install.

```
yum -y install epel-release
yum install -y autoconf libtool gcc pkgconfig python-devel python36-devel
python3 -m pip install --upgrade pip
pip install --upgrade pip setuptools wheel
pip install jq pyjq pysnmp requests pyyaml
```