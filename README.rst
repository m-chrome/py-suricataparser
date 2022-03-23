suricataparser |build-status| |py-versions| |pypi-version| |license|
======================================================================
Pure python package for parsing and generating Snort/Suricata rules.

Install
---------
Requires Python >= 3.6.

    pip install suricataparser

Usage
---------
::

    >>> from suricataparser import parse_rule, parse_file, parse_rules

Parse rules file:
::

    >>> rules = parse_file("suricata.rules")

Parse rules object (for embedding into scripts):
::

    >>> rules = parse_rules(rules_object)

Parse raw rule:
::

    >>> rule = parse_rule('alert tcp any any -> any any (sid:1; gid:1;)')
    >>> print(rule)
    alert tcp any any -> any any (msg:"Msg"; sid:1; gid:1;)

View rule properties:
::

    >>> rule.sid
    1

    >>> rule.action
    alert

    >>> rule.header
    tcp any any -> any any

    >>> rule.msg
    '"Msg"'

Turn on/off rule:
::

    >>> rule.enabled
    True

    >>> rule.enabled = False
    >>> print(rule)
    # alert tcp any any -> any any (msg:"Msg"; sid:1; gid:1;)

Modify options:
::

    >>> rule.add_option("http_uri")
    >>> rule.add_option("key", "value")
    >>> print(rule)
    alert tcp any any -> any any (msg: "Msg"; sid: 1; gid: 1; http_uri; key: value;)

    >>> rule.pop_option("key")
    >>> print(rule)
    alert tcp any any -> any any (msg: "Msg"; sid: 1; gid: 1; http_uri;)

.. |build-status| image:: https://travis-ci.org/m-chrome/py-suricataparser.png?branch=master
   :target: https://travis-ci.org/m-chrome/py-suricataparser
.. |pypi-version| image:: https://badge.fury.io/py/suricataparser.svg
   :target: https://pypi.org/project/suricataparser
.. |license| image:: https://img.shields.io/pypi/l/suricataparser.svg
   :target: https://github.com/m-chrome/py-suricataparser/blob/master/LICENSE
.. |py-versions| image:: https://img.shields.io/pypi/pyversions/suricataparser.svg
   :target: https://pypi.org/project/suricataparser
