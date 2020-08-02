suricataparser |build-status|
====================================
Pure python parser for Snort/Suricata rules.

Install
---------
Requires Python >= 3.6.

    pip install suricataparser

Usage
---------
::

    >>> from suricataparser import parse_rule, parse_file

Parse rules file:
::

    >>> rules = parse_file("suricata.rules")

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
