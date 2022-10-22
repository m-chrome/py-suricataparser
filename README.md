# suricataparser

[![pypi-version](https://badge.fury.io/py/suricataparser.svg)](https://pypi.org/project/suricataparser)
[![py-versions](https://img.shields.io/pypi/pyversions/suricataparser.svg)](https://pypi.org/project/suricataparser)
[![license](https://img.shields.io/pypi/l/suricataparser.svg)](https://github.com/m-chrome/py-suricataparser/blob/master/LICENSE)
[![CI](https://github.com/m-chrome/py-suricataparser/actions/workflows/tests.yml/badge.svg)](https://github.com/m-chrome/py-suricataparser/actions)

Pure python package for parsing and generating Snort/Suricata rules.

## Installation

via pip:

```shell
pip install suricataparser
```

via Poetry:

```shell
poetry add suricataparser
```

## Project status

Suricataparser completed, api is stable and frozen. If you found a bug, 
create an [issue](https://github.com/m-chrome/py-suricataparser/issues/new).

## Usage examples

Parse file with rules:

```python
from suricataparser import parse_file

rules = parse_file("suricata.rules")
```

Parse raw rule:

```python
from suricataparser import parse_rule

rule = parse_rule('alert tcp any any -> any any (sid:1; gid:1;)')
```

Parse string with many rules:

```python
from suricataparser import parse_rules

rules_object = "..."
rules = parse_rules(rules_object)
```

View rule properties:

```
>>> rule.sid
1

>>> rule.action
alert

>>> rule.header
tcp any any -> any any

>>> rule.msg
'"Msg"'
```

Turn on/off rule:

```
>>> rule.enabled
True

>>> rule.enabled = False
>>> print(rule)
# alert tcp any any -> any any (msg:"Msg"; sid:1; gid:1;)
```

Modify options:

```
>>> rule.add_option("http_uri")
>>> rule.add_option("key", "value")
>>> print(rule)
alert tcp any any -> any any (msg: "Msg"; sid: 1; gid: 1; http_uri; key: value;)

>>> rule.pop_option("key")
>>> print(rule)
alert tcp any any -> any any (msg: "Msg"; sid: 1; gid: 1; http_uri;)
```
