import os
import tempfile

import pytest

from suricataparser import parse_rule, parse_file
from suricataparser.exceptions import RuleParseException


def test_parse_rule():
    rule = 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS ' \
           '(msg:"ET CURRENT_EVENTS Request to .in FakeAV Campaign June ' \
           '19 2012 exe or zip"; flow:established,to_server; content:"setup."; ' \
           'fast_pattern:only; http_uri; content:".in|0d 0a|"; flowbits:isset,somebit; ' \
           'flowbits:unset,otherbit; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?' \
           'setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; ' \
           'reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; ' \
           'classtype:trojan-activity; sid: 2014929; rev: 1;)'
    parsed_rule = parse_rule(rule)
    assert parsed_rule.enabled is True
    assert parsed_rule.action == "alert"
    assert parsed_rule.header == "tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS"
    assert parsed_rule.sid == 2014929
    assert parsed_rule.rev == 1
    assert parsed_rule.msg == '"ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip"'
    assert len(parsed_rule.options) == 16


def test_parse_disabled_rule():
    rule = '# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)'
    parsed_rule = parse_rule(rule)
    assert parsed_rule.enabled is False


def test_parse_double_commented_rule():
    rule = '## alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)'
    parsed_rule = parse_rule(rule)
    assert parsed_rule.enabled is False
    assert parsed_rule.raw == 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)'


def test_parse_commented_and_space_rule():
    rule = '## #alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Text";)'
    parsed_rule = parse_rule(rule)
    assert parsed_rule.enabled is False
    assert parsed_rule.raw == 'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Text";)'


def test_parse_rule_with_list():
    rule = 'alert http any any -> [1.1.1.1, 1.1.1.2] any (sid:1; rev:1; http_uri;)'
    parsed_rule = parse_rule(rule)
    assert parsed_rule
    assert parsed_rule.enabled
    assert parsed_rule.action == "alert"
    assert parsed_rule.header == "http any any -> [1.1.1.1, 1.1.1.2] any"


def test_parse_rule_with_broken_options():
    rule = 'alert tcp any any -> any any (sid:1)'
    with pytest.raises(RuleParseException):
        parse_rule(rule)


def test_parse_rule_with_wrong_action():
    rule = parse_rule('dig tcp any any - any any (sid:1;)')
    assert rule is None


def test_parse_something():
    rule = parse_rule('# This is suricata rule')
    assert rule is None


def test_parse_rule_with_two_metadata():
    rule = parse_rule('alert tcp any any -> any any (msg:"Message"; metadata: former_category TROJAN; '
                      'sid:1; rev:1; metadata: malware_family Crypton, malware_family Nemesis;)')
    metadata_opts = [opt for opt in rule.options if opt.name == "metadata"]
    assert len(metadata_opts) == 2


def test_parse_rule_with_colon_in_options():
    rule = parse_rule('alert tcp any any -> any any (msg:"Message: text";)')
    assert rule
    assert rule.msg == '"Message: text"'


def test_parse_rule_with_semicolon_in_msg():
    rule = parse_rule('alert tcp any any -> any any (msg:"Message\\;text";)')
    assert rule.msg == '"Message\\;text"'


def test_parse_file():
    with tempfile.NamedTemporaryFile(delete=False) as rules_file:
        rules_file.write("{rule}\n".format(rule='alert tcp any any -> any any (sid:1;)').encode())
        rules_path = rules_file.name
    rules = parse_file(rules_path)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.enabled is True
    assert rule.action == "alert"
    assert rule.sid == 1
    os.remove(rules_path)


def test_parse_multiline_rule():
    with tempfile.NamedTemporaryFile(delete=False) as rules_file:
        rules_file.write('''alert tcp any any -> any any (msg:"Msg"; \\
        sid:1;)'''.encode())
        rules_path = rules_file.name
    rules = parse_file(rules_path)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.enabled is True
    assert rule.action == "alert"
    assert rule.sid == 1
    os.remove(rules_path)


def test_parse_rule_with_empty_metadata():
    with pytest.raises(RuleParseException):
        parse_rule('alert tcp any any -> any any (sid:1; metadata;)')
