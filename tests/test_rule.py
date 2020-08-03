from suricataparser import parse_rule, Rule
from suricataparser.rule import Option, Metadata


def test_turn_off_rule():
    rule = parse_rule('alert tcp any any -> any any (sid: 1;)')
    assert rule.enabled
    rule.enabled = False
    assert not rule.enabled


def test_rule_repr():
    rule = parse_rule('alert http any any -> any any (sid: 1; http_uri;)')
    rule.enabled = False
    assert str(rule) == '# alert http any any -> any any (sid: 1; http_uri;)'


def test_build_rule():
    rule = Rule(enabled=True, action="alert", header="http any any -> any any",
                options=[Option(name="sid", value="1"),
                         Option(name="http_uri"),
                         Option(name="metadata", value=Metadata(data=["key value"]))])
    assert str(rule) == 'alert http any any -> any any (sid: 1; http_uri; metadata: key value;)'
    assert rule.metadata == ['key value']


def test_pop_option():
    rule = parse_rule('drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg:”ET TROJAN Likely Bot Nick '
                      'in IRC (USA +..)”; flow:established,to_server; flowbits:isset,is_proto_irc; '
                      'content:”NICK “; pcre:”/NICK .*USA.*[0-9]{3,}/i”; reference:url,doc.emerging'
                      'threats.net/2008124; classtype:trojan-activity; sid:2008124; rev:2; gid:1;)')
    assert rule
    rule.pop_option("pcre")
    assert len(rule.options) == 9
    assert str(rule) == 'drop tcp $HOME_NET any -> $EXTERNAL_NET any (msg: ”ET TROJAN Likely Bot Nick ' \
                        'in IRC (USA +..)”; flow: established,to_server; flowbits: isset,is_proto_irc; ' \
                        'content: ”NICK “; reference: url,doc.emergingthreats.net/2008124; ' \
                        'classtype: trojan-activity; sid: 2008124; rev: 2; gid: 1;)'


def test_add_option():
    rule = parse_rule('alert http any any -> any any (msg:"Message";sid:1;)')
    rule.add_option("http_uri")
    assert str(rule) == 'alert http any any -> any any (msg: "Message"; sid: 1; http_uri;)'
    assert rule.options[2] == Option("http_uri")


def test_add_option_with_index():
    rule = parse_rule('alert http any any -> any any (msg:"Message";sid:1;)')
    rule.add_option("http_uri", index=1)
    assert str(rule) == 'alert http any any -> any any (msg: "Message"; http_uri; sid: 1;)'
    assert rule.options[1] == Option("http_uri")


def test_metadata_repr():
    metadata = Metadata(["key value", "key value"])
    assert str(metadata) == "key value, key value"


def test_add_meta():
    metadata = Metadata(["key value", "key value"])
    metadata.add_meta("key", "value")
    assert metadata.data == ["key value", "key value", "key value"]


def test_pop_meta():
    metadata = Metadata(["key value", "key1 value"])
    metas = metadata.pop_meta("key1")
    assert metadata.data == ["key value"]
    assert metas == ["key1 value"]


def test_change_classtype():
    rule = parse_rule('alert tcp any any -> any any (msg: "Message"; classtype: trojan-activity; '
                      'metadata: k v;)')
    assert rule.classtype == 'trojan-activity'
    rule.pop_option("classtype")
    rule.add_option("classtype", "backdoor")
    assert rule.classtype == "backdoor"
