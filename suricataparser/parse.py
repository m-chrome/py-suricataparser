import re

from suricataparser.exceptions import RuleParseException
from suricataparser.rule import Rule, Option, Metadata


rule_pattern = re.compile(r"^(?P<enabled>#)*[\s#]*"
                          r"(?P<raw>"
                          r"(?P<header>[^()]+)"
                          r"\((?P<options>.*)\)"
                          r"$)")


def parse_metadata(buffer):
    if not buffer:
        # Metadata never empty
        raise RuleParseException()

    items = [kv.strip() for kv in buffer.strip().split(",")]
    return Metadata(items)


def parse_options(buffer):
    buffer = buffer.strip()
    if buffer[-1] != ";":
        raise RuleParseException()

    parts = buffer.split(";")
    parts = parts[:-1]
    options = []
    option = ""
    for part in parts:
        option += part
        if part[-1] == "\\":
            option += ";"
            continue

        if option.find(":") > -1:
            name, value = [x.strip() for x in option.split(":", 1)]
        else:
            name = option.strip()
            value = None

        if name == Option.METADATA:
            value = parse_metadata(value)
        options.append(Option(name=name, value=value))
        option = ""

    return options


def parse_rule(buffer):
    buffer = buffer.strip()
    m = rule_pattern.match(buffer)
    if not m:
        return

    if m.group("enabled") == "#":
        enabled = False
    else:
        enabled = True

    header = m.group("header").strip()
    action, header = header.split(" ", maxsplit=1)
    if action not in ("alert", "drop", "pass", "reject"):
        return

    raw = m.group("raw").strip()
    options = m.group("options").strip()
    options = parse_options(options)
    return Rule(enabled=enabled, action=action, header=header.strip(), options=options, raw=raw)


def parse_file(path):
    rules = []
    with open(path) as rules_file:
        buffer = ""
        for line in rules_file:
            if line.rstrip().endswith("\\"):
                buffer += line.strip()[:-1]
                continue
            rule = parse_rule(buffer + line)
            if rule:
                rules.append(rule)
            buffer = ""
    return rules
