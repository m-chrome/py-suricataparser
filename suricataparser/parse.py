import re
from pathlib import Path
from typing import Optional, Union, List

from suricataparser.exceptions import RuleParseException
from suricataparser.rule import Rule, Option, Metadata


rule_pattern = re.compile(r"^(?P<enabled>#)*[\s#]*"
                          r"(?P<raw>"
                          r"(?P<header>[^()]+)"
                          r"\((?P<options>.*)\)"
                          r"$)")


def parse_metadata(buffer: str) -> Metadata:
    if not buffer:
        # Metadata never empty
        raise RuleParseException()

    items = [kv.strip() for kv in buffer.strip().split(",")]
    return Metadata(items)


def parse_options(buffer: str) -> List[Option]:
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

def parse_rule(buffer: str) -> Optional[Rule]:
    buffer = buffer.strip()
    m = rule_pattern.match(buffer)
    if not m:
        return

    if m.group("enabled") == "#":
        enabled = False
    else:
        enabled = True

    header = m.group("header")
    if not header:
        return

    header_parts = header.strip().split(" ", maxsplit=1)
    if len(header_parts) != 2:
        return
    
    action, header = header_parts
    if action not in ("alert", "drop", "pass", "reject"):
        return

    raw = m.group("raw").strip()
    options = m.group("options").strip()
    options = parse_options(options)
    return Rule(enabled=enabled, action=action, header=header.strip(), options=options, raw=raw)


def parse_file(path: Union[str, Path]) -> List[Rule]:
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


def parse_rules(rules_object: str) -> List[Rule]:
    rules = []
    buffer = ""
    for line in rules_object.splitlines():
        if line.rstrip().endswith("\\"):
            buffer += line.strip()[:-1]
            continue
        rule = parse_rule(buffer + line)
        if rule:
            rules.append(rule)
        buffer = ""
    return rules
