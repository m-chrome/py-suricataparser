from typing import Any, Optional, List


class Option:
    CLASSTYPE = "classtype"
    GID = "gid"
    METADATA = "metadata"
    MSG = "msg"
    REV = "rev"
    SID = "sid"

    def __init__(self, name: str, value: Optional[Any] = None):
        self.name: str = name
        self.value: Optional[str, 'Metadata'] = value

    def __eq__(self, other: 'Option') -> bool:
        return self.name == other.name and self.value == other.value

    def __str__(self) -> str:
        if not self.value:
            return "{name};".format(name=self.name)
        return "{name}:{value};".format(name=self.name, value=self.value)


class Metadata:
    def __init__(self, data: list):
        self.data = data

    def __str__(self) -> str:
        return ", ".join(self.data)

    def add_meta(self, name: str, value: str) -> list:
        self.data.append("{name} {value}".format(name=name, value=value))
        return self.data

    def pop_meta(self, name: str) -> list:
        meta_items = []
        metadata = []
        for meta in self.data:
            if meta.startswith(name):
                meta_items.append(meta)
            else:
                metadata.append(meta)
        self.data = metadata
        return meta_items


class Rule:
    def __init__(self, enabled: bool, action: str, header: str,
                 options: List[Option], raw: Optional[str] = None):
        self.enabled = enabled
        self._action = action
        self._header = header
        self._protocol = None
        self._source = None
        self._source_ports = None
        self._direction = None
        self._destination = None
        self._destination_ports = None
        self._options = options
        self._sid = None
        self._gid = None
        self._msg = None
        self._rev = None
        self._classtype = None
        self._metadata = []
        self._raw = raw
        if raw:
            self.build_options()
            self.build_header()
        else:
            self.build_rule()

    def __str__(self) -> str:
        return "{enabled}{rule}".format(enabled="" if self.enabled else "# ",
                                        rule=self.raw)

    @property
    def action(self) -> str:
        return self._action

    @property
    def classtype(self) -> str:
        return self._classtype

    @property
    def header(self) -> str:
        return self._header
    
    @property
    def protocol(self) -> str:
        return self._protocol

    @property
    def source(self) -> str:
        return self._source

    @property
    def source_ports(self) -> str:
        return self._source_ports

    @property
    def direction(self) -> str:
        return self._direction

    @property 
    def destination(self) -> str:
        return self._destination

    @property
    def destination_ports(self) -> str:
        return self._destination_ports

    @property
    def metadata(self) -> list:
        return self._metadata

    @property
    def msg(self) -> str:
        return self._msg

    @property
    def options(self) -> List[Option]:
        return self._options

    @property
    def raw(self) -> str:
        return self._raw

    @property
    def rev(self) -> Optional[int]:
        return self._rev

    @property
    def sid(self) -> Optional[int]:
        return self._sid

    def build_header(self):
        headers = self._header.split()
        self._protocol = headers[0]
        self._source = headers[1]
        self._source_ports = headers[2]
        self._direction = headers[3]
        self._destination = headers[4]
        self._destination_ports = headers[5]

    def build_options(self):
        self._metadata = []
        for option in self._options:
            if option.name == Option.MSG:
                self._msg = option.value.strip('"')
            elif option.name == Option.SID:
                self._sid = int(option.value)
            elif option.name == Option.GID:
                self._gid = int(option.value)
            elif option.name == Option.REV:
                self._rev = int(option.value)
            elif option.name == Option.CLASSTYPE:
                self._classtype = option.value
            elif option.name == Option.METADATA:
                self._metadata.extend(option.value.data)

    def build_rule(self) -> str:
        self._raw = self._action + " " + self._header + " "
        self._raw += "({options})".format(options=" ".join([str(opt) for opt in self._options]))
        self.build_options()
        self.build_header()
        return self._raw

    def add_option(self, name: str, value: Optional[str] = None, index: Optional[int] = None):
        option = Option(name=name, value=value)
        if index is None:
            self._options.append(option)
        else:
            self._options.insert(index, option)
        self.build_rule()

    def pop_option(self, name: str):
        chosen_options = []
        options = []
        for opt in self._options:
            if opt.name != name:
                options.append(opt)
            else:
                chosen_options.append(opt)
        self._options = options
        self.build_rule()
        return chosen_options

    def get_option(self, name: str) -> List[Option]:
        return [option for option in self.options if option.name == name]

    def to_dict(self) -> dict:
        options = []
        for option in self.options:
            if option.name != Option.METADATA:
                options.append({"name": option.name, "value": option.value})
            else:
                options.append({"name": option.name, "value": option.value.data})

        return {
            "enabled": self.enabled, "action": self.action,
            "header": self.header, "options": options
        }
