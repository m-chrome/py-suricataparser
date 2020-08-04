class Option:
    CLASSTYPE = "classtype"
    GID = "gid"
    METADATA = "metadata"
    MSG = "msg"
    REV = "rev"
    SID = "sid"

    def __init__(self, name, value=None):
        self.name = name
        self.value = value

    def __eq__(self, other):
        return self.name == other.name and self.value == other.value

    def __str__(self):
        if not self.value:
            return "{name};".format(name=self.name)
        return "{name}: {value};".format(name=self.name, value=self.value)


class Metadata:
    def __init__(self, data):
        self.data = data

    def __str__(self):
        return ", ".join(self.data)

    def add_meta(self, name, value):
        self.data.append("{name} {value}".format(name=name, value=value))
        return self.data

    def pop_meta(self, name):
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
    def __init__(self, enabled, action, header, options, raw=None):
        self.enabled = enabled
        self._action = action
        self._header = header
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
        else:
            self.build_rule()

    def __str__(self):
        return "{enabled}{rule}".format(enabled="" if self.enabled else "# ",
                                        rule=self.raw)

    @property
    def action(self):
        return self._action

    @property
    def classtype(self):
        return self._classtype

    @property
    def header(self):
        return self._header

    @property
    def metadata(self):
        return self._metadata

    @property
    def msg(self):
        return self._msg

    @property
    def options(self):
        return self._options

    @property
    def raw(self):
        return self._raw

    @property
    def rev(self):
        return self._rev

    @property
    def sid(self):
        return self._sid

    def build_options(self):
        self._metadata = []
        for option in self._options:
            if option.name == Option.MSG:
                self._msg = option.value
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

    def build_rule(self):
        self._raw = self._action + " " + self._header + " "
        self._raw += "({options})".format(options=" ".join([str(opt) for opt in self._options]))
        self.build_options()
        return self._raw

    def add_option(self, name, value=None, index=None):
        option = Option(name=name, value=value)
        if index is None:
            self._options.append(option)
        else:
            self._options.insert(index, option)
        self.build_rule()

    def pop_option(self, name):
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
