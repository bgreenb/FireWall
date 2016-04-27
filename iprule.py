
class Match(object):
    def __init__(self, name, rule=None):
        self.name = name
        self.rule = rule

    def __getattr__(self, name):
        try:
            return super(Match, self).__getattribute__(name)
        except KeyError:
            raise AttributeError

    def __setattr__(self, key, value):
        key = key.replace("-", "_")
        super(Match, self).__setattr__(key, value)

class Rule(object):
    """ Rules are entries in chains
    """

    def __init__(self, chain=None):
        self.chain = chain
        self._matches = []
        self._target = None
        self._proto = None
        self._src = None
        self._dst = None

    def create_match(self, name):
        match = Match(name)
        self.add_match(match)
        return match

    def add_match(self, match):
        match.rule = self
        self._matches.append(match)

    def remove_match(self, match):
        self._matches.remove(match)

    def _get_target(self):
        return self._target

    def _set_target(self, target):
        self._target = target
    target = property(_get_target, _set_target)

    def _get_proto(self):
        return self._proto

    def _set_proto(self, protocol):
        self._proto = protocol
    protocol = property(_get_proto, _set_proto)

    def get_src(self):
        return self._src

    def set_src(self, src):
        self._src = src
    src = property(get_src, set_src)

    def get_dst(self):
        return self._dst

    def set_dst(self, dst):
        self._dst = dst
    dst = property(get_dst, set_dst)



class Chain(object):

    _cache = dict()
    def __new__(cls, table, name):
        obj = Chain._cache.get(table.name + "." + name, None)
        if not obj:
            obj = object.__new__(cls)
            obj.__init__(table, name)
            Chain._cache[table.name + "." + name] = obj
            obj._rules = []
        return obj

    def __init__(self, table, name):
        self.name = name
        self.table = table
        table.add_chain(self)
        #self._rules = []

    def append_rule(self, rule):
        self._rules.append(rule)
        rule.chain = self

    def insert_rule(self, rule, position=0):
        self._rules.insert(position, rule)
        rule.chain = self

    def replace_rule(self, rule, position=0):
        self._rules[position] = rule
        rule.chain = self

    def get_rule(self, position=0):
        return self._rules[position]

    def delete_rule(self, position=-1):
        if position < 0:
            print "wrong position"
            return
        del self._rules[position]

class Table(object):

    FILTER = "filter"
    """This is the constant for the filter table."""
    MANGLE = "mangle"
    """This is the constant for the mangle table."""
    RAW = "raw"
    """This is the constant for the raw table."""
    NAT = "nat"
    """This is the constant for the nat table."""
    ALL = ["filter", "mangle", "raw", "nat"]

    _cache = dict()

    def __new__(cls, name):
        obj = Table._cache.get(name, None)
        if not obj:
            obj = object.__new__(cls)
            obj.__init__(name)
            Table._cache[name] = obj
            obj.chains = dict()
        return obj

    def __init__(self, name):
        self.name = name
        #self.chains = dict()

    def add_chain(self, chain):
        if chain.name not in self.chains:
            self.chains[chain.name] = chain
        #else :
        #    raise ValueError("chain already exist")

    def get_chain(self, chain_name):
        return self.chains[chain_name]

    def delete_chain(self, chain):
        if chain.name not in self.chians:
            raise ValueError("nothing to delete")
        else:
            del self.chains[chain.name]
