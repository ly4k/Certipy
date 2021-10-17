# Certipy - Active Directory certificate abuse
#
# Description:
#   Various general structures
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#

import enum

from certipy.formatting import to_pascal_case


class IntFlag(enum.IntFlag):
    def to_list(self):
        cls = self.__class__
        members, _ = enum._decompose(cls, self._value_)
        return members

    def to_str_list(self):
        return list(map(lambda x: str(x), self.to_list()))

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (to_pascal_case(self._name_))
        members, _ = enum._decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [to_pascal_case(str(m._name_ or m._value_)) for m in members]
                ),
            )

    def __repr__(self):
        return str(self)


class Flag(enum.Flag):
    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (to_pascal_case(self._name_))
        members, _ = enum._decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [to_pascal_case(str(m._name_ or m._value_)) for m in members]
                ),
            )
