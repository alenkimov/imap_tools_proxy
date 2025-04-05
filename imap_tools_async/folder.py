class FolderInfo:
    """
    Mailbox folder info
        name: str - folder name
        delim: str - delimiter, a character used to delimit levels of hierarchy in a mailbox name
        flags: (str,) - folder flags
    A 'NIL' delimiter means that no hierarchy exists, the name is a "flat" name.
    """
    __slots__ = 'name', 'delim', 'flags'

    def __init__(self, name: str, delim: str, flags: tuple[str, ...]):
        self.name = name
        self.delim = delim
        self.flags = flags

    def __repr__(self):
        return f"{self.__class__.__name__}(name={repr(self.name)}, delim={repr(self.delim)}, flags={repr(self.flags)})"

    def __eq__(self, other):
        return all(getattr(self, i) == getattr(other, i) for i in self.__slots__)
