from dataclasses import dataclass
import re

FOLDER_ITEM_REGEXP = re.compile(r'\((?P<flags>[\S ]*?)\) (?P<delim>[\S]+) (?P<name>.+)')

@dataclass
class Folder:
    """
    Mailbox folder info
        name: str - folder name
        delim: str - delimiter, a character used to delimit levels of hierarchy in a mailbox name
        flags: (str,) - folder flags
    A 'NIL' delimiter means that no hierarchy exists, the name is a "flat" name.
    """
    name: str
    delim: str
    flags: tuple[str, ...]
