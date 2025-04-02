from typing import Union
from collections import namedtuple

Cmd = namedtuple('Cmd', ['name', 'valid_states', 'exec'])
Response = namedtuple('Response', ['result', 'lines'])
StrOrBytes = Union[str, bytes]
