from typing import Union
from collections import namedtuple
from collections import UserString

Cmd = namedtuple('Cmd', ['name', 'valid_states', 'is_async'])
Response = namedtuple('Response', ['result', 'lines'])
StrOrBytes = Union[str, bytes]
Criteria = Union[StrOrBytes, UserString]
