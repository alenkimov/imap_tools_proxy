import asyncio
import re
from copy import copy

from .types import Cmd, Response

from .consts import STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT

from .errors import CommandTimeout
from .errors import UnexpectedCommandStatusError


Commands = {
    'APPEND':       Cmd('APPEND',       (AUTH, SELECTED),           False),
    'AUTHENTICATE': Cmd('AUTHENTICATE', (NONAUTH,),                 False),
    'CAPABILITY':   Cmd('CAPABILITY',   (NONAUTH, AUTH, SELECTED),  True),
    'CHECK':        Cmd('CHECK',        (SELECTED,),                True),
    'CLOSE':        Cmd('CLOSE',        (SELECTED,),                False),
    'COMPRESS':     Cmd('COMPRESS',     (AUTH,),                    False),
    'COPY':         Cmd('COPY',         (SELECTED,),                True),
    'CREATE':       Cmd('CREATE',       (AUTH, SELECTED),           True),
    'DELETE':       Cmd('DELETE',       (AUTH, SELECTED),           True),
    'DELETEACL':    Cmd('DELETEACL',    (AUTH, SELECTED),           True),
    'ENABLE':       Cmd('ENABLE',       (AUTH,),                    False),
    'EXAMINE':      Cmd('EXAMINE',      (AUTH, SELECTED),           False),
    'EXPUNGE':      Cmd('EXPUNGE',      (SELECTED,),                True),
    'FETCH':        Cmd('FETCH',        (SELECTED,),                True),
    'GETACL':       Cmd('GETACL',       (AUTH, SELECTED),           True),
    'GETQUOTA':     Cmd('GETQUOTA',     (AUTH, SELECTED),           True),
    'GETQUOTAROOT': Cmd('GETQUOTAROOT', (AUTH, SELECTED),           True),
    'ID':           Cmd('ID',           (NONAUTH, AUTH, LOGOUT, SELECTED), True),
    'IDLE':         Cmd('IDLE',         (SELECTED,),                False),
    'LIST':         Cmd('LIST',         (AUTH, SELECTED),           True),
    'LOGIN':        Cmd('LOGIN',        (NONAUTH,),                 False),
    'LOGOUT':       Cmd('LOGOUT',       (NONAUTH, AUTH, LOGOUT, SELECTED), False),
    'LSUB':         Cmd('LSUB',         (AUTH, SELECTED),           True),
    'MYRIGHTS':     Cmd('MYRIGHTS',     (AUTH, SELECTED),           True),
    'MOVE':         Cmd('MOVE',         (SELECTED,),                False),
    'NAMESPACE':    Cmd('NAMESPACE',    (AUTH, SELECTED),           True),
    'NOOP':         Cmd('NOOP',         (NONAUTH, AUTH, SELECTED),  True),
    'RENAME':       Cmd('RENAME',       (AUTH, SELECTED),           True),
    'SEARCH':       Cmd('SEARCH',       (SELECTED,),                True),
    'SELECT':       Cmd('SELECT',       (AUTH, SELECTED),           False),
    'SETACL':       Cmd('SETACL',       (AUTH, SELECTED),           False),
    'SETQUOTA':     Cmd('SETQUOTA',     (AUTH, SELECTED),           False),
    'SORT':         Cmd('SORT',         (SELECTED,),                True),
    'STARTTLS':     Cmd('STARTTLS',     (NONAUTH,),                 False),
    'STATUS':       Cmd('STATUS',       (AUTH, SELECTED),           True),
    'STORE':        Cmd('STORE',        (SELECTED,),                True),
    'SUBSCRIBE':    Cmd('SUBSCRIBE',    (AUTH, SELECTED),           False),
    'THREAD':       Cmd('THREAD',       (SELECTED,),                True),
    'UID':          Cmd('UID',          (SELECTED,),                True),
    'UNSUBSCRIBE':  Cmd('UNSUBSCRIBE',  (AUTH, SELECTED),           False),
    # for testing
    'DELAY':        Cmd('DELAY',        (AUTH, SELECTED),           False),
}


class Command:
    def __init__(
        self,
        name: str,
        tag: str,
        *args,
        prefix: str = None,
        untagged_resp_name: str = None,
        loop: asyncio.AbstractEventLoop = None,
        timeout: float = None,
        expected_response_status: str = 'OK',
    ) -> None:
        self.name = name
        self.tag = tag
        self.args = args
        self.prefix = prefix + ' ' if prefix else None
        self.untagged_resp_name = untagged_resp_name or name
        self.expected_response_status = expected_response_status

        self._exception = None
        self._loop = loop if loop is not None else asyncio.get_running_loop()
        self._event = asyncio.Event()
        self._timeout = timeout
        self._timer = asyncio.Handle(lambda: None, None, self._loop)  # fake timer
        self._set_timer()
        self._expected_size = 0

        self._resp_literal_data = bytearray()
        self._resp_result = 'Init'
        self._resp_lines: list[bytes] = list()

    def __repr__(self) -> str:
        return '{tag} {prefix}{name}{space}{args}'.format(
            tag=self.tag, prefix=self.prefix or '', name=self.name,
            space=' ' if self.args else '', args=' '.join(str(arg) if arg is not None else '' \
                                                          for arg in self.args))

    # def __repr__(self) -> str:
    #     representation = f"{self.tag} {self.prefix or ''} {self.name}"
    #     if self.args:
    #         representation += " "
    #         representation += " ".join(str(arg) for arg in self.args if arg is not None)
    #     return representation

    # for tests
    def __eq__(self, other):
        return other is not None and other.tag == self.tag and other.name == self.name and other.args == self.args

    @property
    def response(self) -> Response:
        return Response(self._resp_result, self._resp_lines)

    def close(self, line: bytes, result: str) -> None:
        self.append_to_resp(line, result=result)
        self._timer.cancel()
        self._event.set()

    def begin_literal_data(self, expected_size: int, literal_data: bytes = b'') -> bytes:
        self._expected_size = expected_size
        return self.append_literal_data(literal_data)

    def wait_literal_data(self) -> bool:
        return self._expected_size != 0 and len(self._resp_literal_data) != self._expected_size

    def wait_data(self) -> bool:
        return self.wait_literal_data()

    def append_literal_data(self, data: bytes) -> bytes:
        nb_bytes_to_add = self._expected_size - len(self._resp_literal_data)
        self._resp_literal_data.extend(data[0:nb_bytes_to_add])
        if not self.wait_literal_data():
            self.append_to_resp(self._resp_literal_data)
            self._end_literal_data()
        self._reset_timer()
        return data[nb_bytes_to_add:]

    def append_to_resp(self, line: bytes, result: str = 'Pending') -> None:
        self._resp_result = result
        self._resp_lines.append(line)
        self._reset_timer()

    async def wait(self) -> None:
        await self._event.wait()
        if self._exception is not None:
            raise self._exception

    def flush(self) -> None:
        pass

    def _end_literal_data(self) -> None:
        self._expected_size = 0
        self._resp_literal_data = bytearray()

    def _set_timer(self) -> None:
        if self._timeout is not None:
            self._timer = self._loop.call_later(self._timeout, self._timeout_callback)

    def _timeout_callback(self) -> None:
        self._exception = CommandTimeout(self)
        self.close(str(self._exception).encode(), 'KO')

    def _reset_timer(self) -> None:
        self._timer.cancel()
        self._set_timer()

    @property
    def is_async(self) -> bool:
        return Commands[self.name].is_async

    def raise_on_unexpected_response_status(self):
        if self.response.result != self.expected_response_status:
            raise UnexpectedCommandStatusError(self)


class FetchCommand(Command):
    FETCH_MESSAGE_DATA_RE = re.compile(rb'[0-9]+ FETCH \(')

    def __init__(
        self,
        tag: str,
        *args,
        prefix: str = None,
        untagged_resp_name: str = None,
        loop: asyncio.AbstractEventLoop = None,
        timeout: float = None,
    ) -> None:
        super().__init__(
            'FETCH',
            tag,
            *args,
            prefix=prefix,
            untagged_resp_name=untagged_resp_name,
            loop=loop,
            timeout=timeout,
        )

    def wait_data(self) -> bool:
        last_fetch_index = 0
        for index, line in enumerate(self._resp_lines):
            if isinstance(line, bytes) and self.FETCH_MESSAGE_DATA_RE.match(line):
                last_fetch_index = index
        return not matched_parenthesis(b''.join(filter(lambda l: isinstance(l, bytes),
                                                      self.response.lines[last_fetch_index:])))


def matched_parenthesis(fetch_response: bytes) -> bool:
    return fetch_response.count(b'(') == fetch_response.count(b')')


class IdleCommand(Command):
    def __init__(
        self,
        tag: str,
        queue: asyncio.Queue,
        *args,
        prefix: str = None,
        untagged_resp_name: str = None,
        loop: asyncio.AbstractEventLoop = None,
        timeout: float = None,
    ) -> None:
        super().__init__(
            'IDLE',
            tag,
            *args,
            prefix=prefix,
            untagged_resp_name=untagged_resp_name,
            loop=loop,
            timeout=timeout,
        )
        self.queue = queue
        self.buffer: list[bytes] = list()

    def append_to_resp(self, line: bytes, result: str = 'Pending') -> None:
        if result != 'Pending':
            super().append_to_resp(line, result)
        else:
            self.buffer.append(line)

    def flush(self) -> None:
        if self.buffer:
            self.queue.put_nowait(copy(self.buffer))
            self.buffer.clear()
