# -*- coding: utf-8 -*-
#    aioimaplib : an IMAPrev4 lib using python asyncio
#    Copyright (C) 2016  Bruno Thomas
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
import asyncio
from base64 import b64encode
import functools
import logging
import random
import re
import time
from asyncio import BaseTransport, Future
from datetime import datetime, timezone, timedelta
from typing import Union, Any, Coroutine, Callable, Optional, Pattern
from typing import Literal

from .types import Response
from .consts import ALLOWED_IMAP_VERSIONS
from .consts import ID_MAX_PAIRS_COUNT, ID_MAX_FIELD_LEN, ID_MAX_VALUE_LEN
from .consts import MAXLINE
from .consts import CRLF
from .consts import STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT

from .errors import Error
from .errors import Abort
from .errors import CommandTimeout
from .errors import IncompleteRead
from .errors import MaxResponseLineReachedError
from .command import Commands
from .command import Command
from .command import FetchCommand
from .command import IdleCommand


log = logging.getLogger(__name__)


# # function from imaplib: imaplib.IMAP4._quote()
def quoted(arg: str) -> str:
    """ Given a string, return a quoted string as per RFC 3501, section 9.

        Implementation copied from https://github.com/mjs/imapclient
        (imapclient/imapclient.py), 3-clause BSD license
    """
    arg = arg.replace('\\', '\\\\')
    arg = arg.replace('"', '\\"')
    return '"' + arg + '"'


def arguments_rfs2971(**kwargs: Union[dict, list, str]) -> Union[dict, list]:
    if kwargs:
        if len(kwargs) > ID_MAX_PAIRS_COUNT:
            raise ValueError('Must not send more than 30 field-value pairs')
        args = ['(']
        for field, value in kwargs.items():
            field = quoted(str(field))
            value = quoted(str(value)) if value is not None else 'NIL'
            if len(field) > ID_MAX_FIELD_LEN:
                raise ValueError(f'Field: {field} must not be longer than 30')
            if len(value) > ID_MAX_VALUE_LEN:
                raise ValueError(f'Field: {field} value: {value} must not be longer than 1024')
            args.extend((field, value))
        args.append(')')
    else:
        args = ['NIL']
    return args


def change_state(coro: Callable[..., Coroutine[Any, Any, Optional[Response]]]):
    @functools.wraps(coro)
    async def wrapper(self, *args, **kargs) -> Optional[Response]:
        async with self.state_condition:
            res = await coro(self, *args, **kargs)
            log.debug('state -> %s' % self.state)
            self.state_condition.notify_all()
            return res

    return wrapper


# function from imaplib
def int2ap(num) -> str:
    """Convert integer to A-P string representation."""
    val = ''
    ap = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += ap[mod:mod + 1]
    return val


Months = ' Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')
Mon2num = {s.encode():n+1 for n, s in enumerate(Months[1:])}


# function from imaplib
def time2internaldate(date_time: Any) -> str:
    """Convert date_time to IMAP4 INTERNALDATE representation.

    Return string in form: '"DD-Mmm-YYYY HH:MM:SS +HHMM"'.  The
    date_time argument can be a number (int or float) representing
    seconds since epoch (as returned by time.time()), a 9-tuple
    representing local time, an instance of time.struct_time (as
    returned by time.localtime()), an aware datetime instance or a
    double-quoted string.  In the last case, it is assumed to already
    be in the correct format.
    """
    if isinstance(date_time, (int, float)):
        dt = datetime.fromtimestamp(date_time, timezone.utc).astimezone()
    elif isinstance(date_time, tuple):
        try:
            gmtoff = date_time.tm_gmtoff
        except AttributeError:
            if time.daylight:
                dst = date_time[8]
                if dst == -1:
                    dst = time.localtime(time.mktime(date_time))[8]
                gmtoff = -(time.timezone, time.altzone)[dst]
            else:
                gmtoff = -time.timezone
        delta = timedelta(seconds=gmtoff)
        dt = datetime(*date_time[:6], tzinfo=timezone(delta))
    elif isinstance(date_time, datetime):
        if date_time.tzinfo is None:
            raise ValueError("date_time must be aware")
        dt = date_time
    elif isinstance(date_time, str) and (date_time[0],date_time[-1]) == ('"','"'):
        return date_time        # Assume in correct format
    else:
        raise ValueError("date_time not of a known type")
    fmt = '"%d-{}-%Y %H:%M:%S %z"'.format(Months[dt.month])
    return dt.strftime(fmt)


# cf https://tools.ietf.org/html/rfc3501#section-9
# untagged responses types
literal_data_re = re.compile(rb'.*\{(?P<size>\d+)\}$')
message_data_re = re.compile(rb'[0-9]+ ((FETCH)|(EXPUNGE))')
tagged_status_response_re = re.compile(rb'[A-Z0-9]+ ((OK)|(NO)|(BAD))')


class IMAP4ClientProtocol(asyncio.Protocol):
    def __init__(
        self,
        loop: Optional[asyncio.AbstractEventLoop],
        conn_lost_cb: Callable[[Optional[Exception]], None] = None,
    ):
        self.loop = loop
        self.transport = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = set()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.idle_queue = asyncio.Queue()
        self._idle_event = asyncio.Event()
        self.imap_version = None
        self.literal_data = None
        self.incomplete_line = b''
        self.current_command = None
        self.conn_lost_cb = conn_lost_cb
        self.tasks: set[Future] = set()

        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

    async def create_connection(self, host: str, port: int, **kwargs):
        return await self.loop.create_connection(lambda: self, host, port, **kwargs)

    def connection_made(self, transport: BaseTransport) -> None:
        self.transport = transport
        self.state = CONNECTED

    def data_received(self, d: bytes) -> None:
        log.debug(f'Received: {d}')
        try:
            self._handle_responses(self.incomplete_line + d, self._handle_line, self.current_command)
            self.incomplete_line = b''
            self.current_command = None
        except IncompleteRead as incomplete_read:
            self.current_command = incomplete_read.command
            self.incomplete_line = incomplete_read.data

    def connection_lost(self, exc: Optional[Exception]) -> None:
        log.debug(f'connection lost: {exc}')
        if self.conn_lost_cb is not None:
            self.conn_lost_cb(exc)

    def _handle_responses(self, data: bytes, line_handler: Callable[[bytes, Command], Optional[Command]], current_cmd: Command = None) -> None:
        if not data:
            if self.pending_sync_command is not None:
                self.pending_sync_command.flush()
            if current_cmd is not None and current_cmd.wait_data():
                raise IncompleteRead(current_cmd)
            return

        if len(data) > MAXLINE:
            raise MaxResponseLineReachedError(data)

        if current_cmd is not None and current_cmd.wait_literal_data():
            data = current_cmd.append_literal_data(data)
            if current_cmd.wait_literal_data():
                raise IncompleteRead(current_cmd)

        line, separator, tail = data.partition(CRLF)
        if not separator:
            raise IncompleteRead(current_cmd, data)

        cmd = line_handler(line, current_cmd)

        begin_literal = literal_data_re.match(line)
        if begin_literal:
            size = int(begin_literal.group('size'))
            if cmd is None:
                cmd = Command('NIL', 'unused')
            cmd.begin_literal_data(size)
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        elif cmd is not None and cmd.wait_data():
            self._handle_responses(tail, line_handler, current_cmd=cmd)
        else:
            self._handle_responses(tail, line_handler)

    def _handle_line(self, line: bytes, current_cmd: Command) -> Optional[Command]:
        if not line:
            return

        if self.state == CONNECTED:
            task = asyncio.ensure_future(self.welcome(line))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
        elif tagged_status_response_re.match(line):
            self._response_done(line)
        elif current_cmd is not None:
            current_cmd.append_to_resp(line)
            return current_cmd
        elif line.startswith(b'*'):
            return self._untagged_response(line)
        elif line.startswith(b'+'):
            self._continuation(line)
        else:
            log.info(f'unknown data received: {line}')

    def send(self, line: str, scrub: str = None) -> None:
        data = f'{line}\r\n'.encode()
        if scrub:
            log.debug(f'Sending: {data.replace(scrub.encode(), len(scrub) * b"*")}')
        else:
            log.debug(f'Sending: {data}')
        self.transport.write(data)

    async def execute(
        self,
        command: Command,
        scrub: str = None,
    ) -> Response:
        if self.state not in Commands.get(command.name).valid_states:
            raise Abort(f'command {command.name} illegal in state {self.state}')

        if self.pending_sync_command is not None:
            await self.pending_sync_command.wait()

        if command.is_async:
            if self.pending_async_commands.get(command.untagged_resp_name) is not None:
                await self.pending_async_commands[command.untagged_resp_name].wait()
            self.pending_async_commands[command.untagged_resp_name] = command
        else:
            if self.pending_async_commands:
                await self.wait_async_pending_commands()
            self.pending_sync_command = command

        self.send(str(command), scrub=scrub)
        try:
            await command.wait()
        except CommandTimeout:
            if command.is_async:
                self.pending_async_commands.pop(command.untagged_resp_name, None)
            else:
                self.pending_sync_command = None
            raise
        finally:
            if command.name == 'IDLE':
                self._idle_event.clear()

        command.raise_on_unexpected_response_status()

        return command.response

    @change_state
    async def welcome(self, command: bytes) -> None:
        if b'PREAUTH' in command:
            self.state = AUTH
        elif b'OK' in command:
            self.state = NONAUTH
        else:
            raise Error(command.decode())
        await self.capability()

    def command(
        self,
        name: str,
        *args,
        **kwargs,
    ) -> Command:
        return Command(
            name,
            self.new_tag(),
            *args,
            loop=self.loop,
            **kwargs,
        )

    def idle_command(
        self,
        *args,
        **kwargs,
    ) -> IdleCommand:
        return IdleCommand(
            self.new_tag(),
            self.idle_queue,
            *args,
            loop=self.loop,
            **kwargs,
        )

    def fetch_command(
        self,
        *args,
        **kwargs,
    ) -> FetchCommand:
        return FetchCommand(
            self.new_tag(),
            *args,
            loop=self.loop,
            **kwargs,
        )

    @change_state
    async def login(self, username: str, password: str) -> Response:
        command = self.command('LOGIN', username, quoted(password))
        response = await self.execute(command, scrub=password)
        self.state = AUTH
        for line in response.lines:
            if b'CAPABILITY' in line:
                self.capabilities = self.capabilities.union(set(line.decode().replace('CAPABILITY', '').strip().split()))
        return response

    # todo
    # def login_utf8(self, username: str, password: str):
    #     """Authenticate to an account with a UTF-8 username and/or password"""
    #     # rfc2595 section 6 - PLAIN SASL mechanism
    #     encoded = (b"\0" + username.encode("utf8") + b"\0" + password.encode("utf8"))
    #     # Assumption is the server supports AUTH=PLAIN capability
    #     return self.authenticate("PLAIN", lambda x: encoded)

    @change_state
    async def xoauth2(self, username: str, token: str) -> Response:
        """Authentication with XOAUTH2.

        Tested with outlook.

        Specification:
        https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
        https://developers.google.com/gmail/imap/xoauth2-protocol
        """
        sasl_string = b64encode(f"user={username}\1auth=Bearer {token}\1\1".encode("ascii"))
        command = self.command('AUTHENTICATE', 'XOAUTH2', sasl_string.decode("ascii"))
        response = await self.execute(command, scrub=token)
        self.state = AUTH
        return response

    @change_state
    async def logout(self) -> Response:
        command = self.command('LOGOUT', expected_response_status='BYE')
        response = await self.execute(command)
        self.state = LOGOUT
        return response

    @change_state
    async def select_folder(self, folder='INBOX') -> Response:
        command = self.command('SELECT', folder)
        response = await self.execute(command)
        self.state = SELECTED
        return response

    @change_state
    async def close(self) -> Response:
        command = self.command('CLOSE')
        response = await self.execute(command)
        if response.result == 'OK':
            self.state = AUTH
        return response

    async def idle(self) -> Response:
        if 'IDLE' not in self.capabilities:
            raise Abort('server has not IDLE capability')
        self._idle_event.clear()
        command = self.idle_command()
        return await self.execute(command)

    def has_pending_idle_command(self) -> bool:
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    def idle_done(self) -> None:
        self.send('DONE')

    # todo Criteria
    async def search_messages(
        self,
        *criteria,
        charset: Optional[str] = 'utf-8',
        by_uid: bool = False,
    ) -> Response:
        args = ('CHARSET', charset) + criteria if charset is not None else criteria
        prefix = 'UID' if by_uid else ''

        command = self.command('SEARCH', *args, prefix=prefix)
        return await self.execute(command)

    async def fetch(
        self,
        message_set: str,
        message_parts: str,
        by_uid: bool = False,
        timeout: float = None,
    ) -> Response:
        command = self.fetch_command(message_set, message_parts, prefix='UID' if by_uid else '', timeout=timeout)
        return await self.execute(command)

    async def store(self, *args: str, by_uid: bool = False) -> Response:
        command = self.command('STORE', *args, prefix='UID' if by_uid else '', untagged_resp_name='FETCH')
        return await self.execute(command)

    async def expunge(self, *args: str, by_uid=False) -> Response:
        command = self.command('EXPUNGE', *args, prefix='UID' if by_uid else '')
        return await self.execute(command)

    # todo Criteria
    async def uid(
        self,
        command: Literal['FETCH', 'STORE', 'COPY', 'MOVE', 'EXPUNGE'],
        *criteria: str,
        timeout: float = None,
    ) -> Response:
        if self.state not in Commands.get('UID').valid_states:
            raise Abort('command UID illegal in state %s' % self.state)

        command_upper = command.upper()

        if command_upper == 'FETCH':
            return await self.fetch(criteria[0], criteria[1], by_uid=True, timeout=timeout)
        elif command_upper == 'STORE':
            return await self.store(*criteria, by_uid=True)
        elif command_upper == 'COPY':
            return await self.copy(*criteria, by_uid=True)
        elif command_upper == 'MOVE':
            return await self.move(*criteria, by_uid=True)
        elif command_upper == 'EXPUNGE':
            if 'UIDPLUS' not in self.capabilities:
                raise Abort(f'EXPUNGE with uids is only valid with UIDPLUS capability. UIDPLUS not in ({self.capabilities})')
            return await self.expunge(*criteria, by_uid=True)
        else:
            raise Abort(f'command UID only possible with COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was {command_upper})')

    async def copy(self, *args: str, by_uid: bool = False) -> Response:
        command = self.command('COPY', *args, prefix='UID' if by_uid else '')
        return await self.execute(command)

    async def move(self, uid_set: str, mailbox: str, by_uid: bool = False) -> Response:
        if 'MOVE' not in self.capabilities:
            raise Abort('server has not MOVE capability')

        command = self.command('MOVE', uid_set, mailbox, prefix='UID' if by_uid else '')
        return await self.execute(command)

    async def capability(self) -> None:  # that should be a Response (would avoid the Optional)
        command = self.command('CAPABILITY')
        response = await self.execute(command)

        capability_list = response.lines[0].decode().split()
        self.capabilities = set(capability_list)
        try:
            self.imap_version = list(
                filter(lambda x: x.upper() in ALLOWED_IMAP_VERSIONS, capability_list)).pop().upper()
        except IndexError:
            raise Error('server not IMAP4 compliant')

    async def append(self, message_bytes: bytes, mailbox: str = 'INBOX', flags: str = None, date: Any = None, timeout: float = None) -> Response:
        args = [mailbox]
        if flags is not None:
            if (flags[0], flags[-1]) != ('(', ')'):
                args.append('(%s)' % flags)
            else:
                args.append(flags)
        if date is not None:
            args.append(time2internaldate(date))
        args.append('{%s}' % len(message_bytes))
        self.literal_data = message_bytes
        command = self.command('APPEND', *args, timeout=timeout)
        return await self.execute(command)

    async def id(self, **kwargs: Union[dict, list, str]) -> Response:
        args = arguments_rfs2971(**kwargs)
        return await self.execute(Command('ID', self.new_tag(), *args, loop=self.loop))

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST', 'EXAMINE', 'ENABLE'}

    async def namespace(self) -> Response:
        if 'NAMESPACE' not in self.capabilities:
            raise Abort('server has not NAMESPACE capability')
        return await self.execute(Command('NAMESPACE', self.new_tag(), loop=self.loop))

    async def simple_command(
        self,
        name: str,
        *args: str,
    ) -> Response:
        if name not in self.simple_commands:
            raise ValueError(f'simple command only available for {self.simple_commands}')
        command = self.command(name, *args)
        return await self.execute(command)

    async def wait_async_pending_commands(self) -> None:
        await asyncio.wait([asyncio.ensure_future(cmd.wait()) for cmd in self.pending_async_commands.values()])

    async def wait(self, state_regexp: Pattern) -> None:
        state_re = re.compile(state_regexp)
        async with self.state_condition:
            await self.state_condition.wait_for(lambda: state_re.match(self.state))

    async def wait_for_idle_response(self):
        await self._idle_event.wait()

    def _untagged_response(self, line: bytes) -> Command:
        line = line.replace(b'* ', b'')
        if self.pending_sync_command is not None:
            self.pending_sync_command.append_to_resp(line)
            command = self.pending_sync_command
        else:
            match = message_data_re.match(line)
            if match:
                cmd_name, text = match.group(1), match.string
            else:
                cmd_name, _, text = line.partition(b' ')
            command = self.pending_async_commands.get(cmd_name.decode().upper())
            if command is not None:
                command.append_to_resp(text)
            else:
                # noop is async and servers can send untagged responses
                command = self.pending_async_commands.get('NOOP')
                if command is not None:
                    command.append_to_resp(line)
                else:
                    log.info('ignored untagged response : %s' % line)
        return command

    def _response_done(self, line: bytes) -> None:
        log.debug('tagged status %s' % line)
        tag, _, response = line.partition(b' ')

        if self.pending_sync_command is not None:
            if self.pending_sync_command.tag != tag.decode():
                raise Abort('unexpected tagged response with pending sync command (%s) response: %s' %
                            (self.pending_sync_command, response))
            command = self.pending_sync_command
            self.pending_sync_command = None
        else:
            cmds = self._find_pending_async_cmd_by_tag(tag.decode())
            if len(cmds) == 0:
                raise Abort('unexpected tagged (%s) response: %s' % (tag, response))
            elif len(cmds) > 1:
                raise Error('inconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds.pop()
            self.pending_async_commands.pop(command.untagged_resp_name)

        response_result, _, response_text = response.partition(b' ')
        command.close(response_text, result=response_result.decode())

    def _continuation(self, line: bytes) -> None:
        if self.pending_sync_command is None:
            log.info(f'server says {line} (ignored)')
        elif self.pending_sync_command.name == 'APPEND':
            if self.literal_data is None:
                Abort('asked for literal data but have no literal data to send')
            self.transport.write(self.literal_data)
            self.transport.write(CRLF)
            self.literal_data = None
        elif self.pending_sync_command.name == 'IDLE':
            log.debug(f'continuation line -- assuming IDLE is active: {line}')
            self._idle_event.set()
        else:
            log.debug(f'continuation line appended to pending sync command {self.pending_sync_command}: {line}')
            self.pending_sync_command.append_to_resp(line)
            self.pending_sync_command.flush()

    def new_tag(self) -> str:
        tag = self.tagpre + str(self.tagnum)
        self.tagnum += 1
        return tag

    def _find_pending_async_cmd_by_tag(self, tag: str) -> list:
        return [c for c in self.pending_async_commands.values() if c is not None and c.tag == tag]
