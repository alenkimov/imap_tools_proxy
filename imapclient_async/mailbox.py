import re
import ssl
import asyncio
import functools
import random
import logging

from base64 import b64encode
from datetime import datetime
from imaplib import Time2Internaldate as to_internaldate

from typing import Any
from typing import Union
from typing import Optional
from typing import Coroutine
from typing import Callable
from typing import AsyncIterator
from typing import Sequence
from typing import Iterable

from python_socks.async_.asyncio import Proxy

from .types import Response
from .types import Criteria
from .enums import FolderStatus
from .consts import ALLOWED_IMAP_VERSIONS
from .consts import MAXLINE
from .consts import CRLF
from .consts import STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT
from .consts import UID_PATTERN, MOVE_RESULT_TAG
from .consts import IMAP4_PORT, IMAP4_SSL_PORT
from .consts import STOP_WAIT_SERVER_PUSH
from .consts import TWENTY_NINE_MINUTES
from .consts import LITERAL_DATA_REGEXP
from .consts import MESSAGE_DATA_REGEXP
from .consts import TAGGED_STATUS_RESPONSE_REGEXP
from .errors import AbortError
from .errors import IncorrectRamblerPassword
from .errors import IMAPClientError
from .errors import CommandTimeout
from .errors import IncompleteRead
from .errors import UnexpectedCommandStatus
from .errors import MaxResponseDataLengthReached
from .errors import UnsupportedCapability

from .utils import normalise_sort_criteria
from .utils import pairs_to_dict, join_uids
from .utils import clean_uids, chunked, clean_flags, chunked_crop
from .utils import quoted
from .utils import int2ap
from .utils import arguments_rfs2971

from .command import Commands
from .command import Command
from .command import FetchCommand
from .command import IdleCommand

from .imap_utf7 import utf7_decode
from .query import AND
from .message import MailMessage
from .folder import Folder
from .folder import FOLDER_ITEM_REGEXP


log = logging.getLogger(__name__)


def change_state(coro: Callable[..., Coroutine[Any, Any, Optional[Response]]]):
    @functools.wraps(coro)
    async def wrapper(self, *args, **kargs) -> Optional[Response]:
        async with self.state_condition:
            res = await coro(self, *args, **kargs)
            log.debug(f'state -> {self.state}')
            self.state_condition.notify_all()
            return res

    return wrapper


def require_capability(capability: str):
    """Decorator raising UnsupportedCapability when a capability is not available."""

    def actual_decorator(func):
        @functools.wraps(func)
        def wrapper(protocol, *args, **kwargs):
            protocol.check_capability(capability)
            return func(protocol, *args, **kwargs)

        return wrapper

    return actual_decorator


class IMAPClient(asyncio.Protocol):
    DEFAULT_CHARSET = 'US-ASCII'

    def __init__(
        self,
        host: str,
        port: int = IMAP4_SSL_PORT,
        *,
        timeout: float = 10,
        proxy_url: str = None,
        ssl_context: Optional[ssl.SSLContext] = None,
        loop: asyncio.AbstractEventLoop = None,
        conn_lost_cb: Callable[[Optional[Exception]], None] = None,
    ):
        if port == IMAP4_SSL_PORT and ssl_context is None:
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        self.host = host
        self.port = port
        self.timeout = timeout
        self._proxy_url = proxy_url
        self.ssl_context = ssl_context
        self.loop = loop
        self.conn_lost_cb = conn_lost_cb

        self.transport = None
        self.tasks: set[asyncio.Future] = set()
        self._idle_waiter = None
        self._current_folder = None
        self.state = STARTED
        self.state_condition = asyncio.Condition()
        self.capabilities = set()
        self.pending_async_commands = dict()
        self.pending_sync_command = None
        self.current_command = None
        self.idle_queue = asyncio.Queue()
        self._idle_event = asyncio.Event()
        self.imap_version = None
        self.literal_data = None
        self.incomplete_line = b''
        self.tagnum = 0
        self.tagpre = int2ap(random.randint(4096, 65535))

        # self.folder_encode = True
        # self.normalise_times = True

    @property
    def proxy_url(self) -> str | None:
        return self._proxy_url

    @property
    def current_folder(self) -> str | None:
        return self._current_folder

    async def connect(self):
        self.loop = self.loop or asyncio.get_running_loop()
        sock, server_hostname = None, None
        if self._proxy_url:
            # self.ssl_context.check_hostname = False
            # self.ssl_context.verify_mode = ssl.CERT_NONE
            server_hostname = self.host if (self.ssl_context and ssl.HAS_SNI) else None
            sock = await Proxy.from_url(self._proxy_url).connect(self.host, self.port)
        return await self.loop.create_connection(
            lambda: self,
            self.host,
            self.port,
            ssl=self.ssl_context,
            server_hostname=server_hostname,
            sock=sock,
        )

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
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

    def _handle_responses(
            self,
            data: bytes,
            line_handler: Callable[[bytes, Command],
            Optional[Command]],
            current_cmd: Command = None,
    ) -> None:
        if not data:
            if self.pending_sync_command is not None:
                self.pending_sync_command.flush()
            if current_cmd is not None and current_cmd.wait_data():
                raise IncompleteRead(current_cmd)
            return

        if len(data) > MAXLINE:
            raise MaxResponseDataLengthReached(data)

        if current_cmd is not None and current_cmd.wait_literal_data():
            data = current_cmd.append_literal_data(data)
            if current_cmd.wait_literal_data():
                raise IncompleteRead(current_cmd)

        line, separator, tail = data.partition(CRLF)
        if not separator:
            raise IncompleteRead(current_cmd, data)

        cmd = line_handler(line, current_cmd)

        begin_literal = LITERAL_DATA_REGEXP.match(line)
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
        elif TAGGED_STATUS_RESPONSE_REGEXP.match(line):
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
            raise AbortError(f'command {command.name} illegal in state {self.state}')

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

        if command.response.result != 'OK':
            raise UnexpectedCommandStatus(command)

        return command.response

    @change_state
    async def welcome(self, command: bytes) -> None:
        if b'PREAUTH' in command:
            self.state = AUTH
        elif b'OK' in command:
            self.state = NONAUTH
        else:
            raise IMAPClientError(command.decode())
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
        if self.host == "imap.rambler.ru" and "%" in password:
            raise IncorrectRamblerPassword(password)

        command = self.command('LOGIN', username, quoted(password))
        response = await asyncio.wait_for(self.execute(command, scrub=password), self.timeout)
        self.state = AUTH
        for line in response.lines:
            if b'CAPABILITY' in line:
                self.capabilities = self.capabilities.union(
                    set(line.decode().replace('CAPABILITY', '').strip().split()))
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
        response = await asyncio.wait_for(self.execute(command, scrub=token), self.timeout)
        self.state = AUTH
        return response

    @change_state
    async def logout(self) -> Response:
        command = self.command('LOGOUT')
        response = await asyncio.wait_for(self.execute(command), self.timeout)
        self.state = LOGOUT
        return response

    @change_state
    async def select_folder(self, folder='INBOX') -> Response:
        command = self.command('SELECT', folder)
        response = await asyncio.wait_for(self.execute(command), self.timeout)
        self._current_folder = folder
        self.state = SELECTED
        return response

    @change_state
    async def close(self) -> Response:
        command = self.command('CLOSE')
        response = await asyncio.wait_for(self.execute(command), self.timeout)
        if response.result == 'OK':
            self.state = AUTH
        return response

    @require_capability('IDLE')
    async def idle(self) -> Response:
        self._idle_event.clear()
        command = self.idle_command()
        return await self.execute(command)

    def has_pending_idle_command(self) -> bool:
        return self.pending_sync_command is not None and self.pending_sync_command.name == 'IDLE'

    @require_capability('IDLE')
    def idle_done(self) -> None:
        """Take the server out of IDLE mode.

        This method should only be called if the server is already in
        IDLE mode.
        """
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        self.send('DONE')

    async def _search_message_uids(
        self,
        *,
        criteria: Criteria = 'ALL',
        charset: str = DEFAULT_CHARSET,
    ) -> Response:
        """Return a list of messages ids from the currently selected
        folder matching *criteria*.

        :param criteria: ...
        :param charset: specifies the character set of the criteria. It
        defaults to US-ASCII as this is the only charset that a server
        is required to support by the RFC. UTF-8 is commonly supported
        however.
        """
        command = self.command('SEARCH', 'CHARSET', charset, criteria)
        return await self.execute(command)

    @require_capability('SORT')
    def _search_and_sort_message_uids(
        self,
        sort_criteria: str | Iterable[str],
        *,
        criteria: Criteria = 'ALL',
        charset: str = DEFAULT_CHARSET,
    ):
        """Return a list of message ids from the currently selected
        folder, sorted by *sort_criteria* and optionally filtered by
        *criteria*.

        :param sort_criteria: may be specified as a sequence of strings or a single string.
        Valid *sort_criteria* values::

            ['ARRIVAL']
            ['SUBJECT', 'ARRIVAL']
            'ARRIVAL'
            'REVERSE SIZE'

        The *criteria* and *charset* arguments are as per
        :py:meth:`.search`.

        See :rfc:`5256` for full details.

        Note that SORT is an extension to the IMAP4 standard so it may
        not be supported by all IMAP servers.

        :param criteria: ...
        :param charset: specifies the character set of the criteria. It
        defaults to US-ASCII as this is the only charset that a server
        is required to support by the RFC. UTF-8 is commonly supported
        however.
        """
        command = self.command('SORT', normalise_sort_criteria(sort_criteria), charset, criteria)
        return self.execute(command)

    async def search_message_uids(
        self,
        *,
        criteria: Criteria = 'ALL',
        charset: str = DEFAULT_CHARSET,
        sort_criteria: str | Iterable[str] = None,
    ) -> list[str]:
        """
        Search folder for matching message uids in current folder
        :param criteria: message search criteria
        :param charset: IANA charset, indicates charset of the strings that appear in the search criteria. See rfc2978
        :param sort_criteria: criteria for sort messages on server, use SortCriteria constants. Charset arg is important for sort
        :return: uids
        """
        # encoded_criteria = criteria if type(criteria) is bytes else str(criteria).encode(charset)
        if sort_criteria:
            response = await asyncio.wait_for(
                self._search_and_sort_message_uids(sort_criteria, criteria=criteria, charset=charset),
                self.timeout,
            )
        else:
            response = await asyncio.wait_for(
                self._search_message_uids(criteria=criteria, charset=charset),
                self.timeout,
            )
        return response.lines[0].decode().split() if response.lines[0] else []

    async def store(self, criteria: Criteria = 'ALL', by_uid: bool = False) -> Response:
        command = self.command('STORE', criteria, prefix='UID' if by_uid else '', untagged_resp_name='FETCH')
        return await asyncio.wait_for(self.execute(command), self.timeout)

    async def expunge_messages(self, uids: Iterable[str] = None):
        """
        When, no *uids* are specified, remove all messages
        from the currently selected folder that have the
        ``\\Deleted`` flag set.

        The return value is the server response message
        followed by a list of expunge responses. For example::

            ('Expunge completed.',
             [(2, 'EXPUNGE'),
              (1, 'EXPUNGE'),
              (0, 'RECENT')])

        In this case, the responses indicate that the message with
        sequence numbers 2 and 1 where deleted, leaving no recent
        messages in the folder.

        See :rfc:`3501#section-6.4.3` section 6.4.3 and
        :rfc:`3501#section-7.4.1` section 7.4.1 for more details.

        When *uids* are specified, remove the specified messages
        from the selected folder, provided those messages also have
        the ``\\Deleted`` flag set. The return value is ``None`` in
        this case.

        Expunging messages by id(s) requires that *use_uid* is
        ``True`` for the client.

        See :rfc:`4315#section-2.1` section 2.1 for more details.
        """
        if uids:
            self.check_capability('UIDPLUS')
            command = self.command('EXPUNGE', join_uids(uids), prefix='UID')
        else:
            command = self.command('EXPUNGE')
        return await self.execute(command)

    async def copy_messages(
        self,
        uids: Union[str, Iterable[str]],
        destination_folder: str,
        chunks: Optional[int] = None,
    ) -> list[tuple]:
        """
        Copy messages from the current folder to the specified folder.
        Do nothing on empty uid_list.
        :param uids: UIDs for copy
        :param destination_folder: Folder for email copies
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: empty uid_list, command results otherwise
        """
        cleaned_uid_list = clean_uids(uids)
        if not cleaned_uid_list:
            return []

        results = []
        for chunk in chunked_crop(cleaned_uid_list, chunks):
            command = self.command('COPY', join_uids(chunk), destination_folder, prefix='UID')
            response = await asyncio.wait_for(self.execute(command), self.timeout)
            results.append(response)
        return results

    @require_capability('MOVE')
    async def _move_messages(
        self,
        uids: Iterable[str],
        destination_folder: str,
    ) -> Response:
        """Atomically move messages to another folder.

        Requires the MOVE capability, see :rfc:`6851`.

        :param uids: List of message UIDs to move.
        :param destination_folder: The destination folder name.
        """
        command = self.command('MOVE', join_uids(uids), destination_folder, prefix='UID')
        return await self.execute(command)

    async def capability(self) -> Response:
        command = self.command('CAPABILITY')
        response = await self.execute(command)

        capability_list = response.lines[0].decode().split()
        self.capabilities = set(capability_list)
        try:
            self.imap_version = list(
                filter(lambda x: x.upper() in ALLOWED_IMAP_VERSIONS, capability_list)).pop().upper()
        except IndexError:
            raise IMAPClientError('server not IMAP4 compliant')

        return response

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities

    def check_capability(self, capability: str):
        if not self.has_capability(capability):
            raise UnsupportedCapability(capability)

    async def id(self, **kwargs: Union[dict, list, str]) -> Response:
        args = arguments_rfs2971(**kwargs)
        command = Command('ID', self.new_tag(), *args, loop=self.loop)
        return await asyncio.wait_for(self.execute(command), self.timeout)

    simple_commands = {'NOOP', 'CHECK', 'STATUS', 'CREATE', 'DELETE', 'RENAME',
                       'SUBSCRIBE', 'UNSUBSCRIBE', 'LSUB', 'LIST', 'EXAMINE', 'ENABLE'}

    @require_capability('NAMESPACE')
    async def namespace(self) -> Response:
        command = self.command('NAMESPACE')
        return await asyncio.wait_for(self.execute(command), self.timeout)

    async def getquotaroot(self, folder: str = 'INBOX'):
        command = self.command('GETQUOTAROOT', folder, untagged_resp_name='QUOTA')
        return self.execute(command)

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

    async def wait(self, state_regexp: str) -> None:
        state_regexp = re.compile(state_regexp)
        async with self.state_condition:
            await self.state_condition.wait_for(lambda: state_regexp.match(self.state))

    async def wait_hello_from_server(self) -> None:
        await asyncio.wait_for(self.wait('AUTH|NONAUTH'), self.timeout)

    async def wait_for_idle_response(self):
        await self._idle_event.wait()

    def _untagged_response(self, line: bytes) -> Command:
        line = line.replace(b'* ', b'')
        if self.pending_sync_command is not None:
            self.pending_sync_command.append_to_resp(line)
            command = self.pending_sync_command
        else:
            match = MESSAGE_DATA_REGEXP.match(line)
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
                raise AbortError('unexpected tagged response with pending sync command (%s) response: %s' %
                                 (self.pending_sync_command, response))
            command = self.pending_sync_command
            self.pending_sync_command = None
        else:
            cmds = self._find_pending_async_cmd_by_tag(tag.decode())
            if len(cmds) == 0:
                raise AbortError('unexpected tagged (%s) response: %s' % (tag, response))
            elif len(cmds) > 1:
                raise IMAPClientError('inconsistent state : two commands have the same tag (%s)' % cmds)
            command = cmds.pop()
            self.pending_async_commands.pop(command.untagged_resp_name)

        response_result, _, response_text = response.partition(b' ')
        command.close(response_text, result=response_result.decode())

    def _continuation(self, line: bytes) -> None:
        if self.pending_sync_command is None:
            log.info(f'server says {line} (ignored)')
        elif self.pending_sync_command.name == 'APPEND':
            if self.literal_data is None:
                AbortError('asked for literal data but have no literal data to send')
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

    async def stop_wait_server_push(self) -> bool:
        if self.has_pending_idle_command():
            await self.idle_queue.put(STOP_WAIT_SERVER_PUSH)
            return True
        return False

    async def wait_server_push(self, timeout: float = TWENTY_NINE_MINUTES) -> Response:
        return await asyncio.wait_for(self.idle_queue.get(), timeout=timeout)

    async def idle_start(self, timeout: float = TWENTY_NINE_MINUTES) -> asyncio.Future:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        idle = asyncio.ensure_future(self.idle())
        self.tasks.add(idle)
        idle.add_done_callback(self.tasks.discard)
        wait_for_ack = asyncio.ensure_future(self.wait_for_idle_response())
        self.tasks.add(wait_for_ack)
        wait_for_ack.add_done_callback(self.tasks.discard)
        await asyncio.wait({idle, wait_for_ack}, return_when=asyncio.FIRST_COMPLETED)
        if not self.has_pending_idle():
            wait_for_ack.cancel()
            raise AbortError('server returned error to IDLE command')

        def start_stop_wait_server_push():
            task = asyncio.ensure_future(self.stop_wait_server_push())
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        self._idle_waiter = self.loop.call_later(timeout, start_stop_wait_server_push)
        return idle

    def has_pending_idle(self) -> bool:
        return self.has_pending_idle_command()

    async def noop(self) -> Response:
        return await asyncio.wait_for(self.simple_command('NOOP'), self.timeout)

    async def check(self) -> Response:
        return await asyncio.wait_for(self.simple_command('CHECK'), self.timeout)

    async def examine_folder(self, folder: str = 'INBOX') -> Response:
        return await asyncio.wait_for(self.simple_command('EXAMINE', folder), self.timeout)

    async def subscribe_folder(self, folder: str) -> Response:
        return await asyncio.wait_for(self.simple_command('SUBSCRIBE', folder), self.timeout)

    async def unsubscribe_folder(self, folder: str) -> Response:
        return await asyncio.wait_for(self.simple_command('UNSUBSCRIBE', folder), self.timeout)

    async def create_folder(self, folder: str) -> Response:
        return await asyncio.wait_for(self.simple_command('CREATE', folder), self.timeout)

    async def delete_folder(self, folder: str) -> Response:
        return await asyncio.wait_for(self.simple_command('DELETE', folder), self.timeout)

    async def rename_folder(self, folder: str, new_folder_name: str) -> Response:
        return await asyncio.wait_for(self.simple_command('RENAME', folder, new_folder_name), self.timeout)

    async def get_folders(
        self,
        directory='""',
        pattern='*',
        subscribed_only: bool = False,
    ) -> list[Folder]:
        """
        Get a listing of folders on the server
        :param directory: mailbox folder, if empty - get from root
        :param pattern: search arguments, is case-sensitive mailbox name with possible wildcards
            * is a wildcard, and matches zero or more characters at this position
            % is similar to * but it does not match a hierarchy delimiter
        :param subscribed_only: bool - get only subscribed folders
        :return: [FolderInfo]
        """
        command_name = 'LSUB' if subscribed_only else 'LIST'
        response = await asyncio.wait_for(self.simple_command(
            command_name, directory, pattern), self.timeout)

        folders = []
        for folder_item in response.lines:
            if not folder_item:
                continue
            if type(folder_item) is bytes:
                folder_match = re.search(FOLDER_ITEM_REGEXP, utf7_decode(folder_item))
                if not folder_match:
                    continue
                folder_dict = folder_match.groupdict()
                name = folder_dict['name']
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1]
            elif type(folder_item) is tuple:
                # when name has " or \ chars
                folder_match = re.search(FOLDER_ITEM_REGEXP, utf7_decode(folder_item[0]))
                if not folder_match:
                    continue
                folder_dict = folder_match.groupdict()
                name = utf7_decode(folder_item[1])
            else:
                continue
            folders.append(Folder(
                name=name.replace('\\"', '"'),
                delim=folder_dict['delim'].replace('"', ''),
                flags=tuple(folder_dict['flags'].split()),  # noqa
            ))
        return folders

    @require_capability('ENABLE')
    async def enable(self, capability: str) -> Response:
        return await asyncio.wait_for(self.simple_command('ENABLE', capability), self.timeout)

    async def numbers(
        self,
        *,
        criteria: Criteria = 'ALL',
        charset: str = DEFAULT_CHARSET,
    ) -> list[str]:
        """
        Search mailbox for matching message numbers in current folder (this is not uids)
        Message Sequence Number Message Attribute - to accessing messages by relative position in the mailbox,
        it also can be used in mathematical calculations, see rfc3501.
        :param criteria: message search criteria (see examples at ./doc/imap_search_criteria.txt)
        :param charset: IANA charset, indicates charset of the strings that appear in the search criteria. See rfc2978
        :return email message numbers
        """
        return await self.search_message_uids(criteria=criteria, charset=charset)

    async def _fetch_messages(
        self,
        message_set: str,
        message_parts: str,
        by_uid: bool = False,
    ) -> Response:
        command = self.fetch_command(message_set, message_parts, prefix='UID' if by_uid else '', timeout=self.timeout)
        return await self.execute(command)

    # todo fetch
    async def numbers_to_uids(self, numbers: list[str]) -> list[str]:
        """Get message uids by message numbers"""
        if not numbers:
            return []

        fetch_result = await self._fetch_messages(','.join(numbers), "(UID)")
        result = []
        for raw_uid_item in fetch_result[1]:
            uid_match = re.search(UID_PATTERN, (raw_uid_item or b'').decode())
            if uid_match:
                result.append(uid_match.group('uid'))
        return result

    # todo fetch
    async def _fetch_by_one(
        self,
        uids: Iterable[str],
        message_parts: str,
    ) -> AsyncIterator[list]:
        for uid in uids:
            fetch_result = await self._fetch_messages(uid, message_parts)
            if not fetch_result[1] or fetch_result[1][0] is None:
                continue
            yield fetch_result[1]

    # todo fetch
    async def _fetch_in_bulk(
        self,
        uids: Sequence[str],
        message_parts: str,
        reverse: bool,
        bulk: int,
    ) -> AsyncIterator[list]:
        if not uids:
            return

        if isinstance(bulk, int) and bulk >= 2:
            uid_list_seq = chunked_crop(uids, bulk)
        elif isinstance(bulk, bool):
            uid_list_seq = (uids,)
        else:
            raise ValueError('bulk arg may be bool or int >= 2')

        for uid_list_i in uid_list_seq:
            fetch_result = await self._fetch_messages(join_uids(uid_list_i), message_parts)
            if not fetch_result[1] or fetch_result[1][0] is None:
                return
            for built_fetch_item in chunked((reversed if reverse else iter)(fetch_result[1]), 2):
                yield built_fetch_item

    # todo fetch
    async def fetch_messages(
        self,
        criteria: Criteria = 'ALL',
        *,
        charset: str = DEFAULT_CHARSET,
        limit: Optional[Union[int, slice]] = None,
        mark_seen: bool = True,
        reverse: bool = False,
        headers_only: bool = False,
        bulk: Union[bool, int] = False,
        # sort: Optional[Union[str, Iterable[str]]] = None,
    ) -> AsyncIterator[MailMessage]:
        """
        Mail message generator in current folder by search criteria
        :param criteria: message search criteria (see examples at ./doc/imap_search_criteria.txt)
        :param charset: IANA charset, indicates charset of the strings that appear in the search criteria. See rfc2978
        :param limit: int | slice - limit number of read emails | slice emails range for read
                      useful for actions with a large number of messages, like "move" | paging
        :param mark_seen: mark emails as seen on fetch
        :param reverse: in order from the larger date to the smaller
        :param headers_only: get only email headers (without text, html, attachments)
        :param bulk:
            False - fetch each message separately per N commands - low memory consumption, slow
            True  - fetch all messages per 1 command - high memory consumption, fast. Fails on big bulk at server
            int - fetch messages by bulks of the specified size
        :param sort: criteria for sort messages on server, use SortCriteria constants. Charset arg is important for sort
        :return generator: MailMessage
        """
        message_parts = (f"(BODY{'' if mark_seen else '.PEEK'}"
                         f"[{'HEADER' if headers_only else ''}]"
                         f" UID FLAGS RFC822.SIZE)")
        limit_range = slice(0, limit) if type(limit) is int else limit or slice(None)
        assert type(limit_range) is slice
        # uids = tuple((reversed if reverse else iter)(await self.uids(criteria, charset, sort)))[limit_range]
        uids = tuple((reversed if reverse else iter)(await self.uids(criteria, charset)))[limit_range]
        if bulk:
            message_generator = self._fetch_in_bulk(uids, message_parts, reverse, bulk)
        else:
            message_generator = self._fetch_by_one(uids, message_parts)
        async for fetch_item in message_generator:
            yield MailMessage(fetch_item)

    async def delete_messages(
        self,
        uids: Union[str, Iterable[str]],
        chunks: Optional[int] = None,
    ) -> Optional[list[tuple[tuple, tuple]]]:
        """
        Delete email messages
        Do nothing on empty uids
        :param uids: UIDs for delete
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uids, command results otherwise
        """
        cleaned_uids = clean_uids(uids)
        if not cleaned_uids:
            return None
        results = []
        for chunk in chunked_crop(cleaned_uids, chunks):
            store_result = await self.store(join_uids(chunk), '+FLAGS', r'(\Deleted)')
            expunge_result = await self.expunge_messages()
            results.append((store_result, expunge_result))
        return results

    async def move_messages(
        self,
        uids: Union[str, Iterable[str]],
        destination_folder: str,
        chunks: Optional[int] = None,
    ) -> list[tuple[tuple, tuple]]:
        """
        Move email messages into the specified folder.
        Do nothing on empty uids.
        :param uids: UIDs for move
        :param destination_folder: Folder for move to
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uids, command results otherwise
        """
        cleaned_uids = clean_uids(uids)
        if not cleaned_uids:
            return []

        results = []

        # Server side move
        if self.has_capability('MOVE'):
            for chunk in chunked_crop(cleaned_uids, chunks):
                response = await asyncio.wait_for(self._move_messages(chunk, destination_folder), self.timeout)
                results.append((response, MOVE_RESULT_TAG))

        # Client side move
        else:
            for chunk in chunked_crop(cleaned_uids, chunks):
                copy_response = await self.copy_messages(chunk, destination_folder)
                delete_response = await self.delete_messages(chunk)
                results.append((copy_response, delete_response))

        return results

    async def flag_messages(
        self,
        uid_list: Union[str, Iterable[str]],
        flags: Union[str, Iterable[str]],
        value: bool,
        chunks: Optional[int] = None,
    ) -> list[tuple[tuple, tuple]]:
        """
        Set/unset email flags.
        Do nothing on empty uid_list.
        System flags contains in consts.MailMessageFlags.all
        :param uid_list: UIDs for set flag
        :param flags: Flags for operate
        :param value: Should the flags be set: True - yes, False - no
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uid_list, command results otherwise
        """
        cleaned_uids = clean_uids(uid_list)
        if not cleaned_uids:
            return []

        results = []
        for chunk in chunked_crop(cleaned_uids, chunks):
            store_result = await self.store(
                join_uids(chunk),
                ('+' if value else '-') + 'FLAGS',
                f'({" ".join(clean_flags(flags))})'
            )
            expunge_result = await self.expunge_messages()
            results.append((store_result, expunge_result))
        return results

    async def _append_message(
        self,
        message_bytes: bytes,
        folder: str,
        *,
        flags: str = None,
        date: Any = None,
    ) -> Response:
        args = [folder]
        if flags is not None:
            if (flags[0], flags[-1]) != ('(', ')'):
                args.append('(%s)' % flags)
            else:
                args.append(flags)
        if date is not None:
            args.append(to_internaldate(date))
        args.append('{%s}' % len(message_bytes))
        self.literal_data = message_bytes
        command = self.command('APPEND', *args, timeout=self.timeout)
        return await self.execute(command)

    async def append_message(
        self,
        message: Union[MailMessage, bytes],
        folder: str,
        dt: Optional[datetime] = None,
        flags: Optional[Union[str, Iterable[str]]] = None,
    ) -> Response:
        """
        Append email messages to server
        :param message: MailMessage object or bytes
        :param folder: destination folder, INBOX by default
        :param dt: email message datetime with tzinfo, now by default, imaplib.Time2Internaldate types supported
        :param flags: email message flags, no flags by default. System flags at consts.MailMessageFlags.all
        :return: command results
        """
        timezone = datetime.now().astimezone().tzinfo  # system timezone
        cleaned_flags = clean_flags(flags or [])

        return await self._append_message(
            message if type(message) is bytes else message.obj.as_bytes(),
            folder,
            flags=f'({" ".join(cleaned_flags)})' if cleaned_flags else None,
            date=dt or datetime.now(timezone),
        )

    async def get_folder_status(
        self,
        folder: str,
        statuses: Iterable[FolderStatus] = None,
    ) -> dict[FolderStatus, int]:
        """
        Get the status of a folder

        - MESSAGES: The number of messages in the mailbox
        - RECENT: The number of messages with the Recent flag set
        - UIDNEXT: The next unique identifier value of the mailbox
        - UIDVALIDITY: The unique identifier validity value of the mailbox
        - UNSEEN: The number of messages which do not have the Seen flag set

        :return: {'MESSAGES': ..., 'RECENT': ..., 'UIDNEXT': ..., 'UIDVALIDITY': ..., 'UNSEEN': ...}
        """
        if not statuses:
            statuses = tuple(FolderStatus)

        response = await asyncio.wait_for(self.simple_command(
            'STATUS', folder, f'({" ".join(statuses)})'), self.timeout)

        status_data = [i for i in response.lines if type(i) is bytes][0]  # may contain tuples with encoded names
        values = status_data.decode().split('(')[-1].split(')')[0].split(' ')
        return {k: int(v) for k, v in pairs_to_dict(values).items() if str(v).isdigit()}

    async def super_smart_get_messages(
        self,
        folders: Sequence[str],
        *,
        since: datetime = None,
        allowed_senders: Sequence[str] = None,
        allowed_receivers: Sequence[str] = None,
        sender_regex: str | re.Pattern[str] = None,
        limit: int = 10,
        reverse: bool = True,
    ) -> AsyncIterator[MailMessage]:
        for folder in folders:
            await self.select_folder(folder)

            criteria = AND(
                date_gte=since.date() if since else None,
                from_=allowed_senders if allowed_senders else None,
                to=allowed_receivers if allowed_receivers else None,
                all=True  # Условие для выборки всех сообщений при отсутствии других фильтров
            )

            async for message in self.fetch_messages(criteria, limit=limit, reverse=reverse):  # type: MailMessage
                # Фильтрация по дате
                if since and message.date < since:
                    continue

                # Фильтрация по регулярному выражению
                if sender_regex and not re.search(sender_regex, message.from_, re.IGNORECASE):
                    continue

                yield message
