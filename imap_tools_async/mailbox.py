import asyncio
import logging
import re
import ssl
from asyncio import Future
from datetime import datetime
from typing import Union, Any, Callable, Optional, Pattern
from typing import AsyncIterator
from typing import Sequence
from typing import Iterable
from typing import Literal

from python_socks.async_.asyncio import Proxy

from .types import Response
from .consts import UID_PATTERN, MOVE_RESULT_TAG
from .consts import IMAP4_PORT, IMAP4_SSL_PORT
from .consts import STOP_WAIT_SERVER_PUSH
from .consts import TWENTY_NINE_MINUTES

from .errors import Abort
from .errors import IncorrectRamblerPassword
from .errors import MailboxFolderStatusValueError
from .command import Command

from .imap_utf7 import utf7_decode
from .enums import MailBoxFolderStatusOptions
from .utils import pairs_to_dict
from .utils import clean_uids, chunked, encode_folder, clean_flags, chunked_crop
from .types import StrOrBytes
from .types import Criteria

from .message import MailMessage
from .protocol import IMAP4ClientProtocol
from .folder import FolderInfo


log = logging.getLogger(__name__)


class IMAP4:
    protocol: IMAP4ClientProtocol | None
    TIMEOUT_SECONDS = 10.0

    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = IMAP4_PORT,
        *,
        timeout: float = TIMEOUT_SECONDS,
        loop: asyncio.AbstractEventLoop = None,
        conn_lost_cb: Callable[[Optional[Exception]], None] = None,
    ):
        self.timeout = timeout
        self.port = port
        self.host = host
        self.protocol = None
        self._idle_waiter = None
        self.tasks: set[Future] = set()
        self._current_folder = None

        loop = loop or asyncio.get_running_loop()
        self.protocol = IMAP4ClientProtocol(loop, conn_lost_cb)

    @property
    def current_folder(self) -> str | None:
        return self._current_folder

    async def connect(self, ssl_context: ssl.SSLContext = None):
        return await self.protocol.create_connection(self.host, self.port, ssl_context=ssl_context)

    async def wait_hello_from_server(self) -> None:
        await asyncio.wait_for(self.protocol.wait('AUTH|NONAUTH'), self.timeout)

    async def login(self, username: str, password: str) -> Response:
        if self.host == "imap.rambler.ru" and "%" in password:
            raise IncorrectRamblerPassword(password)

        return await asyncio.wait_for(self.protocol.login(username, password), self.timeout)

    async def xoauth2(self, username: str, token: str) -> Response:
        return await asyncio.wait_for(self.protocol.xoauth2(username, token), self.timeout)

    async def logout(self) -> Response:
        return await asyncio.wait_for(self.protocol.logout(), self.timeout)

    async def select_folder(self, folder: str = 'INBOX') -> Response:
        response = await asyncio.wait_for(self.protocol.select_folder(folder), self.timeout)
        self._current_folder = folder
        return response

    # todo Criteria
    async def search_messages(self, *criteria: str, charset: Optional[str] = 'utf-8') -> Response:
        return await asyncio.wait_for(self.protocol.search_messages(*criteria, charset=charset), self.timeout)

    async def uid_search(self, *criteria: str, charset: Optional[str] = 'utf-8') -> Response:
        return await asyncio.wait_for(self.protocol.search_messages(*criteria, by_uid=True, charset=charset), self.timeout)

    async def uid(
        self,
        command: Literal['FETCH', 'STORE', 'COPY', 'MOVE', 'EXPUNGE'],
        *criteria: str,
    ) -> Response:
        return await self.protocol.uid(command, *criteria, timeout=self.timeout)

    async def store(self, *criteria: str) -> Response:
        return await asyncio.wait_for(self.protocol.store(*criteria), self.timeout)

    async def copy(self, *criteria: str) -> Response:
        return await asyncio.wait_for(self.protocol.copy(*criteria), self.timeout)

    async def expunge(self) -> Response:
        return await asyncio.wait_for(self.protocol.expunge(), self.timeout)

    async def fetch(self, message_set: str, message_parts: str) -> Response:
        return await self.protocol.fetch(message_set, message_parts, timeout=self.timeout)

    async def idle(self) -> Response:
        return await self.protocol.idle()

    def idle_done(self) -> None:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        self.protocol.idle_done()

    async def stop_wait_server_push(self) -> bool:
        if self.protocol.has_pending_idle_command():
            await self.protocol.idle_queue.put(STOP_WAIT_SERVER_PUSH)
            return True
        return False

    async def wait_server_push(self, timeout: float = TWENTY_NINE_MINUTES) -> Response:
        return await asyncio.wait_for(self.protocol.idle_queue.get(), timeout=timeout)

    async def idle_start(self, timeout: float = TWENTY_NINE_MINUTES) -> Future:
        if self._idle_waiter is not None:
            self._idle_waiter.cancel()
        idle = asyncio.ensure_future(self.idle())
        self.tasks.add(idle)
        idle.add_done_callback(self.tasks.discard)
        wait_for_ack = asyncio.ensure_future(self.protocol.wait_for_idle_response())
        self.tasks.add(wait_for_ack)
        wait_for_ack.add_done_callback(self.tasks.discard)
        await asyncio.wait({idle, wait_for_ack}, return_when=asyncio.FIRST_COMPLETED)
        if not self.has_pending_idle():
            wait_for_ack.cancel()
            raise Abort('server returned error to IDLE command')

        def start_stop_wait_server_push():
            task = asyncio.ensure_future(self.stop_wait_server_push())
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        self._idle_waiter = self.protocol.loop.call_later(timeout, start_stop_wait_server_push)
        return idle

    def has_pending_idle(self) -> bool:
        return self.protocol.has_pending_idle_command()

    async def id(self, **kwargs) -> Response:
        return await asyncio.wait_for(self.protocol.id(**kwargs), self.timeout)

    async def namespace(self) -> Response:
        return await asyncio.wait_for(self.protocol.namespace(), self.timeout)

    async def noop(self) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('NOOP'), self.timeout)

    async def check(self) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('CHECK'), self.timeout)

    async def examine(self, folder: str = 'INBOX') -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('EXAMINE', folder), self.timeout)

    async def status(self, folder: str, names: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('STATUS', folder, names), self.timeout)

    async def subscribe(self, folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('SUBSCRIBE', folder), self.timeout)

    async def unsubscribe(self, folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('UNSUBSCRIBE', folder), self.timeout)

    async def lsub(self, reference_name: str, folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('LSUB', reference_name, folder), self.timeout)

    async def create(self, folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('CREATE', folder), self.timeout)

    async def delete(self, folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('DELETE', folder), self.timeout)

    async def rename(self, old_folder: str, new_folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('RENAME', old_folder, new_folder), self.timeout)

    async def getquotaroot(self) -> Response:
        return await asyncio.wait_for(self.protocol.execute(Command('GETQUOTAROOT', self.protocol.new_tag(), 'INBOX', untagged_resp_name='QUOTA')), self.timeout)

    async def folder_list(self, directory='""', pattern='*') -> Response:
        return await asyncio.wait_for(self.protocol.simple_command('LIST', directory, pattern), self.timeout)

    async def folder_exists(self, pattern: str) -> bool:
        """Checks whether a folder exists on the server."""
        return len(await self.folder_list('""', pattern)) > 0

    async def append(self, message_bytes, folder: str = 'INBOX', flags: str = None, date: Any = None) -> Response:
        return await self.protocol.append(message_bytes, folder, flags, date, timeout=self.timeout)

    async def close(self) -> Response:
        return await asyncio.wait_for(self.protocol.close(), self.timeout)

    async def move(self, uid_set: str, folder: str) -> Response:
        return await asyncio.wait_for(self.protocol.move(uid_set, folder), self.timeout)

    async def enable(self, capability: str) -> Response:
        if 'ENABLE' not in self.protocol.capabilities:
            raise Abort('server has not ENABLE capability')

        return await asyncio.wait_for(self.protocol.simple_command('ENABLE', capability), self.timeout)

    async def numbers(self, criteria: Criteria = 'ALL', charset: str = 'US-ASCII') -> list[str]:
        """
        Search mailbox for matching message numbers in current folder (this is not uids)
        Message Sequence Number Message Attribute - to accessing messages by relative position in the mailbox,
        it also can be used in mathematical calculations, see rfc3501.
        :param criteria: message search criteria (see examples at ./doc/imap_search_criteria.txt)
        :param charset: IANA charset, indicates charset of the strings that appear in the search criteria. See rfc2978
        :return email message numbers
        """
        encoded_criteria = criteria if type(criteria) is bytes else str(criteria).encode(charset)
        search_result = await self.search_messages(encoded_criteria, charset)
        return search_result[1][0].decode().split() if search_result[1][0] else []

    async def numbers_to_uids(self, numbers: list[str]) -> list[str]:
        """Get message uids by message numbers"""
        if not numbers:
            return []
        fetch_result = await self.fetch(','.join(numbers), "(UID)")
        result = []
        for raw_uid_item in fetch_result[1]:
            uid_match = re.search(UID_PATTERN, (raw_uid_item or b'').decode())
            if uid_match:
                result.append(uid_match.group('uid'))
        return result

    async def uids(
        self,
        criteria: Criteria = 'ALL',
        charset: str = 'US-ASCII',
        # sort: Optional[Union[str, Iterable[str]]] = None,
    ) -> list[str]:
        """
        Search mailbox for matching message uids in current folder
        :param criteria: message search criteria (see examples at ./doc/imap_search_criteria.txt)
        :param charset: IANA charset, indicates charset of the strings that appear in the search criteria. See rfc2978
        # :param sort: criteria for sort messages on server, use SortCriteria constants. Charset arg is important for sort
        :return: email message uids
        """
        # todo sort support
        # encoded_criteria = criteria if type(criteria) is bytes else str(criteria).encode(charset)
        # if sort:
        #     sort = (sort,) if isinstance(sort, str) else sort
        #     uid_result = await self.uid('SORT', f'({" ".join(sort)})', charset, encoded_criteria)
        # else:
        #     uid_result = self.uid('SEARCH', 'CHARSET', charset, encoded_criteria)  # *charset are opt here

        response = await self.search_messages(criteria, charset)
        return response.lines[0].decode().split() if response.lines[0] else []

    async def _fetch_by_one(self, uid_list: Sequence[str], message_parts: str) -> AsyncIterator[list]:
        for uid in uid_list:
            fetch_result = await self.uid('FETCH', uid, message_parts)
            if not fetch_result[1] or fetch_result[1][0] is None:
                continue
            yield fetch_result[1]

    async def _fetch_in_bulk(
        self,
        uid_list: Sequence[str],
        message_parts: str,
        reverse: bool,
        bulk: int,
    ) -> AsyncIterator[list]:
        if not uid_list:
            return

        if isinstance(bulk, int) and bulk >= 2:
            uid_list_seq = chunked_crop(uid_list, bulk)
        elif isinstance(bulk, bool):
            uid_list_seq = (uid_list,)
        else:
            raise ValueError('bulk arg may be bool or int >= 2')

        for uid_list_i in uid_list_seq:
            fetch_result = await self.uid('FETCH', ','.join(uid_list_i), message_parts)
            if not fetch_result[1] or fetch_result[1][0] is None:
                return
            for built_fetch_item in chunked((reversed if reverse else iter)(fetch_result[1]), 2):
                yield built_fetch_item

    async def smart_fetch(
        self,
        criteria: Criteria = 'ALL',
        charset: str = 'US-ASCII',
        limit: Optional[Union[int, slice]] = None,
        mark_seen=True,
        reverse=False,
        headers_only=False,
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
        uid_list: Union[str, Iterable[str]],
        chunks: Optional[int] = None,
    ) -> Optional[list[tuple[tuple, tuple]]]:
        """
        Delete email messages
        Do nothing on empty uid_list
        :param uid_list: UIDs for delete
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uid_list, command results otherwise
        """
        cleaned_uid_list = clean_uids(uid_list)
        if not cleaned_uid_list:
            return None
        results = []
        for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
            store_result = await self.uid('STORE', ','.join(cleaned_uid_list_i), '+FLAGS', r'(\Deleted)')
            expunge_result = await self.expunge()
            results.append((store_result, expunge_result))
        return results

    async def copy_messages(
        self,
        uid_list: Union[str, Iterable[str]],
        destination_folder: StrOrBytes,
        chunks: Optional[int] = None,
    ) -> Optional[list[tuple]]:
        """
        Copy email messages into the specified folder.
        Do nothing on empty uid_list.
        :param uid_list: UIDs for copy
        :param destination_folder: Folder for email copies
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uid_list, command results otherwise
        """
        cleaned_uid_list = clean_uids(uid_list)
        if not cleaned_uid_list:
            return None
        results = []
        for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
            copy_result = await self.uid(
                'COPY', ','.join(cleaned_uid_list_i), encode_folder(destination_folder))  # noqa
            results.append(copy_result)
        return results

    async def move_messages(
        self,
        uid_list: Union[str, Iterable[str]],
        destination_folder: StrOrBytes,
        chunks: Optional[int] = None,
    ) -> Optional[list[tuple[tuple, tuple]]]:
        """
        Move email messages into the specified folder.
        Do nothing on empty uid_list.
        :param uid_list: UIDs for move
        :param destination_folder: Folder for move to
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uid_list, command results otherwise
        """
        cleaned_uid_list = clean_uids(uid_list)
        if not cleaned_uid_list:
            return None
        if 'MOVE' in self.protocol.capabilities:
            # server side move
            results = []
            for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
                move_result = await self.uid(
                    'MOVE', ','.join(cleaned_uid_list_i), encode_folder(destination_folder))  # noqa
                results.append((move_result, MOVE_RESULT_TAG))
            return results
        else:
            # client side move
            results = []
            for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
                copy_result = await self.copy_messages(cleaned_uid_list_i, destination_folder)
                delete_result = await self.delete_messages(cleaned_uid_list_i)
                results.append((copy_result, delete_result))
            return results

    async def flag_messages(
        self,
        uid_list: Union[str, Iterable[str]],
        flag_set: Union[str, Iterable[str]],
        value: bool,
        chunks: Optional[int] = None,
    ) -> Optional[list[tuple[tuple, tuple]]]:
        """
        Set/unset email flags.
        Do nothing on empty uid_list.
        System flags contains in consts.MailMessageFlags.all
        :param uid_list: UIDs for set flag
        :param flag_set: Flags for operate
        :param value: Should the flags be set: True - yes, False - no
        :param chunks: Number of UIDs to process at once, to avoid server errors on large set. Proc all at once if None.
        :return: None on empty uid_list, command results otherwise
        """
        cleaned_uid_list = clean_uids(uid_list)
        if not cleaned_uid_list:
            return None
        results = []
        for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
            store_result = await self.uid(
                'STORE',
                ','.join(cleaned_uid_list_i),
                ('+' if value else '-') + 'FLAGS',
                f'({" ".join(clean_flags(flag_set))})'
            )
            expunge_result = await self.expunge()
            results.append((store_result, expunge_result))
        return results

    async def append_message(
        self,
        message: Union[MailMessage, bytes],
        folder: StrOrBytes = 'INBOX',
        dt: Optional[datetime] = None,
        flag_set: Optional[Union[str, Iterable[str]]] = None,
    ) -> Response:
        """
        Append email messages to server
        :param message: MailMessage object or bytes
        :param folder: destination folder, INBOX by default
        :param dt: email message datetime with tzinfo, now by default, imaplib.Time2Internaldate types supported
        :param flag_set: email message flags, no flags by default. System flags at consts.MailMessageFlags.all
        :return: command results
        """
        timezone = datetime.now().astimezone().tzinfo  # system timezone
        cleaned_flags = clean_flags(flag_set or [])
        return await self.append(
            message if type(message) is bytes else message.obj.as_bytes(),
            folder,
            f'({" ".join(cleaned_flags)})' if cleaned_flags else None,
            dt or datetime.now(timezone),
        )

    async def smart_status(self, folder: Optional[StrOrBytes] = None, options: Optional[Iterable[str]] = None) -> dict[str, int]:
        """
        Get the status of a folder
        :param folder: mailbox folder, current folder if None
        :param options: [str] with values from MailBoxFolderStatusOptions.all | None - for get all options
        :return: dict with available options keys
            example: {'MESSAGES': 41, 'RECENT': 0, 'UIDNEXT': 11996, 'UIDVALIDITY': 1, 'UNSEEN': 5}
        """
        if folder is None:
            folder = self.current_folder
        if not options:
            options = tuple(MailBoxFolderStatusOptions.all)
        for opt in options:
            if opt not in MailBoxFolderStatusOptions.all:
                raise MailboxFolderStatusValueError(str(opt))
        response = await self.protocol.simple_command(
            'STATUS', folder, f'({" ".join(options)})')
        line = response.lines.encode() if isinstance(response.lines, str) else response.lines
        command = self.protocol._untagged_response(line)
        status_data = [i for i in command.response.lines if type(i) is bytes][0]  # may contain tuples with encoded names
        values = status_data.decode().split('(')[-1].split(')')[0].split(' ')
        return {k: int(v) for k, v in pairs_to_dict(values).items() if str(v).isdigit()}

    async def smart_folder_list(
        self,
        folder: str = '',
        search_args: str = '*',
        subscribed_only: bool = False,
    ) -> list[FolderInfo]:
        """
        Get a listing of folders on the server
        :param folder: mailbox folder, if empty - get from root
        :param search_args: search arguments, is case-sensitive mailbox name with possible wildcards
            * is a wildcard, and matches zero or more characters at this position
            % is similar to * but it does not match a hierarchy delimiter
        :param subscribed_only: bool - get only subscribed folders
        :return: [FolderInfo]
        """
        folder_item_re = re.compile(r'\((?P<flags>[\S ]*?)\) (?P<delim>[\S]+) (?P<name>.+)')
        command = 'LSUB' if subscribed_only else 'LIST'
        response = await self.protocol.simple_command(command, folder, search_args),
        line = response.lines.encode() if isinstance(response.lines, str) else response.lines
        command = self.protocol._untagged_response(line)
        result = []
        for folder_item in command.response.result:
            if not folder_item:
                continue
            if type(folder_item) is bytes:
                folder_match = re.search(folder_item_re, utf7_decode(folder_item))
                if not folder_match:
                    continue
                folder_dict = folder_match.groupdict()
                name = folder_dict['name']
                if name.startswith('"') and name.endswith('"'):
                    name = name[1:-1]
            elif type(folder_item) is tuple:
                # when name has " or \ chars
                folder_match = re.search(folder_item_re, utf7_decode(folder_item[0]))
                if not folder_match:
                    continue
                folder_dict = folder_match.groupdict()
                name = utf7_decode(folder_item[1])
            else:
                continue
            result.append(FolderInfo(
                name=name.replace('\\"', '"'),
                delim=folder_dict['delim'].replace('"', ''),
                flags=tuple(folder_dict['flags'].split()),  # noqa
            ))
        return result


def extract_exists(response: Response) -> Optional[int]:
    for line in response.lines:
        if b'EXISTS' in line:
            return int(line.replace(b' EXISTS', b'').decode())


class IMAP4_SSL(IMAP4):
    def __init__(
        self,
        host: str = '127.0.0.1',
        port: int = IMAP4_SSL_PORT,
        *,
        timeout: float = IMAP4.TIMEOUT_SECONDS,
        loop: asyncio.AbstractEventLoop = None,
        conn_lost_cb: Callable[[Optional[Exception]], None] = None,
        proxy_url: str = None,
    ):
        self._proxy_url = proxy_url
        super().__init__(host, port, timeout=timeout, loop=loop, conn_lost_cb=conn_lost_cb)

    @property
    def proxy_url(self) -> str | None:
        return self._proxy_url

    async def connect(self, ssl_context: ssl.SSLContext = None):
        ssl_context = ssl_context or ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        sock = None
        if self._proxy_url:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            sock = await Proxy.from_url(self._proxy_url).connect(self.host, self.port)

        return await self.protocol.create_connection(self.host, self.port, ssl=ssl_context, sock=sock)


MailBoxUnencrypted = IMAP4
MailBox = IMAP4_SSL
# MailBoxTls = ...
