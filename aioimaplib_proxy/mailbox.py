import re
import datetime
from collections import UserString
from typing import Optional, Iterable, Sequence, Union, Iterator

import imaplib
from . import aioimaplib
from .message import MailMessage
from .folder import MailBoxFolderManager
from .idle import IdleManager
from .consts import UID_PATTERN, MOVE_RESULT_TAG
from .utils import clean_uids, check_command_status, chunked, encode_folder, clean_flags, \
    chunked_crop
from .types import StrOrBytes
from .errors import MailboxStarttlsError, MailboxNumbersError, \
    MailboxFetchError, MailboxCopyError, MailboxFlagError, \
    MailboxAppendError, MailboxTaggedResponseError, MailboxMoveError


Criteria = Union[StrOrBytes, UserString]


class BaseMailBox:
    """Working with the email box"""

    email_message_class = MailMessage
    folder_manager_class = MailBoxFolderManager
    idle_manager_class = IdleManager

    def __init__(self):
        self.client: aioimaplib.IMAP4 = self._get_mailbox_client()
        self.folder = self.folder_manager_class(self)
        self.idle = self.idle_manager_class(self)
        self.login_result = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self.logout()

    def _get_mailbox_client(self) -> aioimaplib.IMAP4:
        raise NotImplementedError

    def consume_until_tagged_response(self, tag: bytes):
        """Waiting for tagged response"""
        tagged_commands = self.client.tagged_commands
        response_set = []
        while True:
            response: bytes = self.client._get_response()  # noqa, example: b'IJDH3 OK IDLE Terminated'
            if tagged_commands[tag]:
                break
            response_set.append(response)
        result = tagged_commands.pop(tag)
        check_command_status(result, MailboxTaggedResponseError)
        return result, response_set

    async def login(self, username: str, password: str, initial_folder: Optional[str] = 'INBOX') -> 'BaseMailBox':
        """Authenticate to account"""
        login_result = await self.client.login(username, password)
        if initial_folder is not None:
            self.folder.set(initial_folder)
        self.login_result = login_result
        return self  # return self in favor of context manager

    # todo
    # def login_utf8(self, username: str, password: str, initial_folder: Optional[str] = 'INBOX') -> 'BaseMailBox':
    #     """Authenticate to an account with a UTF-8 username and/or password"""
    #     # rfc2595 section 6 - PLAIN SASL mechanism
    #     encoded = (b"\0" + username.encode("utf8") + b"\0" + password.encode("utf8"))
    #     # Assumption is the server supports AUTH=PLAIN capability
    #     login_result = self.client.authenticate("PLAIN", lambda x: encoded)
    #     check_command_status(login_result, MailboxLoginError)
    #     if initial_folder is not None:
    #         self.folder.set(initial_folder)
    #     self.login_result = login_result
    #     return self

    async def xoauth2(self, username: str, access_token: str, initial_folder: Optional[str] = 'INBOX') -> 'BaseMailBox':
        """Authenticate to account using OAuth 2.0 mechanism"""
        result = await self.client.xoauth2(username, access_token)
        if initial_folder is not None:
            await self.folder.set(initial_folder)
        self.login_result = result
        return self

    async def logout(self) -> tuple:
        """Informs the server that the client is done with the connection"""
        return await self.client.logout()

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
        search_result = await self.client.search(encoded_criteria, charset)
        check_command_status(search_result, MailboxNumbersError)
        return search_result[1][0].decode().split() if search_result[1][0] else []

    async def numbers_to_uids(self, numbers: list[str]) -> list[str]:
        """Get message uids by message numbers"""
        if not numbers:
            return []
        fetch_result = await self.client.fetch(','.join(numbers), "(UID)")
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
        sort: Optional[Union[str, Iterable[str]]] = None,
    ) -> list[str]:
        """
        Search mailbox for matching message uids in current folder
        :param criteria: message search criteria (see examples at ./doc/imap_search_criteria.txt)
        :param charset: IANA charset, indicates charset of the strings that appear in the search criteria. See rfc2978
        :param sort: criteria for sort messages on server, use SortCriteria constants. Charset arg is important for sort
        :return: email message uids
        """
        encoded_criteria = criteria if type(criteria) is bytes else str(criteria).encode(charset)
        if sort:
            sort = (sort,) if isinstance(sort, str) else sort
            uid_result = await self.client.uid('SORT', f'({" ".join(sort)})', charset, encoded_criteria)
        else:
            uid_result = self.client.uid('SEARCH', 'CHARSET', charset, encoded_criteria)  # *charset are opt here

        return uid_result[1][0].decode().split() if uid_result[1][0] else []

    async def _fetch_by_one(self, uid_list: Sequence[str], message_parts: str) -> Iterator[list]:
        for uid in uid_list:
            fetch_result = await self.client.uid('FETCH', uid, message_parts)
            check_command_status(fetch_result, MailboxFetchError)
            if not fetch_result[1] or fetch_result[1][0] is None:
                continue
            yield fetch_result[1]

    async def _fetch_in_bulk(
        self,
        uid_list: Sequence[str],
        message_parts: str,
        reverse: bool,
        bulk: int,
    ) -> Iterator[list]:
        if not uid_list:
            return

        if isinstance(bulk, int) and bulk >= 2:
            uid_list_seq = chunked_crop(uid_list, bulk)
        elif isinstance(bulk, bool):
            uid_list_seq = (uid_list,)
        else:
            raise ValueError('bulk arg may be bool or int >= 2')

        for uid_list_i in uid_list_seq:
            fetch_result = await self.client.uid('FETCH', ','.join(uid_list_i), message_parts)
            if not fetch_result[1] or fetch_result[1][0] is None:
                return
            for built_fetch_item in chunked((reversed if reverse else iter)(fetch_result[1]), 2):
                yield built_fetch_item

    async def fetch(
        self,
        criteria: Criteria = 'ALL',
        charset: str = 'US-ASCII',
        limit: Optional[Union[int, slice]] = None,
        mark_seen=True,
        reverse=False,
        headers_only=False,
        bulk: Union[bool, int] = False,
        sort: Optional[Union[str, Iterable[str]]] = None,
    ) -> Iterator[MailMessage]:
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
        uids = tuple((reversed if reverse else iter)(await self.uids(criteria, charset, sort)))[limit_range]
        if bulk:
            message_generator = self._fetch_in_bulk(uids, message_parts, reverse, bulk)
        else:
            message_generator = self._fetch_by_one(uids, message_parts)
        for fetch_item in message_generator:
            yield self.email_message_class(fetch_item)

    async def expunge(self):
        return await self.client.expunge()

    async def delete(
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
            store_result = await self.client.uid('STORE', ','.join(cleaned_uid_list_i), '+FLAGS', r'(\Deleted)')
            expunge_result = await self.expunge()
            results.append((store_result, expunge_result))
        return results

    async def copy(
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
            copy_result = self.client.uid(
                'COPY', ','.join(cleaned_uid_list_i), encode_folder(destination_folder))  # noqa
            results.append(copy_result)
        return results

    def move(self, uid_list: Union[str, Iterable[str]], destination_folder: StrOrBytes, chunks: Optional[int] = None) \
            -> Optional[list[tuple[tuple, tuple]]]:
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
        if 'MOVE' in self.client.capabilities:
            # server side move
            results = []
            for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
                move_result = self.client.uid(
                    'MOVE', ','.join(cleaned_uid_list_i), encode_folder(destination_folder))  # noqa
                check_command_status(move_result, MailboxMoveError)
                results.append((move_result, MOVE_RESULT_TAG))
            return results
        else:
            # client side move
            results = []
            for cleaned_uid_list_i in chunked_crop(cleaned_uid_list, chunks):
                copy_result = self.copy(cleaned_uid_list_i, destination_folder)
                delete_result = self.delete(cleaned_uid_list_i)
                results.append((copy_result, delete_result))
            return results

    def flag(self, uid_list: Union[str, Iterable[str]], flag_set: Union[str, Iterable[str]], value: bool,
             chunks: Optional[int] = None) -> Optional[List[Tuple[tuple, tuple]]]:
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
            store_result = self.client.uid(
                'STORE',
                ','.join(cleaned_uid_list_i),
                ('+' if value else '-') + 'FLAGS',
                f'({" ".join(clean_flags(flag_set))})'
            )
            check_command_status(store_result, MailboxFlagError)
            expunge_result = self.expunge()
            results.append((store_result, expunge_result))
        return results

    def append(self, message: Union[MailMessage, bytes],
               folder: StrOrBytes = 'INBOX',
               dt: Optional[datetime.datetime] = None,
               flag_set: Optional[Union[str, Iterable[str]]] = None) -> tuple:
        """
        Append email messages to server
        :param message: MailMessage object or bytes
        :param folder: destination folder, INBOX by default
        :param dt: email message datetime with tzinfo, now by default, imaplib.Time2Internaldate types supported
        :param flag_set: email message flags, no flags by default. System flags at consts.MailMessageFlags.all
        :return: command results
        """
        timezone = datetime.datetime.now().astimezone().tzinfo  # system timezone
        cleaned_flags = clean_flags(flag_set or [])
        typ, dat = self.client.append(
            encode_folder(folder),  # noqa
            f'({" ".join(cleaned_flags)})' if cleaned_flags else None,
            dt or datetime.datetime.now(timezone),  # noqa
            message if type(message) is bytes else message.obj.as_bytes()
        )
        append_result = (typ, dat)
        check_command_status(append_result, MailboxAppendError)
        return append_result


class MailBoxUnencrypted(BaseMailBox):
    """Working with the email box through IMAP4"""

    def __init__(self, host='', port=143, timeout=None):
        """
        :param host: host's name (default: localhost)
        :param port: port number
        :param timeout: timeout in seconds for the connection attempt, since python 3.9
        """
        self._host = host
        self._port = port
        self._timeout = timeout
        super().__init__()

    def _get_mailbox_client(self) -> aioimaplib.IMAP4:
        return aioimaplib.IMAP4(self._host, self._port, timeout=self._timeout)


class MailBox(BaseMailBox):
    """Working with the email box through IMAP4 over SSL connection"""

    def __init__(self, host='', port=993, timeout=None, keyfile=None, certfile=None, ssl_context=None):
        """
        :param host: host's name (default: localhost)
        :param port: port number
        :param timeout: timeout in seconds for the connection attempt, since python 3.9
        :param keyfile: PEM formatted file that contains your private key (deprecated)
        :param certfile: PEM formatted certificate chain file (deprecated)
        :param ssl_context: SSLContext object that contains your certificate chain and private key
        Since Python 3.9 timeout argument added
        Since Python 3.12 keyfile and certfile arguments are deprecated, ssl_context and timeout must be keyword args
        """
        self._host = host
        self._port = port
        self._timeout = timeout
        self._keyfile = keyfile
        self._certfile = certfile
        self._ssl_context = ssl_context
        super().__init__()

    def _get_mailbox_client(self) -> aioimaplib.IMAP4:
        return aioimaplib.IMAP4_SSL(self._host, self._port, ssl_context=self._ssl_context, timeout=self._timeout)


class MailBoxTls(BaseMailBox):
    """Working with the email box through IMAP4 with STARTTLS"""

    def __init__(self, host='', port=993, timeout=None, ssl_context=None):
        """
        :param host: host's name (default: localhost)
        :param port: port number
        :param timeout: timeout in seconds for the connection attempt, since python 3.9
        :param ssl_context: SSLContext object that contains your certificate chain and private key
        """
        self._host = host
        self._port = port
        self._timeout = timeout
        self._ssl_context = ssl_context
        super().__init__()

    def _get_mailbox_client(self) -> aioimaplib.IMAP4:
        client = aioimaplib.IMAP4(self._host, self._port, timeout=self._timeout)
        result = client.starttls(self._ssl_context)
        check_command_status(result, MailboxStarttlsError)
        return client
