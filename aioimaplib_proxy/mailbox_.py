import asyncio
from datetime import datetime, timedelta
from typing import Literal
from email import message_from_bytes
from email.utils import parsedate_to_datetime
import re
import pytz
from better_imap.utils import get_service_by_email_address
from better_proxy import Proxy
from .imap import IMAP4_SSL_PROXY
from .errors import IMAPSearchTimeout, IMAPLoginFailed
from .models import EmailMessage, ServiceType
from .utils import extract_email_text


class MailBox:
    DEDAULT_FOLDER_NAMES = ["INBOX", "Junk", "Spam"]

    def __init__(
        self,
        address: str,
        password: str,
        *,
        service: ServiceType = None,
        proxy: Proxy | None = None,
        timeout: float = 10,
        loop: asyncio.AbstractEventLoop = None,
    ):
        if not service:
            service = get_service_by_email_address(address)

        if service.host == "imap.rambler.ru" and "%" in password:
            raise ValueError(
                f"IMAP password contains '%' character. Change your password."
                f" It's a specific rambler.ru error"
            )
        self._address = address
        self._password = password
        self._service = service
        self._connected = False
        self._imap = IMAP4_SSL_PROXY(
            host=service.host,
            proxy=proxy,
            timeout=timeout,
            loop=loop,
        )

    async def __aenter__(self):
        await self.login()
        return self

    async def __aexit__(self, *args):
        await self.logout()

    async def logout(self):
        await self._imap.logout()

    async def login(self):
        if self._connected:
            return
        await self._imap.wait_hello_from_server()
        await self._imap.login(self._address, self._password)
        if self._imap.get_state() == "NONAUTH":
            raise IMAPLoginFailed()
        self._connected = True

    async def _select(self, folder: str):
        try:
            await self._imap.select(mailbox=folder)
            if self._imap.get_state() == "AUTH":
                raise IMAPLoginFailed()
        except TimeoutError:
            raise IMAPLoginFailed("Timeout")

    async def get_message_by_id(self, msg_id) -> EmailMessage:
        typ, msg_data = await self._imap.fetch(msg_id, "(RFC822)")
        if typ == "OK":
            email_bytes = bytes(msg_data[1])
            email_message = message_from_bytes(email_bytes)
            email_sender = email_message.get("from")
            email_receiver = email_message.get("to")
            subject = email_message.get("subject")
            email_date = parsedate_to_datetime(email_message.get("date"))
            if email_date.tzinfo is None:
                email_date = pytz.utc.localize(email_date)
            elif email_date.tzinfo != pytz.utc:
                email_date = email_date.astimezone(pytz.utc)
            message_text = extract_email_text(email_message)
            return EmailMessage(
                text=message_text,
                date=email_date,
                sender=email_sender,
                receiver=email_receiver,
                subject=subject,
            )

    async def fetch_messages(
        self,
        folders: list[str] | None = None,
        *,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        since: datetime | None = None,
        allowed_senders: list[str] = None,
        allowed_receivers: list[str] = None,
        sender_regex: str | re.Pattern[str] = None,
    ) -> list[EmailMessage]:
        await self.login()
        folders = folders or self.DEDAULT_FOLDER_NAMES
        all_messages = []
        additional_criteria = ""
        if since:
            date_filter = since.strftime("%d-%b-%Y")
            additional_criteria += f" SINCE {date_filter}"
        if allowed_senders:
            senders_criteria = " ".join(f'FROM "{s}"' for s in allowed_senders)
            additional_criteria += f" {senders_criteria}"
        if allowed_receivers:
            receivers_criteria = " ".join(f'TO "{r}"' for r in allowed_receivers)
            additional_criteria += f" {receivers_criteria}"
        for folder in folders:
            await self._select(folder)
            final_search_criteria = f"{search_criteria}{additional_criteria}".strip()
            status, data = await self._imap.search(
                final_search_criteria, charset=self._service.encoding
            )
            if status != "OK" or not data or not data[0]:
                continue
            email_ids = data[0].split()[::-1]
            for e_id_str in email_ids:
                msg_id = e_id_str.decode(self._service.encoding)
                message = await self.get_message_by_id(msg_id)
                if not message:
                    continue
                if since and message.date < since:
                    continue
                if sender_regex and not re.search(
                    sender_regex, message.sender, re.IGNORECASE
                ):
                    continue
                all_messages.append(message)
        return all_messages

    async def search_matches(
        self,
        regex: str | re.Pattern[str],
        folders: list[str] | None = None,
        *,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        since: datetime = None,
        hours_offset: int | None = None,
        allowed_senders: list[str] = None,
        allowed_receivers: list[str] = None,
        sender_regex: str | re.Pattern[str] = None,
        return_latest: bool = False,
    ) -> str | list[str] | None:
        await self.login()
        if since is None:
            if hours_offset is None:
                since = datetime.now(pytz.utc) - timedelta(hours=hours_offset)
        folders = folders or self.DEDAULT_FOLDER_NAMES
        temp_matches = []
        messages = await self.fetch_messages(
            folders,
            search_criteria=search_criteria,
            since=since,
            allowed_senders=allowed_senders,
            allowed_receivers=allowed_receivers,
            sender_regex=sender_regex,
        )
        for message in messages:
            found = re.findall(regex, message.text)
            if found:
                temp_matches.append((message.date, found[0]))
        temp_matches.sort(key=lambda x: x[0], reverse=True)
        if not temp_matches:
            if return_latest:
                return None
            return []
        if return_latest:
            return temp_matches[0][1]
        return [m[1] for m in temp_matches]

    async def search_match(
        self,
        regex: str | re.Pattern[str],
        folders: list[str] | None = None,
        *,
        search_criteria: Literal["ALL", "UNSEEN"] = "ALL",
        since: datetime = None,
        hours_offset: int = 24,
        allowed_senders: list[str] = None,
        allowed_receivers: list[str] = None,
        sender_regex: str | re.Pattern[str] = None,
    ) -> str | None:
        result = await self.search_matches(
            regex,
            folders=folders,
            search_criteria=search_criteria,
            since=since,
            hours_offset=hours_offset,
            allowed_senders=allowed_senders,
            allowed_receivers=allowed_receivers,
            sender_regex=sender_regex,
            return_latest=True,
        )
        return result

    async def search_with_retry(
        self,
        regex: str | re.Pattern[str],
        folders: list[str] | None = None,
        *,
        allowed_senders: list[str] = None,
        allowed_receivers: list[str] = None,
        sender_email_regex: str | re.Pattern[str] = None,
        since: datetime = None,
        interval: int = 5,
        timeout: int = 90,
    ) -> str | None:
        end_time = asyncio.get_event_loop().time() + timeout
        if since is None:
            since = datetime.now(pytz.utc) - timedelta(seconds=15)
        folders = folders or self.DEDAULT_FOLDER_NAMES
        while asyncio.get_event_loop().time() < end_time:
            match = await self.search_match(
                regex,
                folders=folders,
                allowed_senders=allowed_senders,
                allowed_receivers=allowed_receivers,
                sender_regex=sender_email_regex,
                since=since,
            )
            if match:
                return match
            await asyncio.sleep(interval)
        raise IMAPSearchTimeout(f"No email received within {timeout} seconds")
