from typing import Any
from .consts import MAXLINE
from .types import Response


class ImapToolsError(Exception):
    """Base lib error"""


class IncorrectRamblerPassword(ImapToolsError):
    """
    if host == "imap.rambler.ru" and "%" in password:
        raise IncorrectRamblerPassword(
            "IMAP password contains '%' character. Change your password."
            " It's a specific rambler.ru error"
        )
    """
    pass


class MaxResponseLineReachedError(ImapToolsError):
    """Exception raised when the received line exceeds the maximum allowed length."""
    def __init__(self, data: bytes):
        self.data = data
        super().__init__(f"Received line exceeds maximum allowed length ({MAXLINE} bytes)")


class MailboxFolderStatusValueError(ImapToolsError):
    """Wrong folder status value error"""


class UnexpectedCommandStatusError(ImapToolsError):
    """Unexpected status in IMAP command response"""

    def __init__(self, response: Response, expected: Any):
        """
        :param response: imap command result
        :param expected: expected command status
        """
        self.command_result = response
        self.expected = expected

    def __str__(self):
        return (f'Response status "{self.expected}" expected, '
                f'but "{self.command_result[0]}" received. Data: {str(self.command_result[1])}')


class MailboxFolderSelectError(UnexpectedCommandStatusError):
    pass


class MailboxFolderCreateError(UnexpectedCommandStatusError):
    pass


class MailboxFolderRenameError(UnexpectedCommandStatusError):
    pass


class MailboxFolderDeleteError(UnexpectedCommandStatusError):
    pass


class MailboxFolderStatusError(UnexpectedCommandStatusError):
    pass


class MailboxFolderSubscribeError(UnexpectedCommandStatusError):
    pass


class MailboxLoginError(UnexpectedCommandStatusError):
    pass


class MailboxLogoutError(UnexpectedCommandStatusError):
    pass


class MailboxNumbersError(UnexpectedCommandStatusError):
    pass


class MailboxStarttlsError(UnexpectedCommandStatusError):
    pass


class MailboxFetchError(UnexpectedCommandStatusError):
    pass


class MailboxExpungeError(UnexpectedCommandStatusError):
    pass


class MailboxDeleteError(UnexpectedCommandStatusError):
    pass


class MailboxCopyError(UnexpectedCommandStatusError):
    pass


class MailboxMoveError(UnexpectedCommandStatusError):
    pass


class MailboxFlagError(UnexpectedCommandStatusError):
    pass


class MailboxAppendError(UnexpectedCommandStatusError):
    pass


class MailboxTaggedResponseError(UnexpectedCommandStatusError):
    pass
