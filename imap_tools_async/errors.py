from typing import TYPE_CHECKING

from .consts import MAXLINE

if TYPE_CHECKING:
    from .command import Command


class ImapError(Exception):
    """Base lib error"""


class Error(ImapError):
    def __init__(self, reason: str):
        super().__init__(reason)


class Abort(Error):
    def __init__(self, reason: str):
        super().__init__(reason)


class CommandTimeout(ImapError):
    def __init__(self, command: "Command"):
        self.command = command


class IncompleteRead(ImapError):
    def __init__(self, command: "Command", data: bytes = b''):
        self.command = command
        self.data = data


class IncorrectRamblerPassword(ImapError):
    """
    IMAP password contains '%' character. Change your password.
    It's a specific rambler.ru error
    """
    def __init__(self, password: str):
        self.password = password
        super().__init__("IMAP password contains '%' character."
                         " Change your password."
                         " It's a specific rambler.ru error")



class MaxResponseLineReachedError(ImapError):
    """Exception raised when the received line exceeds the maximum allowed length."""
    def __init__(self, data: bytes):
        self.data = data
        super().__init__(f"Received line exceeds maximum allowed length ({MAXLINE} bytes)")


class MailboxFolderStatusValueError(ImapError):
    """Wrong folder status value error"""


class UnexpectedCommandStatusError(ImapError):
    """Unexpected status in IMAP command response"""

    def __init__(
        self,
        command: "Command",
    ):
        """
        :param command: imap command with result
        """
        self.command = command

    def __str__(self):
        return (f'[{self.command.name}]'
                f' Response status "{self.command.expected_response_status}" expected,'
                f' but "{self.command.response.result}" received.'
                f' Data: {str(self.command.response.lines)}')
