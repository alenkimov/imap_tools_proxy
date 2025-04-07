from typing import TYPE_CHECKING

from .consts import MAXLINE

if TYPE_CHECKING:
    from .command import Command


class IMAPClientError(Exception):
    """
    Logical error
    """


# todo unobvious error. delete it
class AbortError(IMAPClientError):
    """
    Service error
    """


class UnsupportedCapability(IMAPClientError):
    """
    The command tried by the user needs a capability not installed
    on the IMAP server
    """
    def __init__(self, capability: str):
        self.capability = capability
        super().__init__(f"Server does not support '{capability}' capability")


# class LoginError(IMAPClientError):
#     """
#     A connection has been established with the server but an error
#     occurred during the authentication.
#     """


# class IllegalStateError(IMAPClientError):
#     """
#     The command tried needs a different state to be executed. This
#     means the user is not logged in or the command needs a folder to
#     be selected.
#     """


# class InvalidCriteriaError(IMAPClientError):
#     """
#     A command using a search criteria failed, probably due to a syntax
#     error in the criteria string.
#     """


# class ProtocolError(IMAPClientError):
#     """The server replied with a response that violates the IMAP protocol."""


class CommandTimeout(IMAPClientError):
    def __init__(self, command: "Command"):
        self.command = command


class IncompleteRead(IMAPClientError):
    def __init__(self, command: "Command", data: bytes = b''):
        self.command = command
        self.data = data


class IncorrectRamblerPassword(IMAPClientError):
    """
    IMAP password contains '%' character. Change your password.
    It's a specific rambler.ru error
    """
    def __init__(self, password: str):
        self.password = password
        super().__init__("IMAP password contains '%' character."
                         " Change your password."
                         " It's a specific rambler.ru error")


class MaxResponseDataLengthReached(IMAPClientError):
    """Received response data exceeds the maximum allowed length."""
    def __init__(self, data: bytes):
        self.data = data
        super().__init__(f"Received data exceeds maximum allowed length ({MAXLINE} bytes)")


class UnexpectedCommandStatus(IMAPClientError):
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
                f' Response status: "{self.command.response.result}".'
                f' Data: {str(self.command.response.lines)}')
