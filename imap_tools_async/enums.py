from enum import StrEnum


class MessageFlags(StrEnum):
    """
    System email message flags
    All system flags begin with "\"
    """
    SEEN     = '\\Seen'
    ANSWERED = '\\Answered'
    FLAGGED  = '\\Flagged'
    DELETED  = '\\Deleted'
    DRAFT    = '\\Draft'
    RECENT   = '\\Recent'


class FolderStatus(StrEnum):
    """Valid mailbox folder status options"""
    MESSAGES    = 'MESSAGES'
    RECENT      = 'RECENT'
    UIDNEXT     = 'UIDNEXT'
    UIDVALIDITY = 'UIDVALIDITY'
    UNSEEN      = 'UNSEEN'


class SortCriteria(StrEnum):
    """
    Sort criteria
    https://datatracker.ietf.org/doc/html/rfc5256
    ARRIVAL - Internal date and time of the message.
        This differs from the ON criteria in SEARCH, which uses just the internal date.
    CC - [IMAP] addr-mailbox of the first "cc" address.
    DATE - Sent date and time, as described in section 2.2.
    FROM - [IMAP] addr-mailbox of the first "From" address.
    SIZE - Size of the message in octets.
    SUBJECT - Base subject text.
    TO - [IMAP] addr-mailbox of the first "To" address.
    """
    ARRIVAL_DT_ASC = 'ARRIVAL'
    CC_ASC         = 'CC'
    DATE_ASC       = 'DATE'
    FROM_ASC       = 'FROM'
    SIZE_ASC       = 'SIZE'
    SUBJECT_ASC    = 'SUBJECT'
    TO_ASC         = 'TO'

    ARRIVAL_DT_DESC = 'REVERSE ARRIVAL'
    CC_DESC         = 'REVERSE CC'
    DATE_DESC       = 'REVERSE DATE'
    FROM_DESC       = 'REVERSE FROM'
    SIZE_DESC       = 'REVERSE SIZE'
    SUBJECT_DESC    = 'REVERSE SUBJECT'
    TO_DESC         = 'REVERSE TO'
