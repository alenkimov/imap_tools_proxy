# Lib author: Vladimir Kaukin <KaukinVK@ya.ru>
# Modified by: alenkimov <alen.kimov@gmail.com>
# License: Apache-2.0

from .query import AND, OR, NOT, Header, UidRange, A, O, N, H, U
from .mailbox import BaseMailBox, MailBox, MailBoxUnencrypted, MailBoxTls
from .message import MailMessage, MailAttachment
from .folder import MailBoxFolderManager, FolderInfo
from .consts import MailMessageFlags, MailBoxFolderStatusOptions, SortCriteria
from .utils import EmailAddress
from .errors import *
