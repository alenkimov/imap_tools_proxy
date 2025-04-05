import re

SHORT_MONTH_NAMES = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')

UID_PATTERN = re.compile(r'(^|\s+|\W)UID\s+(?P<uid>\d+)')

CODECS_OFFICIAL_REPLACEMENT_CHAR = '�'

MOVE_RESULT_TAG = ('_MOVE',)  # const delete_result part for mailbox.move result, when server have MOVE in capabilities

# to avoid imap servers to kill the connection after 30mn idling
# cf https://www.imapwiki.org/ClientImplementation/Synchronization
TWENTY_NINE_MINUTES = 29 * 60

STOP_WAIT_SERVER_PUSH = [b'stop_wait_server_push']

IMAP4_PORT = 143
IMAP4_SSL_PORT = 993
STARTED, CONNECTED, NONAUTH, AUTH, SELECTED, LOGOUT = 'STARTED', 'CONNECTED', 'NONAUTH', 'AUTH', 'SELECTED', 'LOGOUT'
CRLF = b'\r\n'

# Maximal line length. This is to prevent reading arbitrary length lines.
# 20Mb is enough for search response with about 2 000 000 message numbers
MAXLINE = 20 * 1024 * 1024  # 20Mb

ID_MAX_PAIRS_COUNT = 30
ID_MAX_FIELD_LEN = 30
ID_MAX_VALUE_LEN = 1024

ALLOWED_IMAP_VERSIONS = ('IMAP4REV1', 'IMAP4')
