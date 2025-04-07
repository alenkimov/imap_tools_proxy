import re
import datetime
from itertools import zip_longest
from email.utils import getaddresses, parsedate_to_datetime
from email.header import decode_header, Header
from typing import Union, Optional, Iterable, Any, Iterator, Sequence

from .consts import SHORT_MONTH_NAMES
from .consts import ID_MAX_PAIRS_COUNT
from .consts import ID_MAX_FIELD_LEN
from .consts import ID_MAX_VALUE_LEN
from .enums import MessageFlags
from .types import StrOrBytes
from .imap_utf7 import utf7_encode


def clean_uids(uids: Union[str, Iterable[str]]) -> list[str]:
    """
    Prepare set of uid for use in IMAP commands
    uid RE patterns are not strict and allow invalid combinations, but simple. Example: 2,4:7,9,12:*
    :param uids:
        str, that is comma separated uids
        Iterable, that contains str uids
    :return: list of str - cleaned uids
    """
    # str
    if type(uids) is str:
        if re.search(r'^([\d*:]+,)*[\d*:]+$', uids):  # *optimization for already good str
            return uids.split(',')
        uids = uids.split(',')
    # check uid types
    for uid in uids:
        if type(uid) is not str:
            raise TypeError(f'uid "{str(uid)}" is not string')
        if not re.match(r'^[\d*:]+$', uid.strip()):
            raise TypeError(f'Wrong uid: "{uid}"')
    return [i.strip() for i in uids]


def join_uids(uids: Iterable[str]):
    """Convert a sequence of messages ids or a single integer message id
    into an id byte string for use with IMAP commands
    """
    return ','.join(uids)

def normalise_sort_criteria(criteria: str | Iterable[str]):
    criteria = (criteria,) if isinstance(criteria, str) else criteria
    return f'({" ".join(item.upper() for item in criteria)})'


# imaplib.IMAP4._quote()
def quoted(arg: str) -> str:
    """ Given a string, return a quoted string as per RFC 3501, section 9.

        Implementation copied from https://github.com/mjs/imapclient
        (imapclient/imapclient.py), 3-clause BSD license
    """
    arg = arg.replace('\\', '\\\\')
    arg = arg.replace('"', '\\"')
    return '"' + arg + '"'


def arguments_rfs2971(**kwargs: Union[dict, list, str]) -> Union[dict, list]:
    if kwargs:
        if len(kwargs) > ID_MAX_PAIRS_COUNT:
            raise ValueError('Must not send more than 30 field-value pairs')
        args = ['(']
        for field, value in kwargs.items():
            field = quoted(str(field))
            value = quoted(str(value)) if value is not None else 'NIL'
            if len(field) > ID_MAX_FIELD_LEN:
                raise ValueError(f'Field: {field} must not be longer than 30')
            if len(value) > ID_MAX_VALUE_LEN:
                raise ValueError(f'Field: {field} value: {value} must not be longer than 1024')
            args.extend((field, value))
        args.append(')')
    else:
        args = ['NIL']
    return args


def decode_value(value: StrOrBytes, encoding: Optional[str] = None) -> str:
    """Converts value to utf-8 encoding"""
    if isinstance(encoding, str):
        encoding = encoding.lower()
    if isinstance(value, bytes):
        try:
            return value.decode(encoding or 'utf-8', 'ignore')
        except LookupError:  # unknown encoding
            return value.decode('utf-8', 'ignore')
    return value


class EmailAddress:
    """Parsed email address info"""
    __slots__ = 'name', 'email'

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email

    @property
    def full(self):
        return f'{self.name} <{self.email}>' if self.name and self.email else self.name or self.email

    def __repr__(self):
        return f"{self.__class__.__name__}(name={repr(self.name)}, email={repr(self.email)})"

    def __eq__(self, other):
        return all(getattr(self, i) == getattr(other, i) for i in self.__slots__)


def remove_non_printable(value: str) -> str:
    """Remove non-printable character from value"""
    return ''.join(i for i in value if i.isprintable())


def parse_email_addresses(raw_header: Union[str, Header]) -> tuple[EmailAddress, ...]:
    """
    Parse email addresses from header
    :param raw_header: example: '=?UTF-8?B?0J7Qu9C1=?= <name@company.ru>,\r\n "\'\\"z, z\\"\'" <imap.tools@ya.ru>'
    :return: (EmailAddress, ...)
    """
    result = []
    if type(raw_header) is Header:
        raw_header = decode_value(*decode_header(raw_header)[0])
    for raw_name, email in getaddresses([remove_non_printable(raw_header)]):
        name = decode_value(*decode_header(raw_name)[0]).strip()
        email = email.strip()
        if not (name or email):
            continue
        result.append(EmailAddress(
            name=name or (email if '@' not in email else ''),
            email=email if '@' in email else '',
        ))
    return tuple(result)


def parse_email_date(value: str) -> datetime.datetime:
    """
    Parsing the date described in rfc2822
    Result datetime may be naive or with tzinfo
    1900-1-1 for unparsed
    """
    try:
        return parsedate_to_datetime(value)
    except Exception:  # noqa
        pass
    match = re.search(
        r'(?P<date>\d{1,2}\s+(' + '|'.join(SHORT_MONTH_NAMES) + r')\s+\d{4})\s+' +
        r'(?P<time>\d{1,2}:\d{1,2}(:\d{1,2})?)\s*' +
        r'(?P<zone_sign>[+-])?(?P<zone>\d{4})?',
        value
    )
    if match:
        group = match.groupdict()
        day, month, year = group['date'].split()
        time_values = group['time'].split(':')
        zone_sign = int(f'{group.get("zone_sign") or "+"}1')
        zone = group['zone']
        try:
            return datetime.datetime(
                year=int(year),
                month=SHORT_MONTH_NAMES.index(month) + 1,
                day=int(day),
                hour=int(time_values[0]),
                minute=int(time_values[1]),
                second=int(time_values[2]) if len(time_values) > 2 else 0,
                tzinfo=datetime.timezone(datetime.timedelta(
                    hours=int(zone[:2]) * zone_sign,
                    minutes=int(zone[2:]) * zone_sign
                )) if zone else None,
            )
        except ValueError:
            pass
    return datetime.datetime(1900, 1, 1)


def quote(value: StrOrBytes) -> StrOrBytes:
    if isinstance(value, str):
        return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
    else:
        return b'"' + value.replace(b'\\', b'\\\\').replace(b'"', b'\\"') + b'"'


# function from imaplib
def int2ap(num) -> str:
    """Convert integer to A-P string representation."""
    val = ''
    ap = 'ABCDEFGHIJKLMNOP'
    num = int(abs(num))
    while num:
        num, mod = divmod(num, 16)
        val += ap[mod:mod + 1]
    return val


def pairs_to_dict(items: list[Any]) -> dict[Any, Any]:
    """Example: ['MESSAGES', '3', 'UIDNEXT', '4'] -> {'MESSAGES': '3', 'UIDNEXT': '4'}"""
    if len(items) % 2 != 0:
        raise ValueError('An even-length array is expected')
    return dict((items[i * 2], items[i * 2 + 1]) for i in range(len(items) // 2))


def encode_folder(folder: StrOrBytes) -> bytes:
    """Encode folder name"""
    if isinstance(folder, bytes):
        return folder
    else:
        return quote(utf7_encode(folder))


def clean_flags(flag_set: Union[str, Iterable[str]]) -> list[str]:
    """
    Check the correctness of the flags
    :return: list of str - flags
    """
    if type(flag_set) is str:
        flag_set = [flag_set]
    upper_sys_flags = tuple(i.upper() for i in list(MessageFlags))
    for flag in flag_set:
        if not type(flag) is str:
            raise ValueError(f'Flag - str value expected, but {type(flag_set)} received')
        if flag.upper() not in upper_sys_flags and flag.startswith('\\'):
            raise ValueError('Non system flag must not start with "\\"')
    return flag_set


def replace_html_ct_charset(html: str, new_charset: str) -> str:
    """Replace charset in META tag with content-type attribute in HTML text"""
    meta_ct_match = re.search(r'<\s*meta .*?content-type.*?>', html, re.IGNORECASE | re.DOTALL)
    if meta_ct_match:
        meta = meta_ct_match.group(0)
        meta_new = re.sub(
            pattern=r'charset\s*=\s*[a-zA-Z0-9_:.+-]+',
            repl=f'charset={new_charset}',
            string=meta,
            count=1,
            flags=re.IGNORECASE
        )
        html = html.replace(meta, meta_new)
    return html


def chunked(iterable: Iterable[Any], n: int, fill_value: Optional[Any] = None) -> Iterator[tuple[Any, ...]]:
    """
    Group data into fixed-length chunks or blocks
        [iter(iterable)]*n creates one iterator, repeated n times in the list
        izip_longest then effectively performs a round-robin of "each" (same) iterator
    Examples:
        chunked('ABCDEFGH', 3, '?') --> [('A', 'B', 'C'), ('D', 'E', 'F'), ('G', 'H', '?')]
        chunked([1, 2, 3, 4, 5], 2) --> [(1, 2), (3, 4), (5, None)]
    """
    return zip_longest(*[iter(iterable)] * n, fillvalue=fill_value)


def chunked_crop(seq: Sequence, chunk_size: Optional[int]) -> Iterator[list]:
    """
    Yield successive n-sized chunks from seq.
    Yield seq if chunk_size is False-like
    :param seq: Sequence to chunks
    :param chunk_size: chunk size
    :return: Iterator
    import pprint
    pprint.pprint(list(chunked_crop(range(10, 75), 10)))
    [[10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
     [20, 21, 22, 23, 24, 25, 26, 27, 28, 29],
     [30, 31, 32, 33, 34, 35, 36, 37, 38, 39],
     [40, 41, 42, 43, 44, 45, 46, 47, 48, 49],
     [50, 51, 52, 53, 54, 55, 56, 57, 58, 59],
     [60, 61, 62, 63, 64, 65, 66, 67, 68, 69],
     [70, 71, 72, 73, 74]]
    """
    if not chunk_size:
        yield seq
        return
    if chunk_size < 0:
        raise ValueError('False-like or int>=0 expected')
    for i in range(0, len(seq), chunk_size):
        yield seq[i:i + chunk_size]
