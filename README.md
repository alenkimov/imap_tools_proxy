# imapclient-async

[![Telegram channel](https://img.shields.io/endpoint?color=neon&url=https://tg.sumanjay.workers.dev/cum_insider)](https://t.me/cum_insider)
[![PyPI version info](https://img.shields.io/pypi/v/imapclient-async.svg)](https://pypi.python.org/pypi/imapclient-async)
[![PyPI supported Python versions](https://img.shields.io/pypi/pyversions/imapclient-async.svg)](https://pypi.python.org/pypi/imapclient-async)
[![PyPI downloads per month](https://img.shields.io/pypi/dm/imapclient-async.svg)](https://pypi.python.org/pypi/imapclient-async)

Modern async IMAP4 client.

Special thanks:

- [aioimaplib](https://github.com/iroco-co/aioimaplib)
- [imap-tools](https://github.com/ikvk/imap_tools)
- [imapclient](https://github.com/mjs/imapclient)

## Key features
- Async
- Only one dependency, python-socks, which provides support for http and socks proxies
- Catching a specific `imap.rambler.ru` login error if password contains the `%` sign
- imap-tools convenient functions and errors

|               | aioimaplib | imap-tools | imapclient | imapclient-async | 
|--------------:|:----------:|:----------:|:----------:|:----------------:|
|    High level |     ❌      |     ✅      |     ✅      |        ✅         |
|         Async |     ✅      |     ❌      |     ✅      |        ✅         |
| Proxy support |     ❌      |     ❌      |     ❌      |        ✅         |

## Examples

...
