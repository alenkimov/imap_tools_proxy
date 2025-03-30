import asyncio
import ssl

from aioimaplib import IMAP4_SSL, IMAP4, IMAP4ClientProtocol, get_running_loop, Response
from python_socks.async_.asyncio import Proxy as AsyncProxy
from better_proxy import Proxy

IMAP4_SSL_PORT = 993


class IMAP4_SSL_PROXY(IMAP4_SSL):
    def __init__(
            self,
            host: str = "127.0.0.1",
            port: int = IMAP4_SSL_PORT,
            proxy: Proxy | None = None,
            timeout: float = IMAP4.TIMEOUT_SECONDS,
            loop: asyncio.AbstractEventLoop = None,
            ssl_context: ssl.SSLContext = None,
    ):
        self.host = host
        self.port = port
        self.loop = loop
        self.timeout = timeout
        self.ssl_context = ssl_context
        self.proxy = proxy

        self.protocol = None
        self._idle_waiter = None
        self.tasks: set[asyncio.Future] = set()


    async def connect(self) -> None:
        local_loop = self.loop if self.loop else get_running_loop()

        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context()
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

        self.protocol = IMAP4ClientProtocol(local_loop)
        if not self.proxy:
            await self._connect(local_loop)
        else:
            await self._proxy_connect(local_loop)

    async def _connect(self, loop: asyncio.AbstractEventLoop) -> None:
       await loop.create_connection(
            lambda: self.protocol,
            self.host,
            self.port,
            ssl=self.ssl_context,
        )

    async def _proxy_connect(self, loop: asyncio.AbstractEventLoop) -> None:
        async_proxy = AsyncProxy.from_url(self.proxy.as_url)
        sock = await async_proxy.connect(dest_host=self.host, dest_port=self.port)

        await loop.create_connection(
            lambda: self.protocol,
            sock=sock,
            ssl=self.ssl_context,
            server_hostname=self.host,
        )

    async def wait_hello_from_server(self) -> None:
        if not self.protocol:
            await self.connect()
        await super().wait_hello_from_server()

    async def login(self, user: str, password: str) -> Response:
        if not self.protocol:
            await self.connect()
        return await super().login(user, password)
