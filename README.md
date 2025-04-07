# IMAP Tools Async

Finally, async IMAP Tools!!!

Эта библиотека основана на основе следующих библиотек:
- [aioimaplib](https://github.com/iroco-co/aioimaplib)
- [imap-tools](https://github.com/ikvk/imap_tools)
- [imapclient](https://github.com/mjs/imapclient)

## Ключевые отличия от imap-tools
- (!) Асинхронные команды на основе aioimaplib
- (!) Поддержка http и socks прокси благодаря python-socks
- (+) Модели упрощены, а код осовременен и типизирован
- (+) Обработка специфичной ошибки логина imap.rambler.ru, которая не позволяет выполнить вход, если пароль содержит знак `%`
- (-) Поддерживается версия Python 3.11+
- (-) Отсутствует MailboxTls
- (-) Множество исключений было убрано в угоду упрощения кода. Тем не менее отлавливать и обрабатывать исключения по-прежнему удобно
