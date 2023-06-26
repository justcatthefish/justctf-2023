#!/usr/bin/env python3

import base64
import secrets

token = secrets.token_hex(16)

print("Paseto token:")
print(base64.b64encode(token.encode("utf-8")).decode("utf-8"))
