#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import quopri

def qp_encode(s: str, charset: str) -> str:
    b = s.encode(charset)
    qp_bytes = quopri.encodestring(b)
    qp_str = qp_bytes.decode("ascii")
    return f"=?{charset}?q?{qp_str}?="

def encode_email(address: str):
    try:
        local_part, domain_part = address.split("@", 1)
    except ValueError:
        raise ValueError(f"Invalid email format: {address!r}")

    # Encode local part with quoted-printable
    utf8_local = qp_encode(local_part, "utf-8")
    utf7_local = qp_encode(local_part, "utf-7")

    # Domain must be ASCII (use IDNA/punycode)
    encoded_domain = domain_part.encode("idna").decode("ascii")

    utf8_email = f"{utf8_local}@{encoded_domain}"
    utf7_email = f"{utf7_local}@{encoded_domain}"

    return utf8_email, utf7_email

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} '<email@domain>'")
        sys.exit(1)

    email = sys.argv[1]
    utf8_email, utf7_email = encode_email(email)

    print("UTF-8 encoded email:")
    print(utf8_email)
    print("\nUTF-7 encoded email:")
    print(utf7_email)

if __name__ == "__main__":
    main()

