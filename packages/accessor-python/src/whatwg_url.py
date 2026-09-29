# SPDX-License-Identifier: Apache-2.0
#
# The failure conditions of the WHATWG URL Standard's basic URL parser
# (https://url.spec.whatwg.org/), run with no base URL, ported from the
# specification text. It answers one question: would `new URL(value)` throw?
#
# Paths, queries, fragments and opaque paths never fail, and validation errors
# that are not failures are ignored, so only the scheme, the authority, the
# port and the host are examined. A special-scheme domain whose "domain to
# ASCII" is not plain ASCII lowercasing (a non-ASCII code point after
# percent-decoding, or a label starting with "xn--") needs UTS #46 processing,
# which is not ported: its verdict is None and the caller must reject it.
#
# Every top-level name starts with an underscore because this code is inlined
# into generated modules. Nothing here logs, raises, or echoes the value.

_SPECIAL_SCHEMES = frozenset(("ftp", "file", "http", "https", "ws", "wss"))
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = frozenset("0123456789")
_HEX = frozenset("0123456789abcdefABCDEF")
_RADIX_DIGITS = {8: frozenset("01234567"), 10: _DIGITS, 16: _HEX}
_SCHEME_CHARS = _ALPHA | _DIGITS | frozenset("+-.")
_SLASHES = frozenset("/\\")
_C0_OR_SPACE = "".join(map(chr, range(0x21)))
_FORBIDDEN_HOST = frozenset("\x00\t\n\r #/:<>?@[\\]^|")
_FORBIDDEN_DOMAIN = _FORBIDDEN_HOST | frozenset(_C0_OR_SPACE[:0x20] + "%\x7f")


def _url_verdict(value):
    # True: the parser returns a URL. False: it returns failure.
    # None: the verdict needs UTS #46 (see above), or the input is not a str.
    try:
        return _url_parse(value)
    except Exception:  # defensive: never raise, never carry the value out
        return None


def _url_parse(value):
    # Remove leading and trailing C0 control or space, then all ASCII tab or newline.
    text = value.strip(_C0_OR_SPACE).replace("\t", "").replace("\n", "").replace("\r", "")
    # Scheme start state and scheme state: ASCII alpha, then ASCII alphanumeric,
    # "+", "-" or ".", then ":". Anything else is the no scheme state, and with
    # no base URL that is failure.
    colon = text.find(":")
    if colon < 1 or text[0] not in _ALPHA or not _SCHEME_CHARS.issuperset(text[:colon]):
        return False
    scheme = text[:colon].lower()
    rest = text[colon + 1 :]
    if scheme == "file":
        # File state, then file slash state: two slashes (either direction)
        # reach the file host state; anything else is a path, which never fails.
        if rest[:1] not in _SLASHES or rest[1:2] not in _SLASHES:
            return True
        host = rest[2:]
        host = host[: _first_of(host, "/\\?#")]
        # File host state: a Windows drive letter is a path; empty is the empty host.
        if not host or (len(host) == 2 and host[0] in _ALPHA and host[1] in ":|"):
            return True
        return _host_verdict(host, True)
    if scheme in _SPECIAL_SCHEMES:
        # Special authority slashes and ignore slashes states skip every / and \.
        return _authority_verdict(rest.lstrip("/\\"), True)
    if rest[:2] == "//":
        # Path or authority state, then the authority state.
        return _authority_verdict(rest[2:], False)
    return True  # a path or an opaque path


def _first_of(text, stops):
    # Index of the first code point of text in stops, or len(text).
    end = len(text)
    for stop in stops:
        found = text.find(stop, 0, end)
        if found >= 0:
            end = found
    return end


def _authority_verdict(rest, special):
    # Authority state: it ends at EOF, /, ? or # (and \ for special schemes).
    # Each @ restarts the buffer, so the host starts after the last @.
    authority = rest[: _first_of(rest, "/\\?#" if special else "/?#")]
    at = authority.rfind("@")
    if at >= 0:
        authority = authority[at + 1 :]
        if not authority:
            return False  # host-missing after credentials
    # Host state: the first ":" outside brackets ends the host and starts the port.
    colon = -1
    if "[" in authority:
        inside = False
        for index, char in enumerate(authority):
            if char == ":" and not inside:
                colon = index
                break
            if char == "[":
                inside = True
            elif char == "]":
                inside = False
    else:
        colon = authority.find(":")
    if colon < 0:
        if special and not authority:
            return False  # host-missing
        return _host_verdict(authority, special)
    if colon == 0:
        return False  # host-missing before the port
    verdict = _host_verdict(authority[:colon], special)
    if verdict is not True:
        return verdict
    # Port state: ASCII digits only, at most 65535; an empty port is fine.
    port = authority[colon + 1 :]
    if not _DIGITS.issuperset(port):
        return False
    port = port.lstrip("0")
    return len(port) <= 5 and (not port or int(port) <= 65535)


def _host_verdict(host, special):
    # Host parser.
    if host[:1] == "[":
        return host[-1:] == "]" and _ipv6_valid(host[1:-1])
    if not special:
        # Opaque-host parser: only forbidden host code points fail.
        return _FORBIDDEN_HOST.isdisjoint(host)
    # Percent-decode then UTF-8 decode: any byte >= 0x80 decodes to a non-ASCII
    # code point (U+FFFD when invalid), so the domain is ASCII exactly when the
    # input is ASCII and no escape decodes to a byte >= 0x80.
    domain = _percent_decode_ascii(host) if host.isascii() else None
    if domain is None:
        return None
    # Domain to ASCII: for ASCII input without an "xn--" label it is lowercasing.
    domain = domain.lower()
    if any(label.startswith("xn--") for label in domain.split(".")):
        return None
    if not domain or not _FORBIDDEN_DOMAIN.isdisjoint(domain):
        return False
    if _ends_in_a_number(domain):
        return _ipv4_valid(domain)
    return True


def _percent_decode_ascii(text):
    # Percent-decoding of an ASCII string; None if a byte >= 0x80 is decoded.
    out = []
    start = 0
    while True:
        percent = text.find("%", start)
        if percent < 0:
            out.append(text[start:])
            return "".join(out)
        out.append(text[start:percent])
        pair = text[percent + 1 : percent + 3]
        if len(pair) == 2 and _HEX.issuperset(pair):
            byte = int(pair, 16)
            if byte >= 0x80:
                return None
            out.append(chr(byte))
            start = percent + 3
        else:
            out.append("%")
            start = percent + 1


def _ends_in_a_number(domain):
    # Ends in a number checker.
    parts = domain.split(".")
    if parts[-1] == "":
        parts.pop()
    if not parts:
        return False
    last = parts[-1]
    if last and _DIGITS.issuperset(last):
        return True
    return _ipv4_number(last) is not None


def _ipv4_number(part):
    # IPv4 number parser: None on failure, otherwise the value. Values above
    # 2**32 all fail the same way, so long inputs are capped instead of converted.
    if not part:
        return None
    radix = 10
    if len(part) >= 2 and part[:2] in ("0x", "0X"):
        part, radix = part[2:], 16
    elif len(part) >= 2 and part[0] == "0":
        part, radix = part[1:], 8
    if not part:
        return 0
    if not _RADIX_DIGITS[radix].issuperset(part):
        return None
    part = part.lstrip("0")
    if len(part) > 12:
        return 1 << 48
    return int(part, radix) if part else 0


def _ipv4_valid(domain):
    # IPv4 parser.
    parts = domain.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return False
    numbers = []
    for part in parts:
        number = _ipv4_number(part)
        if number is None:
            return False
        numbers.append(number)
    if any(number > 255 for number in numbers[:-1]):
        return False
    return numbers[-1] < 256 ** (5 - len(numbers))


def _ipv6_valid(text):
    # IPv6 parser (the piece values themselves never cause failure).
    size = len(text)
    pointer = 0
    piece_index = 0
    compress = None
    if text[:1] == ":":
        if text[1:2] != ":":
            return False
        pointer = 2
        piece_index = 1
        compress = 1
    while pointer < size:
        if piece_index == 8:
            return False
        if text[pointer] == ":":
            if compress is not None:
                return False
            pointer += 1
            piece_index += 1
            compress = piece_index
            continue
        length = 0
        while length < 4 and pointer < size and text[pointer] in _HEX:
            pointer += 1
            length += 1
        char = text[pointer] if pointer < size else ""
        if char == ".":
            # IPv4 in IPv6: exactly four decimal parts, each at most 255,
            # no leading zeros, taking two pieces.
            if length == 0 or piece_index > 6:
                return False
            pointer -= length
            numbers_seen = 0
            while pointer < size:
                if numbers_seen > 0:
                    if text[pointer] == "." and numbers_seen < 4:
                        pointer += 1
                    else:
                        return False
                if pointer >= size or text[pointer] not in _DIGITS:
                    return False
                ipv4_piece = None
                while pointer < size and text[pointer] in _DIGITS:
                    number = ord(text[pointer]) - 0x30
                    if ipv4_piece is None:
                        ipv4_piece = number
                    elif ipv4_piece == 0:
                        return False
                    else:
                        ipv4_piece = ipv4_piece * 10 + number
                    if ipv4_piece > 255:
                        return False
                    pointer += 1
                numbers_seen += 1
                if numbers_seen in (2, 4):
                    piece_index += 1
            if numbers_seen != 4:
                return False
            break
        if char == ":":
            pointer += 1
            if pointer >= size:
                return False
        elif char:
            return False
        piece_index += 1
    return compress is not None or piece_index == 8
