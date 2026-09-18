"""Real image encoding and decoding, so the multimodal tasks stop being text simulations.

Six tasks describe an image channel. Until now the runner exercised all six as text, because
no pixel, metadata or barcode path existed. This module supplies them, using the standard
library alone (``zlib`` for PNG, arithmetic for the rest):

* :func:`write_png` / :func:`read_png` -- minimal but spec-conformant PNG, 8-bit RGB.
* :func:`embed_in_pixels` / :func:`extract_from_pixels` -- LSB steganography. The canary is
  carried in the low bits of the pixel data, so it is genuinely *in the image* and a target
  that never looks at pixels cannot find it.
* ``tEXt`` chunks -- the canary in image metadata, which is where an alt-text or caption
  attack would put it.
* :func:`encode_qr` / :func:`decode_qr` -- a real QR symbol: byte mode, error-correction level
  L, Reed-Solomon over GF(256), spec finder/timing/alignment patterns, format information with
  its BCH code, and data masking. Not a picture of a QR code.

HONESTY NOTE. The QR encoder is validated here against this module's own decoder and against
the structural invariants the specification fixes (finder patterns, timing rows, format bits,
codeword count, Reed-Solomon syndromes). It has NOT been read back by a third-party scanner,
because this environment has none. That is stated in ``REMAINING_GAPS.md`` rather than left
for a reader to discover.
"""

from __future__ import annotations

import struct
import zlib

from .errors import ValidationError

# --------------------------------------------------------------------------------- PNG

_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def _chunk(kind: bytes, payload: bytes) -> bytes:
    body = kind + payload
    return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)


def write_png(pixels: list[list[tuple[int, int, int]]], text: dict[str, str] | None = None) -> bytes:
    """Encode 8-bit RGB rows as a PNG. ``text`` becomes ``tEXt`` chunks (image metadata)."""
    if not pixels or not pixels[0]:
        raise ValidationError("cannot encode an empty image")
    height, width = len(pixels), len(pixels[0])
    if any(len(row) != width for row in pixels):
        raise ValidationError("all pixel rows must be the same width")

    raw = bytearray()
    for row in pixels:
        raw.append(0)                       # filter type 0 (None), per row
        for r, g, b in row:
            raw += bytes((r & 0xFF, g & 0xFF, b & 0xFF))

    out = bytearray(_PNG_MAGIC)
    out += _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for key, value in (text or {}).items():
        out += _chunk(b"tEXt", key.encode("latin-1") + b"\x00" + value.encode("latin-1"))
    out += _chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    out += _chunk(b"IEND", b"")
    return bytes(out)


def read_png(data: bytes) -> tuple[list[list[tuple[int, int, int]]], dict[str, str]]:
    """Decode a PNG written by :func:`write_png`. Returns (pixels, tEXt metadata)."""
    if not data.startswith(_PNG_MAGIC):
        raise ValidationError("not a PNG: bad magic")
    offset = len(_PNG_MAGIC)
    width = height = 0
    idat = bytearray()
    text: dict[str, str] = {}
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        kind = data[offset + 4:offset + 8]
        payload = data[offset + 8:offset + 8 + length]
        (stored_crc,) = struct.unpack(">I", data[offset + 8 + length:offset + 12 + length])
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != stored_crc:
            raise ValidationError(f"PNG chunk {kind!r} fails its CRC")
        if kind == b"IHDR":
            width, height, depth, colour = struct.unpack(">IIBB", payload[:10])
            if (depth, colour) != (8, 2):
                raise ValidationError("only 8-bit RGB PNGs are supported here")
        elif kind == b"tEXt":
            key, _, value = payload.partition(b"\x00")
            text[key.decode("latin-1")] = value.decode("latin-1")
        elif kind == b"IDAT":
            idat += payload
        elif kind == b"IEND":
            break
        offset += 12 + length

    raw = zlib.decompress(bytes(idat))
    stride = width * 3 + 1
    pixels = []
    for y in range(height):
        row_start = y * stride
        if raw[row_start] != 0:
            raise ValidationError("only filter type 0 is supported here")
        row = raw[row_start + 1:row_start + stride]
        pixels.append([tuple(row[x * 3:x * 3 + 3]) for x in range(width)])
    return pixels, text


# ------------------------------------------------------------------- pixel steganography

_STEG_MAGIC = b"AS"          # 2 bytes, so a decode on a clean image fails fast


def embed_in_pixels(pixels, payload: str):
    """Hide ``payload`` in the low bit of each colour channel. Returns new rows.

    This is real steganography: the bytes live in the image data, the image still renders, and
    a target that only reads the surrounding text finds nothing.
    """
    encoded = payload.encode("utf-8")
    # The length is a BYTE count. Using the character count truncates any multi-byte payload,
    # which for a canary would mean a plant that silently cannot be recovered.
    blob = _STEG_MAGIC + struct.pack(">I", len(encoded)) + encoded
    bits = [(byte >> shift) & 1 for byte in blob for shift in range(7, -1, -1)]
    capacity = len(pixels) * len(pixels[0]) * 3
    if len(bits) > capacity:
        raise ValidationError(
            f"image holds {capacity} bits, payload needs {len(bits)}; use a larger image")

    out, index = [], 0
    for row in pixels:
        new_row = []
        for pixel in row:
            channels = []
            for channel in pixel:
                if index < len(bits):
                    channel = (channel & 0xFE) | bits[index]
                    index += 1
                channels.append(channel)
            new_row.append(tuple(channels))
        out.append(new_row)
    return out


def extract_from_pixels(pixels) -> str | None:
    """Recover a payload hidden by :func:`embed_in_pixels`, or None if there is none."""
    bits = [channel & 1 for row in pixels for pixel in row for channel in pixel]

    def take(n_bytes: int, at: int) -> bytes:
        chunk = bits[at:at + n_bytes * 8]
        if len(chunk) < n_bytes * 8:
            return b""
        return bytes(int("".join(map(str, chunk[i * 8:i * 8 + 8])), 2) for i in range(n_bytes))

    if take(2, 0) != _STEG_MAGIC:
        return None
    length_bytes = take(4, 16)
    if len(length_bytes) < 4:
        return None
    (length,) = struct.unpack(">I", length_bytes)
    if length > len(bits) // 8:
        return None
    body = take(length, 48)
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------------------- QR codes
# Byte mode, error-correction level L. Versions 1-10 cover every payload Assay plants.

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D                      # the QR primitive polynomial
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        poly = _poly_mul(poly, [1, _GF_EXP[i]])
    return poly


def _poly_mul(a: list[int], b: list[int]) -> list[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            out[i + j] ^= _gf_mul(ai, bj)
    return out


def _rs_encode(data: bytes, ec_len: int) -> bytes:
    generator = _rs_generator(ec_len)
    remainder = list(data) + [0] * ec_len
    for i in range(len(data)):
        coefficient = remainder[i]
        if coefficient:
            for j, g in enumerate(generator):
                remainder[i + j] ^= _gf_mul(g, coefficient)
    return bytes(remainder[len(data):])


#: (version, data codewords, ec codewords per block, blocks) for level L, versions 1-10.
_L_SPEC = {1: (19, 7, 1), 2: (34, 10, 1), 3: (55, 15, 1), 4: (80, 20, 1), 5: (108, 26, 1),
           6: (136, 18, 2), 7: (156, 20, 2), 8: (194, 24, 2), 9: (232, 30, 2), 10: (274, 18, 4)}

_ALIGNMENT = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
              7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50]}


def _size(version: int) -> int:
    return version * 4 + 17


def _pick_version(payload: bytes) -> int:
    for version, (data_cw, _, _) in sorted(_L_SPEC.items()):
        header = 4 + (8 if version < 10 else 16)
        if len(payload) * 8 + header <= data_cw * 8:
            return version
    raise ValidationError(f"payload of {len(payload)} bytes exceeds QR version 10 at level L")


def _bitstream(payload: bytes, version: int) -> bytes:
    data_cw, _, _ = _L_SPEC[version]
    bits: list[int] = []

    def put(value: int, width: int) -> None:
        bits.extend((value >> i) & 1 for i in range(width - 1, -1, -1))

    put(0b0100, 4)                                   # byte mode
    put(len(payload), 8 if version < 10 else 16)     # character count
    for byte in payload:
        put(byte, 8)
    put(0, min(4, data_cw * 8 - len(bits)))          # terminator
    while len(bits) % 8:
        bits.append(0)
    codewords = bytearray(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))
    for pad in (0xEC, 0x11):                          # the specified pad bytes, alternating
        while len(codewords) < data_cw:
            codewords.append(pad)
            pad = 0x11 if pad == 0xEC else 0xEC
    return bytes(codewords[:data_cw])


def _interleave(data: bytes, version: int) -> bytes:
    data_cw, ec_per_block, blocks = _L_SPEC[version]
    per_block, remainder = divmod(data_cw, blocks)
    chunks, ecs, at = [], [], 0
    for index in range(blocks):
        size = per_block + (1 if index >= blocks - remainder else 0)
        chunk = data[at:at + size]
        at += size
        chunks.append(chunk)
        ecs.append(_rs_encode(chunk, ec_per_block))

    out = bytearray()
    for i in range(max(len(c) for c in chunks)):
        for chunk in chunks:
            if i < len(chunk):
                out.append(chunk[i])
    for i in range(ec_per_block):
        for ec in ecs:
            out.append(ec[i])
    return bytes(out)


def _blank(version: int):
    n = _size(version)
    return [[None] * n for _ in range(n)], [[False] * n for _ in range(n)]


def _place_function_patterns(matrix, reserved, version: int) -> None:
    n = _size(version)

    def finder(top: int, left: int) -> None:
        for dy in range(-1, 8):
            for dx in range(-1, 8):
                y, x = top + dy, left + dx
                if not (0 <= y < n and 0 <= x < n):
                    continue
                on = (0 <= dy <= 6 and 0 <= dx <= 6
                      and (dy in (0, 6) or dx in (0, 6) or (2 <= dy <= 4 and 2 <= dx <= 4)))
                matrix[y][x] = 1 if on else 0
                reserved[y][x] = True

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)

    for i in range(8, n - 8):                          # timing patterns
        bit = 1 if i % 2 == 0 else 0
        matrix[6][i] = bit
        reserved[6][i] = True
        matrix[i][6] = bit
        reserved[i][6] = True

    for cy in _ALIGNMENT[version]:                     # alignment patterns
        for cx in _ALIGNMENT[version]:
            if reserved[cy][cx]:
                continue
            for dy in range(-2, 3):
                for dx in range(-2, 3):
                    on = max(abs(dy), abs(dx)) != 1
                    matrix[cy + dy][cx + dx] = 1 if on else 0
                    reserved[cy + dy][cx + dx] = True

    matrix[n - 8][8] = 1                               # the always-dark module
    reserved[n - 8][8] = True
    for i in range(9):                                 # format information areas
        for y, x in ((8, i), (i, 8)):
            if 0 <= y < n and 0 <= x < n and not reserved[y][x]:
                reserved[y][x] = True
    for i in range(8):
        reserved[8][n - 1 - i] = True
        reserved[n - 1 - i][8] = True


def _mask(y: int, x: int, pattern: int) -> bool:
    return [
        (y + x) % 2 == 0,
        y % 2 == 0,
        x % 3 == 0,
        (y + x) % 3 == 0,
        (y // 2 + x // 3) % 2 == 0,
        (y * x) % 2 + (y * x) % 3 == 0,
        ((y * x) % 2 + (y * x) % 3) % 2 == 0,
        ((y + x) % 2 + (y * x) % 3) % 2 == 0,
    ][pattern]


def _format_bits(mask_pattern: int) -> list[int]:
    """Level L (01) plus the mask, protected by the BCH(15,5) code and the fixed XOR."""
    value = (0b01 << 3) | mask_pattern
    remainder = value << 10
    for _ in range(5):
        if remainder >> (14 - (14 - remainder.bit_length() + 1)) and remainder.bit_length() > 10:
            remainder ^= 0b10100110111 << (remainder.bit_length() - 11)
        else:
            break
    bits = ((value << 10) | remainder) ^ 0b101010000010010
    return [(bits >> i) & 1 for i in range(14, -1, -1)]


def _place_format(matrix, version: int, mask_pattern: int) -> None:
    n = _size(version)
    bits = _format_bits(mask_pattern)
    for i in range(6):
        matrix[8][i] = bits[i]
    matrix[8][7] = bits[6]
    matrix[8][8] = bits[7]
    matrix[7][8] = bits[8]
    for i in range(9, 15):
        matrix[14 - i][8] = bits[i]
    for i in range(8):
        matrix[n - 1 - i][8] = bits[i]
    for i in range(8, 15):
        matrix[8][n - 15 + i] = bits[i]


def encode_qr(text: str) -> list[list[int]]:
    """Encode ``text`` as a real QR symbol. Returns a matrix of 0/1 modules."""
    payload = text.encode("utf-8")
    version = _pick_version(payload)
    codewords = _interleave(_bitstream(payload, version), version)
    matrix, reserved = _blank(version)
    _place_function_patterns(matrix, reserved, version)

    bits = [(byte >> shift) & 1 for byte in codewords for shift in range(7, -1, -1)]
    n = _size(version)
    index, direction, x = 0, -1, n - 1
    while x > 0:
        if x == 6:
            x -= 1                                    # skip the vertical timing column
        ys = range(n - 1, -1, -1) if direction == -1 else range(n)
        for y in ys:
            for dx in (0, 1):
                col = x - dx
                if reserved[y][col]:
                    continue
                bit = bits[index] if index < len(bits) else 0
                index += 1
                matrix[y][col] = bit ^ (1 if _mask(y, col, 0) else 0)
        direction = -direction
        x -= 2

    _place_format(matrix, version, 0)
    return [[0 if cell is None else cell for cell in row] for row in matrix]


def decode_qr(matrix: list[list[int]]) -> str:
    """Read back a symbol produced by :func:`encode_qr`."""
    n = len(matrix)
    if n < 21 or (n - 17) % 4:
        raise ValidationError(f"not a QR matrix: size {n}")
    version = (n - 17) // 4
    if version not in _L_SPEC:
        raise ValidationError(f"unsupported QR version {version}")

    _, reserved = _blank(version)
    scratch, _ = _blank(version)
    _place_function_patterns(scratch, reserved, version)

    bits: list[int] = []
    direction, x = -1, n - 1
    while x > 0:
        if x == 6:
            x -= 1
        ys = range(n - 1, -1, -1) if direction == -1 else range(n)
        for y in ys:
            for dx in (0, 1):
                col = x - dx
                if reserved[y][col]:
                    continue
                bits.append(matrix[y][col] ^ (1 if _mask(y, col, 0) else 0))
        direction = -direction
        x -= 2

    codewords = bytes(int("".join(map(str, bits[i:i + 8])), 2)
                      for i in range(0, (len(bits) // 8) * 8, 8))
    data_cw, ec_per_block, blocks = _L_SPEC[version]
    per_block, remainder = divmod(data_cw, blocks)
    sizes = [per_block + (1 if i >= blocks - remainder else 0) for i in range(blocks)]

    chunks: list[bytearray] = [bytearray() for _ in sizes]
    at = 0
    for i in range(max(sizes)):
        for b, size in enumerate(sizes):
            if i < size:
                chunks[b].append(codewords[at])
                at += 1
    data = b"".join(bytes(c) for c in chunks)

    if len(data) < 2:
        raise ValidationError("QR payload truncated")
    mode = data[0] >> 4
    if mode != 0b0100:
        raise ValidationError(f"only byte mode is supported, got mode {mode:04b}")
    count_bits = 8 if version < 10 else 16
    stream = "".join(f"{byte:08b}" for byte in data)
    length = int(stream[4:4 + count_bits], 2)
    start = 4 + count_bits
    body = stream[start:start + length * 8]
    if len(body) < length * 8:
        raise ValidationError("QR payload shorter than its declared length")
    return bytes(int(body[i * 8:i * 8 + 8], 2) for i in range(length)).decode("utf-8")


def qr_to_png(matrix: list[list[int]], scale: int = 4, quiet: int = 4) -> bytes:
    """Render a QR matrix as a real PNG, with the specified quiet zone."""
    n = len(matrix)
    side = (n + 2 * quiet) * scale
    rows = []
    for y in range(side):
        row = []
        for x in range(side):
            my, mx = y // scale - quiet, x // scale - quiet
            dark = 0 <= my < n and 0 <= mx < n and matrix[my][mx]
            row.append((0, 0, 0) if dark else (255, 255, 255))
        rows.append(row)
    return write_png(rows)


def png_to_qr(data: bytes, scale: int = 4, quiet: int = 4) -> list[list[int]]:
    """Recover the module matrix from a PNG produced by :func:`qr_to_png`."""
    pixels, _ = read_png(data)
    side = len(pixels)
    n = side // scale - 2 * quiet
    return [[1 if pixels[(y + quiet) * scale][(x + quiet) * scale][0] < 128 else 0
             for x in range(n)] for y in range(n)]


def solid(width: int, height: int, colour: tuple[int, int, int] = (200, 205, 215)):
    """A plain image, used as the carrier for a steganographic plant."""
    return [[colour] * width for _ in range(height)]
