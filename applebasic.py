#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import pathlib
import struct

# This work would not be possible without the annotated
# disassembly of the Applesoft BASIC ROM.
# https://6502disassembly.com/a2-rom/Applesoft.html

TOKENS: dict[int, str] = {
    0x80: "END",
    0x81: "FOR",
    0x82: "NEXT",
    0x83: "DATA",
    0x84: "INPUT",
    0x85: "DEL",
    0x86: "DIM",
    0x87: "READ",
    0x88: "GR",
    0x89: "TEXT",
    0x8A: "PR#",
    0x8B: "IN#",
    0x8C: "CALL",
    0x8D: "PLOT",
    0x8E: "HLIN",
    0x8F: "VLIN",
    0x90: "HGR2",
    0x91: "HGR",
    0x92: "HCOLOR=",
    0x93: "HPLOT",
    0x94: "DRAW",
    0x95: "XDRAW",
    0x96: "HTAB",
    0x97: "HOME",
    0x98: "ROT=",
    0x99: "SCALE=",
    0x9A: "SHLOAD",
    0x9B: "TRACE",
    0x9C: "NOTRACE",
    0x9D: "NORMAL",
    0x9E: "INVERSE",
    0x9F: "FLASH",
    0xA0: "COLOR=",
    0xA1: "POP",
    0xA2: "VTAB",
    0xA3: "HIMEM:",
    0xA4: "LOMEM:",
    0xA5: "ONERR",
    0xA6: "RESUME",
    0xA7: "RECALL",
    0xA8: "STORE",
    0xA9: "SPEED=",
    0xAA: "LET",
    0xAB: "GOTO",
    0xAC: "RUN",
    0xAD: "IF",
    0xAE: "RESTORE",
    0xB0: "GOSUB",
    0xB1: "RETURN",
    0xB2: "REM",
    0xB3: "STOP",
    0xB4: "ON",
    0xB5: "WAIT",
    0xB6: "LOAD",
    0xB7: "SAVE",
    0xB8: "DEF",
    0xB9: "POKE",
    0xBA: "PRINT",
    0xBB: "CONT",
    0xBC: "LIST",
    0xBD: "CLEAR",
    0xBE: "GET",
    0xBF: "NEW",
    0xC0: "TAB(",
    0xC1: "TO",
    0xC2: "FN",
    0xC3: "SPC(",
    0xC4: "THEN",
    0xC5: "AT",
    0xC6: "NOT",
    0xC7: "STEP",
    0xCD: "AND",
    0xCE: "OR",
    0xD2: "SGN",
    0xD3: "INT",
    0xD4: "ABS",
    0xD5: "USR",
    0xD6: "FRE",
    0xD7: "SCRN(",
    0xD8: "PDL",
    0xD9: "POS",
    0xDA: "SQR",
    0xDB: "RND",
    0xDC: "LOG",
    0xDD: "EXP",
    0xDE: "COS",
    0xDF: "SIN",
    0xE0: "TAN",
    0xE1: "ATN",
    0xE2: "PEEK",
    0xE3: "LEN",
    0xE4: "STR$",
    0xE5: "VAL",
    0xE6: "ASC",
    0xE7: "CHR$",
    0xE8: "LEFT$",
    0xE9: "RIGHT$",
    0xEA: "MID$",
    0xAF: "&",
    0xC8: "+",
    0xC9: "-",
    0xCA: "*",
    0xCB: "/",
    0xCC: "^",
    0xCF: ">",
    0xD0: "=",
    0xD1: "<",
}


def from_uint8(data: bytes) -> int:
    return struct.unpack("B", data)[0]


def from_uint16_le(data: bytes) -> int:
    return struct.unpack("<H", data)[0]


def from_int16_le(data: bytes) -> int:
    return struct.unpack("<h", data)[0]


def from_uint32_be(data: bytes) -> int:
    return struct.unpack(">L", data)[0]


def from_float40_be(data: bytes) -> float:
    if data == b"\x00\x00\x00\x00\x00":
        return 0.0
    exp = data[0]
    bits = struct.unpack(">L", data[1:5])[0]
    sign = -1 if (bits & 0b10000000000000000000000000000000) else 1
    bits = bits & 0b01111111111111111111111111111111
    return sign * (1 + (bits / (2**31))) * 2 ** (exp - 129)


def to_uint8(value: int) -> bytes:
    return struct.pack("B", value)


def to_uint16_le(value: int) -> bytes:
    return struct.pack("<H", value)


def to_int16_le(value: int) -> bytes:
    return struct.pack("<h", value)


def to_uint32_be(value: int) -> bytes:
    return struct.pack(">L", value)


def to_float40_be(value: float) -> bytes:
    if value == 0.0:
        return b"\x00\x00\x00\x00\x00"
    exp_base = math.floor(math.log(abs(value)) / math.log(2))
    exp = max(min(exp_base + 129, 255), 0)
    bits = math.floor(((abs(value) / (2**exp_base)) - 1) * (2**31))
    chunk = bits & 0b01111111111111111111111111111111
    chunk = chunk | (0b10000000000000000000000000000000 if value < 0 else 0)
    data = to_uint8(exp)
    data += to_uint32_be(chunk)
    return data


def detokenify(args: bytes) -> str:
    result = ""
    for x in args:
        if x >= 0x80:
            if x in TOKENS:
                result += f" {TOKENS[x]} "
            else:
                result += f" TOK_{x:02X} "
        else:
            result += chr(x)
    return result.strip()


def read_line(data: bytes, ptr: int) -> tuple[str, int]:
    start = ptr
    inside_str = False
    is_rem = data[ptr] == 0xB2

    while ptr < len(data):
        if data[ptr] == 0x00:
            break
        elif data[ptr] == ord('"'):
            inside_str = not inside_str
        elif data[ptr] == ord(":") and (not inside_str) and not is_rem:
            break
        ptr += 1
    line = detokenify(data[start:ptr])
    return (line, ptr)


def parse_prog(data: bytes, show_offsets: bool, original: bool) -> str:
    result = ""
    ptr = 0
    # utils.hexdump(data, major_len=4)
    unk1 = from_uint16_le(data[ptr : ptr + 2])
    linenum = from_uint16_le(data[ptr + 2 : ptr + 4])
    ptr += 4
    result += "{linenum} " if original else f"# {linenum}\n"
    while ptr < len(data):

        offset = ptr
        if not original and show_offsets:
            result += f"[{offset:#06x}]  "
        if data[ptr] < 0x80:
            # LET statement
            var = b""
            while data[ptr] != 0xD0:  # TOK_EQUAL:
                var += data[ptr : ptr + 1]
                ptr += 1
            var_norm = detokenify(var)
            ptr += 1
            value, ptr = read_line(data, ptr)
            result += f"LET {var_norm} = {value}" + (":" if original else f"\n")
        else:
            line, ptr = read_line(data, ptr)
            result += f"{line}" + (":" if original else f"\n")

        if data[ptr] == ord(":"):
            # next line
            ptr += 1
        elif data[ptr] == 0x00:
            # new start line
            ptr += 1
            unk1 = from_uint16_le(data[ptr : ptr + 2])
            if unk1 == 0:
                break
            linenum = from_uint16_le(data[ptr + 2 : ptr + 4])
            ptr += 4
            result += "\n"
            result += f"{linenum} " if original else f"# {linenum}\n"
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decompile Applesoft BASIC bytecode")
    parser.add_argument("FILE", type=pathlib.Path, help="Applesoft BASIC program data")
    parser.add_argument(
        "--show-offsets", action="store_true", help="Show file offsets for each line"
    )
    parser.add_argument(
        "--original",
        action="store_true",
        help="Output harder to read but more correct source",
    )
    args = parser.parse_args()
    with open(args.FILE, "rb") as f:
        print(parse_prog(f.read(), args.show_offsets, args.original))
