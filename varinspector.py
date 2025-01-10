#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import pathlib
import struct
from typing import Any


def from_uint8(data: bytes) -> int:
    return struct.unpack("B", data)[0]


def from_uint16_le(data: bytes) -> int:
    return struct.unpack("<H", data)[0]


def from_uint16_be(data: bytes) -> int:
    return struct.unpack(">H", data)[0]


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


def extract_regions(data: bytes) -> None:
    var_offset = from_uint16_le(data[0x0069:0x006B])
    array_offset = from_uint16_le(data[0x006B:0x006D])
    string_offset = from_uint16_le(data[0x006D:0x006F])
    end_offset = from_uint16_le(data[0x006F:0x0071])
    print(f"Variables offset: 0x{var_offset:04x}")
    print(f"Arrays offset: 0x{array_offset:04x}")
    print(f"String data offset: 0x{string_offset:04x}")
    print(f"End offset: 0x{end_offset:04x}")
    print()

    ptr = var_offset
    print("Variables:")
    while ptr < array_offset:
        var_name = chr(data[ptr] & 0x7F) + (
            chr(data[ptr + 1] & 0x7F) if (data[ptr + 1] & 0x7F) else ""
        )
        is_func = data[ptr] & 0x80
        is_str = data[ptr + 1] & 0x80
        is_int = is_func and is_str
        var_data: Any = None
        if is_int:
            var_data = from_uint16_be(data[ptr + 2 : ptr + 4])
        elif is_str:
            str_len = data[ptr + 2]
            str_offset = from_uint16_le(data[ptr + 3 : ptr + 5])
            var_data = data[str_offset : str_offset + str_len]
        elif is_func:
            var_data = (
                hex(from_uint16_le(data[ptr + 2 : ptr + 4])),
                hex(from_uint16_le(data[ptr + 4 : ptr + 6])),
                hex(data[ptr + 6]),
            )
        else:
            var_data = from_float40_be(data[ptr + 2 : ptr + 7])

        print(
            f"[0x{ptr:04x}]  {data[ptr:ptr+7].hex()}  {var_name}{'%' if is_int else '$' if is_str else '()' if is_func else ''} = {var_data}"
        )
        ptr += 7
    print()
    print("Arrays:")
    ptr = array_offset
    while ptr < string_offset:
        arr_name = chr(data[ptr] & 0x7F) + (
            chr(data[ptr + 1] & 0x7F) if (data[ptr + 1] & 0x7F) else ""
        )
        is_func = data[ptr] & 0x80
        is_str = data[ptr + 1] & 0x80
        is_int = is_func and is_str
        size = from_uint16_le(data[ptr + 2 : ptr + 4])
        dims = data[ptr + 4]
        sizes = [
            from_uint16_be(data[ptr + 5 + i * 2 : ptr + 7 + i * 2]) for i in range(dims)
        ]
        print(
            f"[0x{ptr:04x}]  {data[ptr:ptr+5+dims*2].hex()}  {arr_name}{'%' if is_int else '$' if is_str else '()' if is_func else ''}{sizes} = "
        )
        next_ptr = ptr + size
        ptr += 5 + dims * 2
        while ptr < next_ptr:
            data_raw = b""
            if is_int:
                var_data = from_uint16_be(data[ptr : ptr + 2])
                data_raw = data[ptr : ptr + 2]
                ptr += 2
            elif is_str:
                str_len = data[ptr]
                str_offset = from_uint16_le(data[ptr + 1 : ptr + 3])
                var_data = data[str_offset : str_offset + str_len]
                data_raw = data[ptr : ptr + 3]
                ptr += 3
            else:
                var_data = from_float40_be(data[ptr : ptr + 5])
                data_raw = data[ptr : ptr + 5]
                ptr += 5
            print(f"[0x{ptr:04x}]  {data_raw.hex()}  - {var_data}")

        ptr = next_ptr


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Print the Applesoft BASIC variable storage from an Apple II memory dump"
    )
    parser.add_argument("FILE", type=pathlib.Path, help="Memory dump file")
    args = parser.parse_args()

    with open(args.FILE, "rb") as f:
        data = f.read()
        extract_regions(data)
