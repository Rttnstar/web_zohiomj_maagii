#!/usr/bin/env python3
"""S-DES laboratory implementation.

The program encrypts bytes, so UTF-8 Mongolian/Cyrillic text is supported.
Each byte is one 8-bit S-DES block; PKCS#7-style padding is used for files.
"""

from __future__ import annotations

import argparse
from pathlib import Path

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
S0 = ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 3, 2))
S1 = ((0, 1, 2, 3), (2, 0, 1, 3), (3, 0, 1, 0), (2, 1, 0, 3))


def permute(bits: str, table: tuple[int, ...]) -> str:
    return "".join(bits[i - 1] for i in table)


def left_shift(bits: str, count: int) -> str:
    count %= len(bits)
    return bits[count:] + bits[:count]


def xor(a: str, b: str) -> str:
    return "".join("1" if x != y else "0" for x, y in zip(a, b))


def make_keys(key10: str) -> tuple[str, str]:
    if len(key10) != 10 or set(key10) - {"0", "1"}:
        raise ValueError("Түлхүүр яг 10 ширхэг 0/1 бит байх ёстой.")
    p10 = permute(key10, P10)
    left, right = p10[:5], p10[5:]
    k1 = permute(left_shift(left, 1) + left_shift(right, 1), P8)
    k2 = permute(left_shift(left, 3) + left_shift(right, 3), P8)
    return k1, k2


def sbox(bits: str, box: tuple[tuple[int, ...], ...]) -> str:
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1:3], 2)
    return f"{box[row][column]:02b}"


def fk(left: str, right: str, key8: str) -> tuple[str, str]:
    expanded = permute(right, EP)
    mixed = xor(expanded, key8)
    substituted = sbox(mixed[:4], S0) + sbox(mixed[4:], S1)
    return xor(left, permute(substituted, P4)), right


def encrypt_block(bits8: str, k1: str, k2: str) -> str:
    if len(bits8) != 8 or set(bits8) - {"0", "1"}:
        raise ValueError("Блок яг 8 ширхэг 0/1 бит байх ёстой.")
    state = permute(bits8, IP)
    left, right = state[:4], state[4:]
    left, right = fk(left, right, k1)
    left, right = right, left
    left, right = fk(left, right, k2)
    return permute(left + right, IP_INV)


def decrypt_block(bits8: str, k1: str, k2: str) -> str:
    return encrypt_block(bits8, k2, k1)


def encrypt_bytes(data: bytes, key10: str) -> bytes:
    k1, k2 = make_keys(key10)
    return bytes(int(encrypt_block(f"{byte:08b}", k1, k2), 2) for byte in data)


def decrypt_bytes(data: bytes, key10: str) -> bytes:
    k1, k2 = make_keys(key10)
    return bytes(int(decrypt_block(f"{byte:08b}", k1, k2), 2) for byte in data)


def pad(data: bytes) -> bytes:
    amount = 8 - (len(data) % 8)
    return data + bytes([amount]) * amount


def unpad(data: bytes) -> bytes:
    if not data or data[-1] < 1 or data[-1] > 8 or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("Padding буруу байна: түлхүүр эсвэл файл буруу байж болно.")
    return data[:-data[-1]]


def encrypt_file(source: Path, target: Path, key10: str) -> None:
    target.write_bytes(encrypt_bytes(pad(source.read_bytes()), key10))


def decrypt_file(source: Path, target: Path, key10: str) -> None:
    target.write_bytes(unpad(decrypt_bytes(source.read_bytes(), key10)))


def main() -> None:
    parser = argparse.ArgumentParser(description="S-DES: файл болон 8-бит блок шифрлэх/тайлах")
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("keys", help="K1, K2 үүсгэх")
    keys.add_argument("key", help="10-bit түлхүүр, жишээ: 1010000010")

    block = sub.add_parser("block", help="нэг 8-bit блок дээр ажиллах")
    block.add_argument("mode", choices=("encrypt", "decrypt"))
    block.add_argument("bits", help="8-bit binary")
    block.add_argument("key", help="10-bit binary")

    file_cmd = sub.add_parser("file", help="файл шифрлэх/тайлах")
    file_cmd.add_argument("mode", choices=("encrypt", "decrypt"))
    file_cmd.add_argument("source", type=Path)
    file_cmd.add_argument("target", type=Path)
    file_cmd.add_argument("key", help="10-bit binary")

    args = parser.parse_args()
    if args.command == "keys":
        k1, k2 = make_keys(args.key)
        print(f"K1 = {k1}\nK2 = {k2}")
    elif args.command == "block":
        k1, k2 = make_keys(args.key)
        result = (encrypt_block if args.mode == "encrypt" else decrypt_block)(args.bits, k1, k2)
        print(result)
    elif args.command == "file":
        if args.mode == "encrypt":
            encrypt_file(args.source, args.target, args.key)
        else:
            decrypt_file(args.source, args.target, args.key)
        print(f"Амжилттай: {args.target}")


if __name__ == "__main__":
    main()
