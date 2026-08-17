"""Fingerprint policy для нейтрализации запрещённых product-названий."""

from __future__ import annotations

import base64
import hashlib
import re
from urllib.parse import unquote


_MAX_DECODE_DEPTH = 3
_MAX_DECODED_CHARS = 2_000_000
_MAX_VARIANTS = 64
_FINGERPRINTS = frozenset({
    "0b79cf2de0ee6b8ee227d9ebfe69b91aa92b1d2509641c4b743518447dbc4c68",
    "053ea4804ef1bb33d4a3d6fb024a614b6d257cebc2bc7cd915da9c9522f37ffc",
    "3ea125d0bff386e6754b3782b300016fc79a9cf8f8669c0a5c3db64467ddb681",
    "45d780f82c9247fc1142f8b60c12b6c6cd3d9f23dd836cfa6e84c498d2f83292",
    "46a4eebd20d881ecfc0ecb54f6d8346524fadb143726d256b1a045303fc67717",
    "57de4cf40144bdf7d00010f2f5557a7d642c2b9705309bfade167dd313e2ca93",
    "5d72436256ada53828b51895a94bb8489e9f1ac4fe937a8024ef1594e7045ff6",
    "60965168ce762e949600281ba6d01fee136e5b6e8257b1f216f9025ed324474c",
    "67f2d22514622d1be30c14ee9f3cb104503a159a33a656ca91a1953aa9616429",
    "6f7ac1823da81d2e52d1a1549ee69c85bbf8bb56d06682849e7c09da2785ce3b",
    "76e3c7bfe641ea125c0c2e1c5f89349e17b352ed128d528de2443794e7acf870",
    "7d3194f79e645c42e4396dda38be04766810ec6a00d00aced3ffc2a0a1f1a9ef",
    "920510199770f4d65cb8aaa2cd12bdb2b8c37f5b3907c50a734a0e3409da2823",
    "c70eca6b0f88f44d81a41311647e50fda1ac454ec04ffd442b0eb4743a993131",
    "c857d09db23e6822e3600bc06ad8d58f92ed62bc8efd81c753f77048662cb97d",
    "d203a277f19a8f7d78fe8e9a621534b2cbd8ef1f0d809908ffc481e778858872",
    "dcc8d7506b63db23eb69667c87a92d82a8bfa0f1320fda7c40f425b5b5db8d42",
    "fc5a1047f5919892fcdf8aa79ea5d6bb6531b5c176939ef0110906cb225941c1",
    "ec8207a3dde607f7867f8f5390915018488b877761306ffd4ef099f9b3ee16a1",
    "f3f2184b56f946c6275818ac52ec46744944aa53a6bc8b65d6c796db83529fee",
    "ad3fc2c957602b6377c2bb1aba065717736fab1d12de083a7edb1206757dd788",
    "add92b9cde2bdbf3daaf65a0db79e9b1a7fa428b71b4d6ce38c742eb6dca0c1c",
    "2d7f45d7b98b427f824e0c643295583e9cf013faffdb5e7095d070ff85276bf4",
})
_TOKEN = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


def contains_prohibited_term(value: str) -> bool:
    """Проверяет plain и bounded encoded variants без раскрытия исходных терминов."""

    seen = {value}
    frontier = (value,)
    for _ in range(_MAX_DECODE_DEPTH + 1):
        if any(_contains_plain_marker(variant) for variant in frontier):
            return True
        decoded = []
        for variant in frontier:
            for candidate in _decode_once(variant):
                if candidate in seen or len(candidate) > _MAX_DECODED_CHARS:
                    continue
                seen.add(candidate)
                decoded.append(candidate)
                if len(seen) >= _MAX_VARIANTS:
                    break
            if len(seen) >= _MAX_VARIANTS:
                break
        if not decoded:
            return False
        frontier = tuple(decoded)
    return False


def neutral_repository_path(value: str) -> str:
    """Возвращает исходный safe path или стабильный opaque placeholder."""

    if not contains_prohibited_term(value):
        return value
    return f"restricted/{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _decode_once(value: str) -> tuple[str, ...]:
    variants = [unquote(value)]
    variants.append(re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), value))
    for token in re.findall(r"[A-Za-z0-9+/=]{4,128}", value):
        try:
            variants.append(base64.b64decode(token, validate=True).decode("utf-8"))
        except (UnicodeError, ValueError):
            continue
    for token in re.findall(r"(?:[0-9a-fA-F]{2}){3,64}", value):
        try:
            variants.append(bytes.fromhex(token).decode("utf-8"))
        except UnicodeError:
            continue
    return tuple(variant for variant in variants if variant != value)


def _contains_plain_marker(value: str) -> bool:
    tokens = tuple(token.lower() for token in _TOKEN.findall(value))
    for start in range(len(tokens)):
        combined = ""
        for token in tokens[start:start + 3]:
            combined += token
            if hashlib.sha256(combined.encode("ascii")).hexdigest() in _FINGERPRINTS:
                return True
    return False
