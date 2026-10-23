"""Small structurally valid class fixtures; no Java installation required."""

from __future__ import annotations

import struct


def class_bytes(name, source=None, *, metadata=True, kind=1, version=(2, 0, 0),
                facade="", parts=()):
    pool = []

    def utf(value):
        data = value.encode("utf-8")
        pool.append(b"\x01" + struct.pack(">H", len(data)) + data)
        return len(pool)

    def integer(value):
        pool.append(b"\x03" + struct.pack(">i", value))
        return len(pool)

    def u2(value):
        return struct.pack(">H", value)

    def class_entry(value):
        reference = utf(value)
        pool.append(b"\x07" + u2(reference))
        return len(pool)

    this, parent = class_entry(name), class_entry("java/lang/Object")
    attributes = []
    if source is not None:
        attributes.append((utf("SourceFile"), u2(utf(source))))
    if metadata:
        descriptor = utf("Lkotlin/Metadata;")
        values = [(utf("k"), b"I" + u2(integer(kind))),
                  (utf("mv"), b"[" + u2(len(version)) + b"".join(
                      b"I" + u2(integer(value)) for value in version))]
        if facade:
            values.append((utf("xs"), b"s" + u2(utf(facade))))
        if parts:
            values.append((utf("d1"), b"[" + u2(len(parts)) + b"".join(
                b"s" + u2(utf(value)) for value in parts)))
        annotation = u2(1) + u2(descriptor) + u2(len(values)) + b"".join(
            u2(key) + value for key, value in values)
        attributes.append((utf("RuntimeVisibleAnnotations"), annotation))
    payload = u2(0x21) + u2(this) + u2(parent) + u2(0) + u2(0) + u2(0)
    payload += u2(len(attributes)) + b"".join(
        u2(key) + struct.pack(">I", len(value)) + value for key, value in attributes)
    return b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + u2(len(pool) + 1) + b"".join(pool) + payload
