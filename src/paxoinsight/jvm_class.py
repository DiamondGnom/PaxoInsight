"""Bounded structural JVM inspection. Never loads or executes a scanned class."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAX_CLASS_BYTES = 8 * 1024**2


class ClassFormatError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.position + size > len(self.data):
            raise ClassFormatError("Обрезанная структура .class")
        start = self.position
        self.position += size
        return self.data[start:self.position]

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def done(self) -> None:
        if self.position != len(self.data):
            raise ClassFormatError("Некорректная длина структуры .class")


@dataclass(slots=True)
class ClassInfo:
    path: str
    name: str
    major: int
    source_file: str = ""
    kotlin: bool = False
    metadata_kind: int = 0
    metadata_version: tuple[int, ...] = ()
    facade: str = ""
    part_names: tuple[str, ...] = ()
    metadata_warning: str = ""
    fields: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    context: dict = field(default_factory=dict)

    @property
    def package(self) -> str:
        return self.name.rpartition("/")[0]


def modified_utf8(data: bytes) -> str:
    if b"\x00" in data or any(value >= 0xf0 for value in data):
        raise ClassFormatError("Недопустимая кодировка CONSTANT_Utf8")
    try:
        value = data.replace(b"\xc0\x80", b"\x00").decode("utf-8", "surrogatepass")
        return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
    except UnicodeError as error:
        raise ClassFormatError("Некорректная modified UTF-8 строка") from error


def parse_class(data: bytes, path: str = "") -> ClassInfo:
    if len(data) > MAX_CLASS_BYTES:
        raise ClassFormatError(".class превышает лимит разбора 8 МиБ")
    reader = Reader(data)
    if reader.take(4) != b"\xca\xfe\xba\xbe":
        raise ClassFormatError("Отсутствует заголовок CAFEBABE")
    reader.number(2)  # minor, including preview marker
    major = reader.number(2)
    if major < 45:
        raise ClassFormatError("Некорректная версия JVM")
    count = reader.number(2)
    pool: list[tuple | None] = [None] * count
    index = 1
    while index < count:
        tag = reader.number(1)
        if tag == 1:
            value = modified_utf8(reader.take(reader.number(2)))
        elif tag == 3:
            value = struct.unpack(">i", reader.take(4))[0]
        elif tag in {7, 8, 16, 19, 20}:
            value = reader.number(2)
        elif tag in {4, 9, 10, 11, 12, 17, 18}:
            value = reader.take(4)
        elif tag == 15:
            value = reader.take(3)
        elif tag in {5, 6}:
            value = reader.take(8)
            if index + 1 >= count:
                raise ClassFormatError("Некорректный Long/Double в constant pool")
        else:
            raise ClassFormatError(f"Неподдерживаемый constant pool tag {tag}")
        pool[index] = (tag, value)
        index += 2 if tag in {5, 6} else 1

    def constant(index: int, tag: int):
        if not 0 < index < count or pool[index] is None or pool[index][0] != tag:
            raise ClassFormatError("Некорректная ссылка constant pool")
        return pool[index][1]

    def text(index: int) -> str:
        return constant(index, 1)

    reader.number(2)  # access flags
    name = text(constant(reader.number(2), 7))
    if not name or any(part in {"", ".", ".."} for part in name.split("/")) or any(
        char in name for char in ".;[\\\x00"
    ):
        raise ClassFormatError("Некорректное внутреннее имя класса")
    superclass = reader.number(2)
    if superclass:
        text(constant(superclass, 7))
    for _ in range(reader.number(2)):
        text(constant(reader.number(2), 7))
    info = ClassInfo(path, name, major)

    def attributes(stream: Reader):
        for _ in range(stream.number(2)):
            attribute_name = text(stream.number(2))
            yield attribute_name, stream.take(stream.number(4))

    def members() -> tuple[str, ...]:
        names = []
        for _ in range(reader.number(2)):
            reader.number(2)
            names.append(text(reader.number(2)))
            text(reader.number(2))  # descriptor
            for _attribute, _data in attributes(reader):
                pass  # Code is never interpreted or executed.
        return tuple(names)

    info.fields, info.methods = members(), members()
    element_count = 0

    def annotation(stream: Reader, depth: int):
        if depth > 16:
            raise ClassFormatError("Слишком глубокая аннотация")
        descriptor = text(stream.number(2))
        values = {}
        for _ in range(stream.number(2)):
            key = text(stream.number(2))
            values[key] = element(stream, depth + 1)
        return descriptor, values

    def element(stream: Reader, depth: int):
        nonlocal element_count
        element_count += 1
        if depth > 16 or element_count > 100_000:
            raise ClassFormatError("Превышен лимит элементов аннотаций")
        tag = chr(stream.number(1))
        if tag == "s":
            return text(stream.number(2))
        if tag in "BCISZ":
            return constant(stream.number(2), 3)
        if tag in "DFJ":
            return constant(stream.number(2), {"D": 6, "F": 4, "J": 5}[tag])
        if tag == "e":
            return text(stream.number(2)), text(stream.number(2))
        if tag == "c":
            return text(stream.number(2))
        if tag == "@":
            return annotation(stream, depth + 1)
        if tag == "[":
            return [element(stream, depth + 1) for _ in range(stream.number(2))]
        raise ClassFormatError("Неизвестный тип элемента аннотации")

    seen = set()
    for attribute_name, payload in attributes(reader):
        if attribute_name not in {"SourceFile", "RuntimeVisibleAnnotations",
                                  "RuntimeInvisibleAnnotations"}:
            continue
        if attribute_name in seen:
            raise ClassFormatError("Повторяющийся атрибут .class")
        seen.add(attribute_name)
        attribute = Reader(payload)
        if attribute_name == "SourceFile":
            info.source_file = text(attribute.number(2))
        else:
            for _ in range(attribute.number(2)):
                descriptor, values = annotation(attribute, 0)
                if descriptor != "Lkotlin/Metadata;":
                    continue
                if info.kotlin:
                    raise ClassFormatError("Дублирующаяся Kotlin Metadata")
                info.kotlin = True
                kind, version = values.get("k", 1), values.get("mv", [])
                if not isinstance(kind, int) or not isinstance(version, list) or not all(
                    isinstance(item, int) for item in version
                ):
                    raise ClassFormatError("Некорректный заголовок Kotlin Metadata")
                info.metadata_kind = kind
                info.metadata_version = tuple(version)
                extra = values.get("xs", "")
                info.facade = extra if isinstance(extra, str) else ""
                parts = values.get("d1", [])
                if kind == 4 and isinstance(parts, list):
                    info.part_names = tuple(item for item in parts if isinstance(item, str))
                if kind not in {1, 2, 3, 4, 5} or not version or version[0] not in {1, 2}:
                    info.metadata_warning = "Неизвестная версия/вид Kotlin Metadata"
        attribute.done()
    reader.done()
    return info
