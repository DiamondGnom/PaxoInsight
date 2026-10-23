"""Conservative Kotlin declaration lexer, not a compiler or executable build tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath

MAX_SOURCE_BYTES = 2 * 1024**2
MAX_TOKENS = 200_000


@dataclass(slots=True)
class SourceInfo:
    path: str
    package: str = ""
    declarations: list[tuple[str, str]] = field(default_factory=list)
    facade: str = ""
    facade_explicit: bool = False
    multifile: bool = False
    notes: list[str] = field(default_factory=list)
    excluded: str = ""
    context: dict = field(default_factory=dict)


def path_context(path: str, *, binary_name: str = "") -> dict:
    parts = path.replace("\\", "/").split("/")
    module, source_set, variant, target = None, "", "", ""
    if "src" in parts:
        index = parts.index("src")
        module = "/".join(parts[:index])
        if len(parts) > index + 2 and parts[index + 2] in {"kotlin", "java"}:
            source_set = parts[index + 1]
    elif "build" in parts:
        index = parts.index("build")
        module = "/".join(parts[:index])
        rest = parts[index + 1:]
        if len(rest) >= 3 and rest[0] == "classes" and rest[1] in {"kotlin", "java"}:
            source_set = rest[2]
            if (len(rest) >= 5 and rest[2].lower() not in {"main", "test", "testfixtures"}
                    and rest[3].lower() in {"main", "test", "testfixtures"}):
                target, source_set = rest[2].lower(), rest[3]
        elif len(rest) >= 3 and rest[:2] == ["tmp", "kotlin-classes"]:
            variant = rest[2]
            source_set = ("androidTest" if "androidtest" in variant.lower() else
                          "testFixtures" if "fixtures" in variant.lower() else
                          "test" if "test" in variant.lower() else "main")
            target = "android"
        else:
            module = None  # An unknown build layout must not become a firm match.
    elif "target" in parts:
        index = parts.index("target")
        if len(parts) > index + 1 and parts[index + 1] in {"classes", "test-classes"}:
            module = "/".join(parts[:index])
            source_set = "test" if parts[index + 1] == "test-classes" else "main"
    elif binary_name and path.replace("\\", "/") == binary_name + ".class":
        module = ""  # A loose package tree at archive root, not an arbitrary JAR.
    lower = source_set.lower()
    test = "test" in lower or any(
        part.lower() in {"test", "tests", "testfixtures", "androidtest"} for part in parts
    )
    non_jvm = lower.startswith(("js", "wasm", "ios", "linux", "mingw", "macos",
                                "native", "watchos", "tvos", "androidnative"))
    if not target and lower not in {"main", "test", "commonmain", "commontest",
                                     "testfixtures", "androidtest"}:
        if lower.endswith("main"):
            target = lower[:-4]
        elif lower.endswith("test"):
            target = "android" if lower.startswith("android") else lower[:-4]
    if "fixture" in lower:
        source_group = "fixtures"
    elif lower == "androidtest" or "instrumented" in lower:
        source_group = "instrumented"
        target = target or "android"
    elif test:
        source_group = "unit_test"
    elif lower in {"main", "commonmain"} or lower.endswith("main"):
        source_group = "main"
    else:
        source_group = lower
    dependency = any(part.lower() in {"libs", "lib", "vendor", "third_party", "node_modules"}
                     for part in parts[:-1])
    return {"module": module, "source_set": source_set, "variant": variant,
            "test": test, "non_jvm": non_jvm, "dependency": dependency,
            "target": target, "source_group": source_group}


def _comment_end(text: str, position: int) -> int:
    depth, position = 1, position + 2
    while position < len(text) and depth:
        if text.startswith("/*", position):
            depth += 1
            if depth > 64:
                raise ValueError("Слишком глубокие комментарии Kotlin")
            position += 2
        elif text.startswith("*/", position):
            depth -= 1
            position += 2
        else:
            position += 1
    if depth:
        raise ValueError("Незавершённый комментарий Kotlin")
    return position


def _template_end(text: str, position: int, depth: int) -> int:
    braces = 1
    while position < len(text):
        if text.startswith("//", position):
            end = text.find("\n", position)
            position = len(text) if end < 0 else end
        elif text.startswith("/*", position):
            position = _comment_end(text, position)
        elif text[position] in {'"', "'"}:
            position, _interpolated = _string_end(text, position, depth + 1)
        elif text[position] == "$":
            end = position
            while end < len(text) and text[end] == "$":
                end += 1
            if text.startswith('"""', end):
                position, _interpolated = _string_end(text, end, depth + 1, end - position)
            else:
                position = end
        elif text[position] == "`":
            end = text.find("`", position + 1)
            if end < 0:
                raise ValueError("Незавершённый идентификатор Kotlin")
            position = end + 1
        elif text[position] == "{":
            braces += 1
            if braces > 64:
                raise ValueError("Слишком глубокий строковый шаблон Kotlin")
            position += 1
        elif text[position] == "}":
            braces -= 1
            position += 1
            if not braces:
                return position
        else:
            position += 1
    raise ValueError("Незавершённый строковый шаблон Kotlin")


def _string_end(text: str, start: int, depth: int = 0, dollars: int = 1) -> tuple[int, bool]:
    if depth > 16:
        raise ValueError("Слишком глубокая вложенность строк Kotlin")
    quote = '"""' if text.startswith('"""', start) else text[start]
    position = start + len(quote)
    interpolated = False
    while position < len(text):
        if text.startswith(quote, position):
            return position + len(quote), interpolated
        if len(quote) == 1 and text[position] == "\\":
            position += 2
        elif quote != "'" and text[position] == "$":
            end = position
            while end < len(text) and text[end] == "$":
                end += 1
            if end - position >= dollars and end < len(text) and text[end] == "{":
                interpolated = True
                position = _template_end(text, end + 1, depth)
            else:
                if end - position >= dollars and end < len(text) and (
                    text[end].isalpha() or text[end] in {"_", "`"}
                ):
                    interpolated = True
                position = end
        else:
            position += 1
    raise ValueError("Незавершённая строка Kotlin")


def _literal(text: str) -> str:
    result = []
    position = 0
    escapes = {"t": "\t", "b": "\b", "n": "\n", "r": "\r", "'": "'", '"': '"',
               "\\": "\\", "$": "$"}
    while position < len(text):
        if text[position] != "\\":
            result.append(text[position])
            position += 1
            continue
        position += 1
        if position >= len(text):
            raise ValueError("Незавершённая escape-последовательность Kotlin")
        character = text[position]
        if character == "u":
            digits = text[position + 1:position + 5]
            if len(digits) != 4:
                raise ValueError("Некорректный Unicode escape Kotlin")
            result.append(chr(int(digits, 16)))
            position += 5
        elif character in escapes:
            result.append(escapes[character])
            position += 1
        else:
            raise ValueError("Неизвестная escape-последовательность Kotlin")
    return "".join(result).encode("utf-16-le", "surrogatepass").decode("utf-16-le")


def _qualified(tokens: list[tuple[str, str]], start: int) -> tuple[str, int]:
    if start >= len(tokens) or tokens[start][0] not in {"id", "escaped_id"}:
        return "", start
    values = [tokens[start][1]]
    position = start + 1
    while position + 1 < len(tokens) and tokens[position][1] == "." and (
        tokens[position + 1][0] in {"id", "escaped_id"}
    ):
        values.append(tokens[position + 1][1])
        position += 2
    return ".".join(values), position


def _tokens(text: str) -> list[tuple[str, str]]:
    result = []
    position = 0
    while position < len(text):
        start = position
        character = text[position]
        if character in " \t\r":
            position += 1
            continue
        if text.startswith("//", position):
            end = text.find("\n", position)
            position = len(text) if end < 0 else end
            continue
        if text.startswith("/*", position):
            position = _comment_end(text, position)
            continue
        dollars = 1
        if character == "$":
            end = position
            while end < len(text) and text[end] == "$":
                end += 1
            if text.startswith('"""', end):
                dollars, position = end - position, end
                character = '"'
        if character in {'"', "'"}:
            start = position
            position, interpolated = _string_end(text, position, dollars=dollars)
            width = 3 if text.startswith('"""', start) else 1
            value = ""
            if not interpolated:
                raw = text[start + width:position - width]
                value = raw if width == 3 else _literal(raw)
            result.append(("template" if interpolated else "string", value))
        elif character == "`":
            end = text.find("`", position + 1)
            if end < 0:
                raise ValueError("Незавершённый идентификатор Kotlin")
            result.append(("escaped_id", text[position + 1:end]))
            position = end + 1
        elif character.isalpha() or character == "_":
            position += 1
            while position < len(text) and (text[position].isalnum() or text[position] == "_"):
                position += 1
            result.append(("id", text[start:position]))
        else:
            position += 1
            result.append(("symbol", character))
        if len(result) > MAX_TOKENS:
            raise ValueError("Превышен лимит токенов Kotlin")
    return result


def parse_source(data: bytes, path: str) -> SourceInfo:
    info = SourceInfo(path, context=path_context(path))
    if path.lower().endswith(".gradle.kts"):
        info.excluded = "Gradle-скрипт: байткод приложения не ожидается"
        return info
    if path.lower().endswith(".kts"):
        info.excluded = "Kotlin-скрипт: требуется отдельная модель компиляции"
        return info
    if info.context["non_jvm"]:
        info.excluded = "Набор исходников другой платформы, не JVM"
        return info
    if len(data) > MAX_SOURCE_BYTES:
        raise ValueError("Kotlin-исходник превышает лимит 2 МиБ")
    text = data.decode("utf-8-sig")
    tokens = _tokens(text)
    values = [value for _kind, value in tokens]
    jvm_name = ""
    imports = {}
    for index, value in enumerate(values):
        if value == "package" and tokens[index][0] == "id":
            package, _cursor = _qualified(tokens, index + 1)
            info.package = package.replace(".", "/")
        elif value == "import" and tokens[index][0] == "id":
            name, cursor = _qualified(tokens, index + 1)
            alias = name.rsplit(".", 1)[-1]
            if cursor + 1 < len(tokens) and values[cursor] == "as":
                alias = values[cursor + 1]
            imports[alias] = name
    # File annotations may use fully-qualified names. No evaluation of constants.
    for index in range(len(tokens) - 3):
        if values[index:index + 3] != ["@", "file", ":"]:
            continue
        name, cursor = _qualified(tokens, index + 3)
        resolved = imports.get(name, name)
        if "." in resolved and not resolved.startswith("kotlin.jvm."):
            continue
        annotation = resolved.rsplit(".", 1)[-1]
        if annotation == "JvmMultifileClass":
            info.multifile = True
        if annotation == "JvmPackageName":
            info.notes.append("@file:JvmPackageName требует отдельного сопоставления JVM-пакета")
        if annotation == "JvmName":
            if (cursor + 2 < len(tokens) and values[cursor] == "("
                    and tokens[cursor + 1][0] == "string" and values[cursor + 1]
                    and values[cursor + 2] == ")"):
                jvm_name = values[cursor + 1]
            else:
                info.notes.append("@file:JvmName задан не простым строковым литералом")
    scopes: list[tuple[str, str, str | None]] = []
    pending = None
    parentheses = 0
    top_level = False
    expect_seen = False
    modifiers = set()
    for index, (kind, value) in enumerate(tokens):
        if value == "(" and kind == "symbol":
            parentheses += 1
        elif value == ")" and kind == "symbol":
            parentheses -= 1
            if parentheses < 0:
                raise ValueError("Несогласованные скобки Kotlin")
        if kind == "symbol" and value == "{":
            if len(scopes) >= 64:
                raise ValueError("Слишком глубокие объявления Kotlin")
            scopes.append(("class", pending, None) if pending and parentheses == 0
                          else ("other", "", pending if parentheses else None))
            if parentheses == 0:
                pending = None
            modifiers.clear()
        elif kind == "symbol" and value == "}":
            if not scopes:
                raise ValueError("Несогласованные скобки Kotlin")
            _kind, _owner, pending = scopes.pop()
            modifiers.clear()
        elif kind == "symbol" and value in {";", "="} and parentheses == 0:
            pending = None
            modifiers.clear()
        if kind != "id" or parentheses:
            continue
        declaration_scope = all(scope[0] == "class" for scope in scopes)
        if not declaration_scope:
            continue
        if value in {"expect", "actual", "companion"}:
            modifiers.add(value)
        if value not in {"class", "interface", "object", "fun", "val", "var", "typealias"}:
            continue
        previous = values[index - 1] if index else ""
        if value == "class" and previous == ":":
            continue  # Foo::class is a literal, not a declaration.
        if value in {"fun", "val", "var", "typealias"}:
            if value == "fun" and index + 1 < len(tokens) and values[index + 1] == "interface":
                continue
            pending = None
            if not scopes:
                if "expect" in modifiers:
                    expect_seen = True
                else:
                    top_level = True
            modifiers.clear()
            continue
        next_kind, name = tokens[index + 1] if index + 1 < len(tokens) else ("", "")
        if value == "object" and "companion" in modifiers and next_kind not in {"id", "escaped_id"}:
            name = "Companion"
        elif next_kind not in {"id", "escaped_id"}:
            continue  # Anonymous objects don't have a predictable JVM class name.
        if name in {"class", "interface", "object"}:
            info.notes.append("Неоднозначное объявление Kotlin")
            continue
        owner = next((scope[1] for scope in reversed(scopes) if scope[0] == "class"), "")
        local = owner + "$" + name if owner else name
        if "expect" in modifiers:
            expect_seen = True
            pending = None
        else:
            full = (info.package + "/" if info.package else "") + local
            info.declarations.append((f"{value} {name}", full))
            pending = local
        modifiers.clear()
    if parentheses or scopes:
        raise ValueError("Незавершённая структура Kotlin")
    if top_level:
        stem = PurePosixPath(path.replace("\\", "/")).stem
        default = stem[:1].upper() + stem[1:] + "Kt"
        info.facade = jvm_name or default
        info.facade_explicit = bool(jvm_name)
        if any(char in info.facade for char in "/.;[\\"):
            info.notes.append("Нестандартное имя JVM-фасада")
    if expect_seen:
        info.notes.append("expect-декларации требуют сопоставления с actual, отдельно не проверены")
    if not info.declarations and not info.facade:
        if not tokens or expect_seen or set(values) <= {"\n", ";"}:
            info.excluded = "Нет самостоятельных JVM-деклараций"
        else:
            info.notes.append("Не обнаружены уверенно распознаваемые JVM-декларации")
    if len(info.declarations) > 2_000:
        raise ValueError("Слишком много объявлений в Kotlin-файле")
    return info
