"""One in-memory source/bytecode index per analysis; no database or JVM required."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path, PurePosixPath
from threading import Event

from .jvm_class import MAX_CLASS_BYTES, ClassInfo, parse_class
from .kotlin_coverage import coverage_for_mapping
from .kotlin_source import MAX_SOURCE_BYTES, SourceInfo, parse_source, path_context
from .models import OperationCancelled

MAX_ANALYSIS_BYTES = 512 * 1024**2
MAX_CANDIDATES = 64
STATUS_LABELS = {
    "confirmed": "ПОДТВЕРЖДЕНО", "partial": "ЧАСТИЧНО", "probable": "ПРЕДПОЛОЖИТЕЛЬНО",
    "ambiguous": "НЕОДНОЗНАЧНО", "missing": "НЕ ОБНАРУЖЕН", "unverified": "НЕ ПРОВЕРЕНО",
    "not_applicable": "НЕ ПРИМЕНИМО",
}


def _compatible(source: dict, binary: dict) -> tuple[bool, bool]:
    left, right = source["module"], binary["module"]
    if left is not None and right is not None and left != right:
        return False, False
    source_known = bool(source["source_set"]) or source["test"]
    binary_known = bool(binary["source_set"]) or binary["test"]
    if source_known and binary_known and source["test"] != binary["test"]:
        return False, False
    if (source.get("target") and binary.get("target")
            and source["target"] != binary["target"]):
        return False, False
    if (source.get("source_group") and binary.get("source_group") and source["test"]
            and source["source_group"] != binary["source_group"]):
        return False, False
    a, b = source["source_set"].lower(), binary["source_set"].lower()
    variant_match = a and a == binary["variant"].lower()
    usual = {"main", "test", "jvmmain", "jvmtest", "commonmain", "commontest",
             "androidmain", "androidtest", "androidunittest", "androidinstrumentedtest",
             "testfixtures"}
    same_group = source.get("source_group") in {"main", "unit_test", "instrumented", "fixtures"}
    same_group = same_group and source.get("source_group") == binary.get("source_group")
    if (a and b and a != b and not variant_match and not same_group
            and (a not in usual or b not in usual)):
        return False, False
    firm = left is not None and left == right and not binary["dependency"]
    return True, firm


def _checked_path(root: Path, relative: str) -> Path:
    original = root / relative
    if original.is_symlink():
        raise ValueError("Ссылка вместо файла анализа")
    path = original.resolve()
    path.relative_to(root.resolve())
    return path


class KotlinIndex:
    def __init__(self, root: Path, cancelled: Event | None = None):
        self.root = root
        self.cancelled = cancelled
        self.classes: list[ClassInfo] = []
        self.by_path: dict[str, ClassInfo] = {}
        self.by_name: dict[str, list[ClassInfo]] = defaultdict(list)
        self.by_source: dict[tuple[str, str], list[ClassInfo]] = defaultdict(list)
        self.scoped_name: dict[tuple, list[ClassInfo]] = defaultdict(list)
        self.scoped_source: dict[tuple, list[ClassInfo]] = defaultdict(list)
        self.invalid: list[dict] = []
        self.invalid_count = 0
        self.invalid_by_stem: dict[str, list[str]] = defaultdict(list)
        self.bytes_read = 0
        self.incomplete = False

    def check(self) -> None:
        if self.cancelled is not None and self.cancelled.is_set():
            raise OperationCancelled("Операция отменена")

    def read(self, relative: str, maximum: int) -> bytes:
        self.check()
        path = _checked_path(self.root, relative)
        size = path.stat().st_size
        if size > maximum:
            raise ValueError("Превышен лимит размера файла статического анализа")
        if self.bytes_read + size > MAX_ANALYSIS_BYTES:
            self.incomplete = True
            raise ValueError("Превышен суммарный лимит чтения Kotlin/JVM 512 МиБ")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        self.bytes_read += len(data)
        if len(data) > maximum or self.bytes_read > MAX_ANALYSIS_BYTES:
            self.incomplete = True
            raise ValueError("Файл вырос во время статического анализа")
        return data

    def index_classes(self, paths: list[str]) -> None:
        for path in paths:
            self.check()
            try:
                info = parse_class(self.read(path, MAX_CLASS_BYTES), path)
                info.context = path_context(path, binary_name=info.name)
            except (OSError, ValueError) as error:
                self.invalid_count += 1
                if len(self.invalid) < 2_000:
                    self.invalid.append({"path": path, "reason": str(error)})
                stem = PurePosixPath(path.replace("\\", "/")).stem
                if len(self.invalid_by_stem[stem]) < MAX_CANDIDATES:
                    self.invalid_by_stem[stem].append(path)
                continue
            self.classes.append(info)
            self.by_path[path] = info
            self.by_name[info.name].append(info)
            self.scoped_name[(info.name, info.context["module"])].append(info)
            if info.source_file:
                self.by_source[(info.package, info.source_file)].append(info)
                self.scoped_source[(info.package, info.source_file,
                                    info.context["module"])].append(info)

    def source(self, path: str) -> SourceInfo:
        try:
            # Scripts/non-JVM files don't need to be opened to classify them.
            context = path_context(path)
            data = (b"" if path.lower().endswith(".kts") or context["non_jvm"]
                    else self.read(path, MAX_SOURCE_BYTES))
            info = parse_source(data, path)
            norm = path.replace("\\", "/")
            if info.context["module"] is None and (
                norm == PurePosixPath(norm).name
                or str(PurePosixPath(norm).parent) == info.package
            ):
                info.context["module"] = ""
            return info
        except (OSError, UnicodeError, ValueError) as error:
            return SourceInfo(path, notes=[str(error)], context=path_context(path))

    def match(self, source: SourceInfo, label: str, expected: str,
              *, part: bool = False, facade: bool = False, duplicate: bool = False,
              expected_kind: int = 1) -> dict:
        filename = PurePosixPath(source.path.replace("\\", "/")).name
        raw = (self.by_source.get((source.package, filename), []) if part
               else self.by_name.get(expected, []))
        module = source.context["module"]
        if module is not None:
            raw = ([*self.scoped_source.get((source.package, filename, module), []),
                    *self.scoped_source.get((source.package, filename, None), [])] if part else
                   [*self.scoped_name.get((expected, module), []),
                    *self.scoped_name.get((expected, None), [])])
        inferred_facade = False
        if not raw and expected_kind == 2 and not source.facade_explicit:
            by_origin = (self.by_source.get((source.package, filename), []) if module is None else
                         [*self.scoped_source.get((source.package, filename, module), []),
                          *self.scoped_source.get((source.package, filename, None), [])])
            raw = [item for item in by_origin if item.metadata_kind == 2]
            inferred_facade = bool(raw)
        possible = []
        for info in raw:
            allowed, firm = _compatible(source.context, info.context)
            if not allowed:
                continue
            if part:
                required_facade = (source.package + "/" if source.package else "") + source.facade
                named_facade = info.facade if "/" in info.facade else (
                    (info.package + "/" if info.package else "") + info.facade
                )
                if info.metadata_kind != 5 or named_facade != required_facade:
                    continue
            possible.append((info, firm))
            if len(possible) > MAX_CANDIDATES:
                break
        record = {"declaration": label, "expected": expected + ("" if part else ".class"),
                  "classes": [], "status": "missing", "reason": "Ожидаемый класс не найден",
                  "shared_facade": facade}
        if not possible:
            stem = expected.rsplit("/", 1)[-1]
            damaged = [path for path in self.invalid_by_stem.get(stem, [])
                       if _compatible(source.context, path_context(path))[0]]
            if self.incomplete or damaged:
                record.update(status="unverified", reason="Байткод повреждён или разбор ограничен",
                              classes=damaged)
            return record
        record["classes"] = sorted({info.path for info, _firm in possible})
        if len(possible) > 1 or duplicate:
            record.update(status="ambiguous",
                          reason="Несколько классов/исходников или вариантов сборки")
            return record
        info, firm = possible[0]
        if inferred_facade:
            record["expected"] = info.name + ".class"
            record["inferred_facade"] = True
        reasons = []
        contradictions = []
        if not firm:
            reasons.append("контекст модуля/зависимости не подтверждён")
        if not info.kotlin:
            reasons.append("нет аннотации kotlin.Metadata")
        elif info.metadata_kind != (5 if part else expected_kind):
            contradictions.append("вид Kotlin Metadata противоречит ожидаемому объявлению")
        if not facade and info.source_file != filename:
            if info.source_file:
                contradictions.append("SourceFile указывает другой исходник")
            else:
                reasons.append("SourceFile отсутствует")
        if facade and info.metadata_kind != 4:
            reasons.append("не подтверждён multifile-фасад")
        norm = info.path.replace("\\", "/")
        if not (norm == info.name + ".class" or norm.endswith("/" + info.name + ".class")):
            reasons.append("путь .class отличается от внутреннего имени")
        if info.metadata_warning or contradictions:
            record.update(status="unverified", reason="; ".join(
                [*contradictions, *([info.metadata_warning] if info.metadata_warning else [])]
            ))
        elif reasons:
            record.update(status="probable", reason="; ".join(reasons))
        else:
            record.update(status="confirmed", reason=(
                "Связь multifile-части с фасадом, Kotlin Metadata и контекст сборки"
                if facade else "Внутреннее имя, SourceFile, Kotlin Metadata и контекст сборки"
            ))
        return record

    def mapping(self, paths: list[str], uninspected: list[str] | None = None) -> dict:
        sources = [self.source(path) for path in paths]
        owners: dict[tuple, int] = defaultdict(int)
        source_owners: dict[tuple, int] = defaultdict(int)
        for source in sources:
            source_owners[(source.context["module"], source.context["test"], source.package,
                           PurePosixPath(source.path.replace("\\", "/")).name)] += 1
            for _label, name in source.declarations:
                owners[(source.context["module"], source.context.get("source_group"),
                        source.context.get("target"), name)] += 1
        rows = []
        used = set()
        for source in sources:
            self.check()
            row = {"source": source.path, "status": "unverified", "classes": [],
                   "declarations": [], "reason": "", "context": source.context,
                   "recognition_complete": not source.notes}
            if source.excluded:
                row.update(status="not_applicable", reason=source.excluded)
                rows.append(row)
                continue
            declarations = []
            for label, name in source.declarations:
                duplicate = owners[(source.context["module"], source.context.get("source_group"),
                                    source.context.get("target"), name)] > 1
                declarations.append(self.match(source, label, name, duplicate=duplicate))
            if source.facade:
                name = (source.package + "/" if source.package else "") + source.facade
                if source.multifile:
                    declarations.append(self.match(source, "Multifile-часть исходника",
                                                   source.path, part=True))
                declarations.append(self.match(source, "Фасад пакетных объявлений", name,
                                               facade=source.multifile,
                                               expected_kind=4 if source.multifile else 2))
                if source.multifile and all(item["status"] == "confirmed"
                                           for item in declarations[-2:]):
                    part_names = {self.by_path[path].name
                                  for path in declarations[-2]["classes"]}
                    facades = [self.by_path[path] for path in declarations[-1]["classes"]]
                    if not facades or not part_names.issubset(set(facades[0].part_names)):
                        declarations[-1].update(
                            status="probable",
                            reason="Фасад не подтверждает список multifile-частей"
                        )
            if uninspected:
                for declaration in declarations:
                    if declaration["status"] == "missing":
                        declaration.update(status="unverified", reason=(
                            "Остались непроверенные архивы; включите распаковку контейнеров "
                            "и повторите анализ"
                        ))
            statuses = {item["status"] for item in declarations}
            if "ambiguous" in statuses:
                status = "ambiguous"
            elif statuses == {"confirmed"}:
                status = "confirmed"
            elif "confirmed" in statuses:
                status = "partial"
            elif "unverified" in statuses or not statuses:
                status = "unverified"
            elif "probable" in statuses:
                status = "probable"
            else:
                status = "missing"
            if source.notes and status == "confirmed":
                status = "probable"
            elif source.notes and status == "missing":
                status = "unverified"
            found = sorted({path for item in declarations for path in item["classes"]})
            used.update(found)
            filename = PurePosixPath(source.path.replace("\\", "/")).name
            source_key = (source.context["module"], source.context["test"],
                          source.package, filename)
            auxiliary = []
            if source_owners[source_key] == 1:
                candidates = self.scoped_source.get((source.package, filename,
                                                     source.context["module"]), [])
                for item in candidates:
                    if item.metadata_kind == 3 and _compatible(source.context, item.context)[1]:
                        used.add(item.path)
                        if len(auxiliary) < MAX_CANDIDATES:
                            auxiliary.append(item.path)
            reasons = list(dict.fromkeys([*source.notes, *(item["reason"] for item in declarations
                                                          if item["status"] != "confirmed")]))
            if not reasons:
                reasons = ["Подтверждена структурная связь исходника и байткода; "
                           "тождество версии исходников не проверяется"]
            row.update(status=status, classes=found, declarations=declarations,
                       reason="; ".join(reasons), auxiliary_classes=auxiliary)
            rows.append(row)
        # An unknown-layout class cannot cover several different source files.
        # A genuine multifile facade is the intentional exception.
        claims: dict[str, list[tuple[int, dict]]] = defaultdict(list)
        for index, row in enumerate(rows):
            for declaration in row["declarations"]:
                if declaration["status"] in {"confirmed", "probable"}:
                    for path in declaration["classes"]:
                        claims[path].append((index, declaration))
        collisions = set()
        for bindings in claims.values():
            if len({index for index, _ in bindings}) < 2 or all(
                declaration.get("shared_facade") for _, declaration in bindings
            ):
                continue
            for index, declaration in bindings:
                declaration.update(status="ambiguous", reason=(
                    "Один class-файл претендует на несколько разных исходников"
                ))
                collisions.add(index)
        for index in collisions:
            rows[index]["status"] = "ambiguous"
            rows[index]["reason"] += "; один class-файл связан с несколькими исходниками"
        missing = {row["source"] for row in rows if row["status"] == "missing"}
        matched = [{"kt": row["source"], "classes": row["classes"]}
                   for row in rows if row["status"] == "confirmed"]
        orphan = [info.path for info in self.classes if info.path not in used
                  and (info.kotlin or info.source_file.endswith((".kt", ".kts")))]
        result = {
            "schema_version": 2, "engine": "python-structural-jvm", "records": rows,
            "matched": matched, "unmatched_kt": sorted(missing),
            "unmatched_main": [row["source"] for row in rows if row["source"] in missing
                               and not row["context"]["test"]],
            "unmatched_test": [row["source"] for row in rows if row["source"] in missing
                               and row["context"]["test"]],
            "orphan_kt_classes": sorted(orphan), "total_kt": sum(
                row["status"] != "not_applicable" for row in rows
            ), "total_matched": len(matched), "invalid_classes": self.invalid,
            "invalid_class_count": self.invalid_count, "bytes_read": self.bytes_read,
            "uninspected_containers": uninspected or [],
            "index_incomplete": self.incomplete,
            "limitations": ["Разбираются объявления Kotlin и заголовки JVM/Kotlin Metadata; "
                            "protobuf d1/d2, SMAP, DEX и семантика методов не анализируются. "
                            "Сопоставление не доказывает сборку из данной версии исходников."],
        }
        result["coverage"] = coverage_for_mapping(result)
        return result

    def bytecode_versions(self) -> dict:
        versions: dict[str, list[str]] = defaultdict(list)
        for info in self.classes:
            version = f"Java {info.major - 44}" if info.major >= 49 else f"JVM major {info.major}"
            versions[version].append(info.path)
        dominant = max(versions, key=lambda name: len(versions[name])) if versions else ""
        mismatch_count = sum(len(paths) for version, paths in versions.items()
                             if version != dominant)
        mismatches = []
        for version, paths in versions.items():
            if version != dominant:
                mismatches.extend({"path": path, "version": version}
                                  for path in paths[:max(0, 100 - len(mismatches))])
        return {"versions": dict(versions), "dominant": dominant,
                "mismatch_count": mismatch_count, "mismatches": mismatches,
                "total_parsed": len(self.classes), "failed_parse": self.invalid_count}
