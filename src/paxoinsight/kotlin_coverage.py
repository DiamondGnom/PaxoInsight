"""Explainable coverage estimates. No confidence weights or SAST coverage claims."""

from __future__ import annotations


def _group(records: list[dict]) -> dict:
    eligible = [row for row in records if row.get("status") != "not_applicable"]
    confirmed = estimated = 0.0
    units = confirmed_units = probable_units = unresolved = 0
    for row in eligible:
        declarations = [item for item in row.get("declarations", []) if isinstance(item, dict)]
        count = len(declarations)
        certain = sum(item.get("status") == "confirmed" for item in declarations)
        probable = sum(item.get("status") == "probable" for item in declarations)
        complete = row.get("recognition_complete",
                           bool(count) and row.get("status") != "unverified")
        if not complete or any(item.get("status") in {"unverified", "ambiguous"}
                               for item in declarations):
            unresolved += 1
        if count:
            confirmed += certain / count if complete else 0.0
            estimated += (certain + probable) / count
        units += count
        confirmed_units += certain if complete else 0
        probable_units += probable + (certain if not complete else 0)
    files = len(eligible)
    available = bool(files and units)
    return {"applicable_files": files, "excluded_files": len(records) - files,
            "expected_units": units, "confirmed_units": confirmed_units,
            "probable_units": probable_units, "unresolved_files": unresolved,
            "confirmed_percent": round(100 * confirmed / files, 1) if available else None,
            "estimated_percent": round(100 * estimated / files, 1) if available else None}


def coverage_for_mapping(mapping: dict) -> dict:
    records = mapping.get("records")
    legacy = not isinstance(records, list)
    if legacy:
        records = []
        for _item in mapping.get("matched", []):
            records.append({"status": "probable", "declarations": [{"status": "probable"}],
                            "context": {"test": False}})
        missing = set(mapping.get("unmatched_kt", [])) | set(mapping.get("unmatched_main", []))
        missing.update(mapping.get("unmatched_test", []))
        for name in missing:
            records.append({"status": "missing", "declarations": [{"status": "missing"}],
                            "context": {"test": name in mapping.get("unmatched_test", [])}})
    records = [row for row in records if isinstance(row, dict)]
    overall = _group(records)
    return {**overall, "method": "file-weighted-declaration-fraction-v1",
            "legacy_heuristic": legacy,
            "main": _group([row for row in records if not (row.get("context") or {}).get("test")]),
            "test": _group([row for row in records if (row.get("context") or {}).get("test")]),
            "incomplete": bool(overall["unresolved_files"] or mapping.get("uninspected_containers")
                               or mapping.get("invalid_class_count")
                               or mapping.get("index_incomplete")),
            "formula": "Each applicable .kt file has equal weight. Its fraction is matched "
                       "expected declarations/artifacts divided by all recognized expected units. "
                       "Unknown files contribute zero; probable unique links count only in the "
                       "estimate. Ambiguous, missing and unverified links never count as matched."}


def percent(value: float | None, *, approximate: bool = False) -> str:
    return "н/д" if value is None else ("≈" if approximate else "") + f"{value:.1f}%"


def coverage_text(coverage: dict) -> str:
    estimated = percent(coverage.get("estimated_percent"), approximate=True)
    confirmed = percent(coverage.get("confirmed_percent"))
    main = percent(coverage.get("main", {}).get("estimated_percent"), approximate=True)
    tests = percent(coverage.get("test", {}).get("estimated_percent"), approximate=True)
    note = " Оценка неполная." if coverage.get("incomplete") else ""
    return (f"Покрытие Kotlin/JVM: {estimated}; подтверждённая доля: {confirmed}. "
            f"Основной код: {main}; тесты: {tests}. "
            f"Исходников: {coverage.get('applicable_files', 0)}, "
            f"ожидаемых объявлений/артефактов: {coverage.get('expected_units', 0)}, "
            f"неопределённых файлов: {coverage.get('unresolved_files', 0)}.{note}")
