"""Read-only audit of the shipped application, using disposable synthetic inputs.

Run with the project's CPython 3.14 build environment. The frozen mode imports
the application's actual Python code objects from the identified local EXE;
third-party/native modules use the installed build environment, not a new EXE.
No real passwords or user archives are read. This is NOT a full sandbox test.
"""
from __future__ import annotations

import argparse
import dataclasses
import dis
import gzip
import hashlib
import importlib.abc
import importlib.util
import io
import json
import marshal
import shutil
import struct
import sys
import tarfile
import tempfile
import types
import warnings
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[2]
EXE = PROJECT / 'dist/python314/PaxoInsight/PaxoInsight.exe'
ZIP = PROJECT / 'dist/PaxoInsight_v6.1_Python314_Portable.zip'
OUT = Path(__file__).resolve().parent


def normalized(code):
    return code.replace(co_filename='<normalized>', co_consts=tuple(
        normalized(item) if isinstance(item, types.CodeType) else item
        for item in code.co_consts
    ))


def children(code):
    yield code
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            yield from children(item)


def identity(reader):
    z = reader.open_embedded_archive('PYZ.pyz')
    with zipfile.ZipFile(ZIP) as archive:
        exe_name = next(n for n in archive.namelist() if n.endswith('/PaxoInsight.exe'))
        package = {
            'zip_sha256': hashlib.sha256(ZIP.read_bytes()).hexdigest(),
            'exe_sha256': hashlib.sha256(EXE.read_bytes()).hexdigest(),
            'exe_in_zip_sha256': hashlib.sha256(archive.read(exe_name)).hexdigest(),
            'files': len(archive.infolist()),
            'uncompressed_bytes': sum(i.file_size for i in archive.infolist()),
            'zip_integrity': archive.testzip(),
            'suspicious_paths': [n for n in archive.namelist() if any(
                x in n.lower() for x in ('.env', '.sqlite', '.web', 'password', 'users.db')
            )],
        }
    package['hardening_modules'] = {
        name: name in z.toc for name in (
            'defusedxml', 'paxoinsight.analysis_inputs', 'paxoinsight.archive_io',
            'paxoinsight._vendor.analyzers', 'PaxoInsight', 'setuptools', 'pip',
            'fastapi', 'uvicorn',
        )
    }
    module = 'paxoinsight.archive_service'
    frozen = z.extract(module)
    candidate = PROJECT / 'build/lib/paxoinsight/archive_service.py'
    code = compile(candidate.read_bytes(), frozen.co_filename, 'exec', optimize=1)
    package['build_lib_archive_code_matches_exe'] = (
        marshal.dumps(normalized(code)) == marshal.dumps(normalized(frozen))
    )
    interesting = {
        '_extract_zip', '_extract_tar', '_extract_7z', '_extract_rar',
        '_validate_member_name', '_copy_directory', 'package_7z',
    }
    with (OUT / 'frozen-disassembly.txt').open('w', encoding='utf-8') as stream:
        for item in children(frozen):
            if item.co_name in interesting:
                print(f'\n## {item.co_qualname}, frozen source line {item.co_firstlineno}', file=stream)
                dis.dis(item, file=stream)
    package['embedded_archive_functions'] = {
        item.co_qualname: {'line': item.co_firstlineno, 'names': item.co_names}
        for item in children(frozen) if item.co_name in interesting
    }
    frozen_zip_read = next(c for c in children(z.extract('zipfile'))
                           if c.co_qualname == 'ZipExtFile._read1')
    package['zip_read1_matches_build_runtime'] = (
        frozen_zip_read.co_code == zipfile.ZipExtFile._read1.__code__.co_code
        and frozen_zip_read.co_names == zipfile.ZipExtFile._read1.__code__.co_names
    )
    package['source_sha256'] = {
        str(p.relative_to(PROJECT)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted((PROJECT / 'src/paxoinsight').rglob('*.py'))
        if 'web' not in p.relative_to(PROJECT / 'src/paxoinsight').parts
    }
    (OUT / 'identity.json').write_text(json.dumps(package, indent=2), encoding='utf-8')
    print(json.dumps(package, indent=2))


class FrozenAppImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, reader):
        self.archive = reader.open_embedded_archive('PYZ.pyz')

    def find_spec(self, fullname, path=None, target=None):
        if (fullname == 'PaxoInsight' or fullname == 'paxoinsight'
                or fullname.startswith('paxoinsight.')) and fullname in self.archive.toc:
            return importlib.util.spec_from_loader(
                fullname, self, is_package=self.archive.toc[fullname][0] == 1
            )
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = str(EXE.parent / (module.__name__.replace('.', '/') + '.py'))
        exec(self.archive.extract(module.__name__), module.__dict__)


def checks(mode):
    if mode == 'frozen':
        from PyInstaller.archive.readers import CArchiveReader
        sys.meta_path.insert(0, FrozenAppImporter(CArchiveReader(str(EXE))))
    else:
        sys.path.insert(0, str(PROJECT / 'src'))
    import py7zr
    from paxoinsight.archive_service import ArchiveService
    from paxoinsight.models import AnalysisOptions

    results = []
    with tempfile.TemporaryDirectory(prefix='StandaloneAudit-') as temporary:
        root = Path(temporary)
        service = ArchiveService() if mode == 'frozen' else ArchiveService(root / 'work')

        def run(name, body):
            directory = root / name
            directory.mkdir()
            try:
                result = body(directory)
                results.append({'test': name, **result})
            except Exception as error:
                results.append({'test': name, 'probe_error': type(error).__name__,
                                'detail': str(error)[:400]})

        def prepare(path, **kw):
            return service.prepare(
                path, AnalysisOptions(delete_source_archive=False, **kw),
                lambda *_: None, Event(),
            )

        def attempt(path, **kw):
            try:
                session = prepare(path, **kw)
            except Exception as error:
                return {'rejected': True, 'exception': type(error).__name__}
            values = {'rejected': False,
                      'files': sum(p.is_file() for p in session.content_root.rglob('*')),
                      'directories': sum(p.is_dir() for p in session.content_root.rglob('*'))}
            if (session.content_root / 'same.txt').is_file():
                values['duplicate_final_value'] = (session.content_root / 'same.txt').read_text()
            service.cleanup(session)
            values['workspace_cleaned'] = not session.session_root.exists()
            return values

        def zipped(directory, names, **kw):
            path = directory / 'input.zip'
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with zipfile.ZipFile(path, 'w') as archive:
                    for name, value in names:
                        archive.writestr(name, value)
            return attempt(path, **kw)

        run('zip_traversal', lambda d: zipped(d, [('../escape.txt', b'blocked')]))
        run('zip_absolute', lambda d: zipped(d, [('C:/escape.txt', b'blocked')]))
        run('zip_duplicates', lambda d: zipped(d, [('same.txt', b'first'), ('same.txt', b'second')]))
        run('zip_implicit_directories', lambda d: zipped(d, [('a/b/c/d/data.txt', b'ok')], max_files=3))

        def tar_case(directory, kind):
            path = directory / 'input.tar'
            with tarfile.open(path, 'w') as archive:
                if kind == 'directories':
                    for index in range(5):
                        item = tarfile.TarInfo(f'dir-{index}')
                        item.type = tarfile.DIRTYPE
                        archive.addfile(item)
                elif kind in ('symlink', 'hardlink'):
                    item = tarfile.TarInfo('link')
                    item.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                    item.linkname = '../outside'
                    archive.addfile(item)
                else:
                    for value in (b'first', b'second'):
                        item = tarfile.TarInfo('same.txt')
                        item.size = len(value)
                        archive.addfile(item, io.BytesIO(value))
            return attempt(path, **({'max_files': 3} if kind == 'directories' else {}))

        for name in ('directories', 'symlink', 'hardlink', 'duplicates'):
            run('tar_' + name, lambda d, name=name: tar_case(d, name))

        def false_7z(directory):
            path = directory / 'input.7z'
            with py7zr.SevenZipFile(path, 'w') as archive:
                archive.writestr(b'A' * 4096, 'payload.bin')
            original = py7zr.SevenZipFile.list
            def listing(archive):
                return [dataclasses.replace(i, uncompressed=1) for i in original(archive)]
            destination = directory / 'output'
            destination.mkdir()
            error_name = None
            try:
                with patch.object(py7zr.SevenZipFile, 'list', listing):
                    service._extract_7z(path, destination,
                                        AnalysisOptions(max_unpacked_bytes=32), None)
            except Exception as error:
                error_name = type(error).__name__
            return {'simulated_false_listing_size': 1, 'configured_limit': 32,
                    'exception': error_name,
                    'bytes_written': sum(p.stat().st_size for p in destination.rglob('*') if p.is_file())}
        run('7z_actual_write_limit', false_7z)

        def low_disk(directory):
            path = directory / 'input.zip'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('payload.bin', b'A' * 4096)
            destination = directory / 'output'
            destination.mkdir()
            error_name = None
            try:
                with patch('shutil.disk_usage', return_value=types.SimpleNamespace(free=0)):
                    service._extract_zip(path, destination, AnalysisOptions(), None)
            except Exception as error:
                error_name = type(error).__name__
            return {'simulated_free_bytes': 0, 'exception': error_name,
                    'bytes_written': sum(p.stat().st_size for p in destination.rglob('*') if p.is_file())}
        run('zip_low_disk', low_disk)

        def bzip_allocation(directory):
            import bz2
            import zlib
            path = directory / 'input.zip'
            # Bound this audit sample to 16 MiB; NEVER try a workstation-size bomb.
            original_size = 16 * 1024**2
            declared_size = 32
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_BZIP2) as archive:
                archive.writestr('payload.bin', bytes(original_size))
            data = bytearray(path.read_bytes())
            central = data.index(b'PK\x01\x02')
            checksum = zlib.crc32(bytes(declared_size))
            struct.pack_into('<I', data, 14, checksum)
            struct.pack_into('<I', data, 22, declared_size)
            struct.pack_into('<I', data, central + 16, checksum)
            struct.pack_into('<I', data, central + 24, declared_size)
            path.write_bytes(data)
            allocations = []
            class Decoder:
                def __init__(self): self.decoder = bz2.BZ2Decompressor()
                def __getattr__(self, name): return getattr(self.decoder, name)
                def decompress(self, *args, **kwargs):
                    value = self.decoder.decompress(*args, **kwargs)
                    allocations.append(len(value))
                    return value
            original = zipfile._get_decompressor
            def decoder(kind):
                return Decoder() if kind == zipfile.ZIP_BZIP2 else original(kind)
            destination = directory / 'output'
            destination.mkdir()
            with patch.object(zipfile, '_get_decompressor', side_effect=decoder):
                service._extract_zip(path, destination,
                                     AnalysisOptions(max_unpacked_bytes=32), None)
            return {'real_crafted_zip_not_mocked_listing': True,
                    'sample_expansion_bounded_to': original_size,
                    'declared_size_and_application_limit': declared_size,
                    'largest_decoder_allocation': max(allocations, default=0),
                    'output_bytes': (destination / 'payload.bin').stat().st_size}
        run('zip_bzip2_memory_allocation', bzip_allocation)

        def rar_password(directory):
            path = directory / 'input.rar'
            path.write_bytes(b'Rar!\x1a\x07\x00 synthetic')
            destination = directory / 'output'
            secret = 'SYNTHETIC-ONLY-password'
            captured = {}
            class Rar:
                def __enter__(self): return self
                def __exit__(self, *_): pass
                def needs_password(self): return True
                def setpassword(self, _): pass
                def infolist(self): return []
            class Stdin(io.BytesIO):
                def close(self):
                    if not self.closed:
                        captured['stdin_password'] = self.getvalue() == (secret + '\n').encode()
                    super().close()
            class Process:
                def __init__(self, command, **kw):
                    captured['command'] = command
                    captured['shell'] = kw.get('shell')
                    self.stdin = Stdin()
                def poll(self): return 0
                def wait(self): return 0
                def kill(self): pass
            def invoke(command, **kw):
                captured['command'] = command
                captured['shell'] = kw.get('shell')
                captured['timeout'] = kw.get('timeout')
                return types.SimpleNamespace(returncode=0, stdout='', stderr='')
            with patch.object(service._rarfile, 'RarFile', return_value=Rar()), \
                    patch('subprocess.run', side_effect=invoke), \
                    patch('subprocess.Popen', side_effect=Process):
                service._extract_rar(path, destination, AnalysisOptions(), secret)
            command = captured['command']
            return {'mocked_native_process': True,
                    'password_in_argv': any(secret in part for part in command),
                    'password_via_stdin': captured.get('stdin_password', False),
                    'forced_rar_type': any(part in ('-tRar', '-tRar5') for part in command),
                    'shell': captured['shell']}
        run('rar_password_transport', rar_password)

        def xml_dtd(directory):
            path = directory / 'pom.xml'
            path.write_text('<!DOCTYPE project [<!ENTITY x "synthetic">]>'
                            '<project><name>&x;</name></project>', encoding='utf-8')
            try:
                if mode == 'source':
                    from paxoinsight.analysis_inputs import parse_xml
                    parse_xml(path)
                else:
                    import PaxoInsight
                    PaxoInsight.ET.parse(path)
            except Exception as error:
                return {'rejected': True, 'exception': type(error).__name__}
            return {'rejected': False, 'note': 'Harmless internal entity only; no XXE claim.'}
        run('xml_internal_dtd', xml_dtd)

        def html_escape(_directory):
            from paxoinsight.reporting import build_kotlin_html_report
            payload = '<script>alert("synthetic")</script>.kt'
            result = types.SimpleNamespace(
                analysis_data={'kotlin_mapping': {'unmatched_main': [payload]}},
                kotlin_files=[payload], class_files=[], source_name=payload,
                finished_at='synthetic',
            )
            html = build_kotlin_html_report(result)
            return {'script_escaped': '<script>' not in html and '&lt;script&gt;' in html,
                    'external_script_tag': '<script src=' in html.lower(),
                    'external_stylesheet_tag': '<link ' in html.lower()}
        run('html_report_escaping', html_escape)

        def source_folder(directory):
            source = directory / 'folder'
            source.mkdir()
            for index in range(5): (source / f'dir-{index}').mkdir()
            destination = directory / 'copied'
            destination.mkdir()
            error_name = None
            try:
                service._copy_directory(source, destination, directory / 'exclude',
                                         AnalysisOptions(max_files=3), lambda *_: None, Event())
            except Exception as error:
                error_name = type(error).__name__
            return {'configured_limit': 3, 'exception_during_copy': error_name,
                    'directories_copied_before_final_validation': sum(p.is_dir() for p in destination.rglob('*'))}
        run('folder_copy_directory_budget', source_folder)

    result = {'mode': mode, 'python': sys.version, 'py7zr': py7zr.__version__,
              'native_environment': 'Build environment; not native DLLs loaded by the EXE.',
              'results': results}
    (OUT / f'probes-{mode}.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


def regression():
    import unittest
    sys.path.insert(0, str(PROJECT / 'src'))
    sys.path.insert(0, str(PROJECT / 'tests'))
    # Web test helpers are available in the existing web test environment;
    # TkDnD is available in the existing desktop environment. Install nothing.
    sys.path.append(str(PROJECT.parent / '.venv314/Lib/site-packages'))
    names = [
        'test_analysis_service', 'test_archive_service', 'test_attention',
        'test_password_dialog', 'test_python314_migration', 'test_reporting',
        'test_security_audit.UntrustedInputsTests',
    ]
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    with (OUT / 'tests-current-source.txt').open('w', encoding='utf-8') as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    summary = {'run': result.testsRun, 'failures': len(result.failures),
               'errors': len(result.errors), 'skipped': len(result.skipped),
               'success': result.wasSuccessful(), 'modules': names,
               'scope': 'Current sources, not shipped EXE'}
    (OUT / 'tests-current-source.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=('identity', 'frozen', 'source', 'regression'), required=True)
    args = parser.parse_args()
    if args.mode == 'identity':
        from PyInstaller.archive.readers import CArchiveReader
        identity(CArchiveReader(str(EXE)))
    elif args.mode == 'regression':
        regression()
    else:
        checks(args.mode)
