"""RAR header inspection without rarfile's implicit comment decompression tools.

Adapter for the pinned rarfile 4.5 parser. Extraction is performed separately
by our controlled 7-Zip process; comments are not used by PaxoInsight. Do not
globally patch rarfile: concurrent jobs/tests may be using its normal API.
"""

from __future__ import annotations

import rarfile


class _Rar3MetadataParser(rarfile.RAR3Parser):
    def _parse_subblocks(self, header, data, position):
        # This upstream method decodes old-style comments only.
        return len(data)

    def _read_comment_v3(self, info, password=None):
        return None


class _Rar5MetadataParser(rarfile.RAR5Parser):
    def _load_comment(self, stream, info):
        return None


class RarMetadataFile(rarfile.RarFile):
    def _parse(self):
        if rarfile.__version__ != "4.5":
            raise RuntimeError("Revalidate the RAR metadata adapter for this rarfile version")
        version, offset = rarfile._find_sfx_header(self._rarfile)
        if offset:
            raise ValueError("Самораспаковывающиеся RAR SFX запрещены")
        parsers = {rarfile.RAR_V3: _Rar3MetadataParser,
                   rarfile.RAR_V5: _Rar5MetadataParser}
        parser = parsers.get(version)
        if parser is None:
            raise rarfile.NotRarFile("Not a RAR3/RAR5 file")
        self._file_parser = parser(
            self._rarfile, self._password, self._crc_check, self._charset,
            self._strict, self._info_callback, offset, self._part_only,
        )
        self._file_parser.parse()
        self.comment = None
