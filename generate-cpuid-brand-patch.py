#!/usr/bin/env python3
"""
Generate an OpenCore kernel patch that removes an unwanted prefix from XNU's
cached CPUID brand string.

The generator analyzes the currently installed x86_64 kernel. It only produces
a patch when it recognizes the compiled leading-space-removal loop around the
CPUID brand buffer. It does not use a fixed kernel address or fixed stack
offset.

Version 1.1.1
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


VERSION = "1.1.1"
GENERATOR_MARKER = "CPUIDBrandAuto"
DEFAULT_CONFIG = Path("/Volumes/EFI/EFI/OC/config.plist")
DEFAULT_KC = Path("/System/Library/KernelCollections/BootKernelExtensions.kc")

MH_MAGIC_64 = 0xFEEDFACF
MH_EXECUTE = 0x2
MH_FILESET = 0xC
CPU_TYPE_X86_64 = 0x01000007
CPU_SUBTYPE_X86_64_ALL = 3

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_UUID = 0x1B
LC_FILESET_ENTRY = 0x80000035
LC_FUNCTION_STARTS = 0x26

N_SECT = 0x0E
N_EXT = 0x01
S_REGULAR = 0x0
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400

SYMBOL_CANDIDATES = (
    "_cpuid_set_generic_info",
    "_cpuid_set_info",
)

KNOWN_CANONICAL_TOKENS = (
    "Intel",
    "AMD",
    "Hygon",
    "VIA",
    "Centaur",
    "Zhaoxin",
    "Apple",
)


class GeneratorError(RuntimeError):
    """A safe, user-readable generation failure."""


@dataclass(frozen=True)
class Symbol:
    address: int
    symbol_type: str
    name: str


@dataclass(frozen=True)
class Segment:
    name: str
    vmaddr: int
    vmsize: int
    fileoff: int
    filesize: int


@dataclass(frozen=True)
class KernelImage:
    container_path: str
    image_fileoff: int
    image_vmaddr: int
    uuid: str | None
    segments: tuple[Segment, ...]
    function_starts_dataoff: int | None
    function_starts_datasize: int | None


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    line: str


@dataclass(frozen=True)
class LoopMatch:
    lea_instruction: Instruction
    compare_instruction: Instruction
    pointer_register: str
    frame_register: str
    disassembly_excerpt: tuple[str, ...]


@dataclass(frozen=True)
class LeaEncoding:
    instruction_length: int
    displacement_offset: int
    displacement_size: int
    old_displacement: int
    new_displacement: int


@dataclass(frozen=True)
class GeneratedPatch:
    patch: dict[str, Any]
    symbol: Symbol
    kernel_image: KernelImage
    function_fileoff: int
    function_size: int
    lea_offset_from_symbol: int
    lea_encoding: LeaEncoding
    skip_bytes: int
    original_brand: str
    normalized_brand: str
    target_substring: str
    find_occurrences_in_function: int
    find_occurrences_in_container: int
    disassembly_excerpt: tuple[str, ...]


def eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def run(
    args: Sequence[str],
    *,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(args),
            text=text,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GeneratorError(f"Required command was not found: {args[0]}") from exc

    if check and result.returncode != 0:
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        raise GeneratorError(
            f"Command failed ({result.returncode}): {' '.join(args)}"
            + (f"\n{output}" if output else "")
        )
    return result


def command_path(name: str) -> str:
    result = run(["/usr/bin/xcrun", "--find", name])
    path = result.stdout.strip()
    if not path:
        raise GeneratorError(f"xcrun could not locate {name}")
    return path


def sysctl_value(name: str) -> str:
    return run(["/usr/sbin/sysctl", "-n", name]).stdout.strip()


def sw_vers_value(flag: str) -> str:
    return run(["/usr/bin/sw_vers", flag]).stdout.strip()


def parse_kernel_version(value: str) -> tuple[int, int, int]:
    fields = value.strip().split(".")
    numbers: list[int] = []
    for field in fields[:3]:
        match = re.match(r"(\d+)", field)
        numbers.append(int(match.group(1)) if match else 0)
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)  # type: ignore[return-value]


def kernel_version_applies(
    current: str,
    minimum: str,
    maximum: str,
) -> bool:
    current_v = parse_kernel_version(current)
    if minimum and current_v < parse_kernel_version(minimum):
        return False
    if maximum and current_v > parse_kernel_version(maximum):
        return False
    return True


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def hex_bytes(value: bytes) -> str:
    return " ".join(f"{byte:02X}" for byte in value)


def format_signed_hex(value: int) -> str:
    return f"-0x{-value:x}" if value < 0 else f"0x{value:x}"


def read_macho_header_and_commands(
    fp: Any,
    offset: int,
) -> tuple[tuple[int, int, int, int, int, int, int, int], bytes]:
    fp.seek(offset)
    header = fp.read(32)
    if len(header) != 32:
        raise GeneratorError(f"Truncated Mach-O header at file offset 0x{offset:x}")

    values = struct.unpack("<IiiIIIII", header)
    magic, _, _, _, _, sizeofcmds, _, _ = values
    if magic != MH_MAGIC_64:
        raise GeneratorError(
            f"Unsupported Mach-O magic 0x{magic:08x} at file offset 0x{offset:x}"
        )

    commands = fp.read(sizeofcmds)
    if len(commands) != sizeofcmds:
        raise GeneratorError("Truncated Mach-O load-command table")
    return values, commands


def iterate_load_commands(
    commands: bytes,
    ncmds: int,
) -> Iterable[tuple[int, int, int, int, bytes]]:
    position = 0
    for index in range(ncmds):
        if position + 8 > len(commands):
            raise GeneratorError("Mach-O load-command table ended early")

        command, command_size = struct.unpack_from("<II", commands, position)
        if (
            command_size < 8
            or position + command_size > len(commands)
        ):
            raise GeneratorError(
                f"Invalid Mach-O load command #{index}: "
                f"cmd=0x{command:x}, size={command_size}"
            )

        yield (
            index,
            position,
            command,
            command_size,
            commands[position:position + command_size],
        )
        position += command_size


def read_c_string(data: bytes, start: int, limit: int) -> str:
    end = data.find(b"\0", start, limit)
    if end < 0:
        end = limit
    return data[start:end].decode("utf-8", errors="replace")


def decode_uleb128_stream(data: bytes) -> Iterable[int]:
    value = 0
    shift = 0
    for byte in data:
        value |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
            if shift > 63:
                raise GeneratorError("Invalid ULEB128 value in LC_FUNCTION_STARTS")
        else:
            yield value
            value = 0
            shift = 0

    if shift:
        raise GeneratorError("Truncated ULEB128 stream in LC_FUNCTION_STARTS")


def parse_symbols(nm_output: str) -> list[Symbol]:
    symbols: list[Symbol] = []
    expression = re.compile(
        r"^([0-9A-Fa-f]{8,16})\s+([A-Za-z])\s+(\S+)$"
    )
    for raw_line in nm_output.splitlines():
        line = raw_line.strip()
        match = expression.match(line)
        if not match:
            continue
        symbols.append(
            Symbol(
                address=int(match.group(1), 16),
                symbol_type=match.group(2),
                name=match.group(3),
            )
        )
    return symbols


def inspect_kernel_image(path: Path) -> KernelImage:
    with path.open("rb") as fp:
        outer_header, outer_commands = read_macho_header_and_commands(fp, 0)
        (
            _,
            _,
            _,
            outer_filetype,
            outer_ncmds,
            _,
            _,
            _,
        ) = outer_header

        image_fileoff = 0
        image_vmaddr = 0

        if outer_filetype == MH_FILESET:
            found = False
            for _, _, command, _, data in iterate_load_commands(
                outer_commands,
                outer_ncmds,
            ):
                if command != LC_FILESET_ENTRY:
                    continue

                vmaddr, fileoff = struct.unpack_from("<QQ", data, 8)
                entry_id_offset = struct.unpack_from("<I", data, 24)[0]
                entry_id = read_c_string(data, entry_id_offset, len(data))
                if entry_id == "com.apple.kernel":
                    image_fileoff = fileoff
                    image_vmaddr = vmaddr
                    found = True
                    break

            if not found:
                raise GeneratorError(
                    "The kernel collection has no com.apple.kernel fileset entry"
                )
        elif outer_filetype != MH_EXECUTE:
            raise GeneratorError(
                f"Unsupported Mach-O file type 0x{outer_filetype:x}"
            )

        inner_header, inner_commands = read_macho_header_and_commands(
            fp,
            image_fileoff,
        )
        inner_ncmds = inner_header[4]

        segments: list[Segment] = []
        function_starts_dataoff: int | None = None
        function_starts_datasize: int | None = None
        uuid: str | None = None

        for _, _, command, _, data in iterate_load_commands(
            inner_commands,
            inner_ncmds,
        ):
            if command == LC_SEGMENT_64:
                name_raw = struct.unpack_from("<16s", data, 8)[0]
                name = name_raw.split(b"\0", 1)[0].decode(
                    "ascii",
                    errors="replace",
                )
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ",
                    data,
                    24,
                )
                segments.append(
                    Segment(
                        name=name,
                        vmaddr=vmaddr,
                        vmsize=vmsize,
                        fileoff=fileoff,
                        filesize=filesize,
                    )
                )
            elif command == LC_FUNCTION_STARTS:
                (
                    function_starts_dataoff,
                    function_starts_datasize,
                ) = struct.unpack_from("<II", data, 8)
            elif command == LC_UUID:
                raw_uuid = data[8:24]
                uuid = (
                    raw_uuid[0:4].hex()
                    + "-"
                    + raw_uuid[4:6].hex()
                    + "-"
                    + raw_uuid[6:8].hex()
                    + "-"
                    + raw_uuid[8:10].hex()
                    + "-"
                    + raw_uuid[10:16].hex()
                ).upper()

        if not segments:
            raise GeneratorError("The kernel Mach-O has no segments")

        return KernelImage(
            container_path=str(path),
            image_fileoff=image_fileoff,
            image_vmaddr=image_vmaddr,
            uuid=uuid,
            segments=tuple(segments),
            function_starts_dataoff=function_starts_dataoff,
            function_starts_datasize=function_starts_datasize,
        )


def map_vm_to_file(image: KernelImage, address: int) -> tuple[Segment, int]:
    for segment in image.segments:
        if segment.vmaddr <= address < segment.vmaddr + segment.vmsize:
            relative = address - segment.vmaddr
            if relative >= segment.filesize:
                raise GeneratorError(
                    f"VM address 0x{address:x} maps beyond the stored part "
                    f"of segment {segment.name}"
                )
            return segment, segment.fileoff + relative
    raise GeneratorError(
        f"VM address 0x{address:x} did not map to a kernel segment"
    )


def function_boundary_from_starts(
    path: Path,
    image: KernelImage,
    address: int,
) -> tuple[int, int] | None:
    if (
        image.function_starts_dataoff is None
        or not image.function_starts_datasize
    ):
        return None

    text_segment = next(
        (segment for segment in image.segments if segment.name == "__TEXT"),
        None,
    )
    if text_segment is None:
        return None

    with path.open("rb") as fp:
        fp.seek(image.function_starts_dataoff)
        blob = fp.read(image.function_starts_datasize)

    current = text_segment.vmaddr
    starts: list[int] = []
    for delta in decode_uleb128_stream(blob):
        if delta == 0:
            break
        current += delta
        starts.append(current)

    for index, start in enumerate(starts):
        if start != address:
            continue
        if index + 1 < len(starts):
            return start, starts[index + 1]
        return None
    return None


def determine_function_range(
    path: Path,
    image: KernelImage,
    symbol: Symbol,
    symbols: Sequence[Symbol],
) -> tuple[int, int]:
    from_function_starts = function_boundary_from_starts(
        path,
        image,
        symbol.address,
    )
    if from_function_starts:
        start, end = from_function_starts
        size = end - start
        if 32 <= size <= 0x10000:
            return start, end

    later_text_symbols = sorted(
        candidate.address
        for candidate in symbols
        if (
            candidate.address > symbol.address
            and candidate.symbol_type in {"T", "t"}
        )
    )
    if later_text_symbols:
        end = later_text_symbols[0]
        size = end - symbol.address
        if 32 <= size <= 0x10000:
            return symbol.address, end

    return symbol.address, symbol.address + 0x4000


def extract_function(
    path: Path,
    image: KernelImage,
    symbol: Symbol,
    symbols: Sequence[Symbol],
) -> tuple[bytes, int]:
    start, end = determine_function_range(path, image, symbol, symbols)
    _, fileoff = map_vm_to_file(image, start)
    size = end - start
    size = min(max(size, 0x400), 0x10000)

    with path.open("rb") as fp:
        fp.seek(fileoff)
        data = fp.read(size)

    if len(data) < 0x100:
        raise GeneratorError(
            f"Could not read enough bytes for {symbol.name}"
        )
    return data, fileoff


def build_synthetic_macho(
    destination: Path,
    symbol: Symbol,
    function_bytes: bytes,
) -> None:
    header_size = 32
    segment_command_size = 72 + 80
    symtab_command_size = 24
    dysymtab_command_size = 80
    command_size = (
        segment_command_size
        + symtab_command_size
        + dysymtab_command_size
    )
    command_count = 3

    code_offset = 0x1000
    code_size = len(function_bytes)
    symbol_table_offset = align(code_offset + code_size, 8)
    string_table_offset = symbol_table_offset + 16
    string_table = b"\0" + symbol.name.encode("utf-8") + b"\0"
    string_table_size = len(string_table)
    file_size = string_table_offset + string_table_size

    header = struct.pack(
        "<IiiIIIII",
        MH_MAGIC_64,
        CPU_TYPE_X86_64,
        CPU_SUBTYPE_X86_64_ALL,
        MH_EXECUTE,
        command_count,
        command_size,
        0,
        0,
    )

    segment_name = b"__TEXT".ljust(16, b"\0")
    segment_command = struct.pack(
        "<II16sQQQQiiII",
        LC_SEGMENT_64,
        segment_command_size,
        segment_name,
        symbol.address,
        align(code_size, 0x1000),
        code_offset,
        code_size,
        7,
        5,
        1,
        0,
    )

    section_command = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text".ljust(16, b"\0"),
        segment_name,
        symbol.address,
        code_size,
        code_offset,
        4,
        0,
        0,
        S_REGULAR
        | S_ATTR_PURE_INSTRUCTIONS
        | S_ATTR_SOME_INSTRUCTIONS,
        0,
        0,
        0,
    )

    symtab_command = struct.pack(
        "<IIIIII",
        LC_SYMTAB,
        symtab_command_size,
        symbol_table_offset,
        1,
        string_table_offset,
        string_table_size,
    )

    dysymtab_command = struct.pack(
        "<" + "I" * 20,
        LC_DYSYMTAB,
        dysymtab_command_size,
        0,
        0,
        0,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    symbol_record = struct.pack(
        "<IBBHQ",
        1,
        N_SECT | N_EXT,
        1,
        0,
        symbol.address,
    )

    image = bytearray(file_size)
    image[0:len(header)] = header
    commands = (
        segment_command
        + section_command
        + symtab_command
        + dysymtab_command
    )
    image[header_size:header_size + len(commands)] = commands
    image[code_offset:code_offset + code_size] = function_bytes
    image[
        symbol_table_offset:symbol_table_offset + len(symbol_record)
    ] = symbol_record
    image[
        string_table_offset:string_table_offset + string_table_size
    ] = string_table

    destination.write_bytes(image)


def parse_otool_disassembly(output: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    expression = re.compile(
        r"^\s*([0-9A-Fa-f]{8,16})\s+"
        r"([A-Za-z][A-Za-z0-9.]*)"
        r"(?:\s+(.*?))?\s*$"
    )
    for line in output.splitlines():
        match = expression.match(line)
        if not match:
            continue
        instructions.append(
            Instruction(
                address=int(match.group(1), 16),
                mnemonic=match.group(2).lower(),
                operands=(match.group(3) or "").strip(),
                line=line.rstrip(),
            )
        )
    return instructions


def find_brand_space_loop(
    instructions: Sequence[Instruction],
) -> LoopMatch:
    matches: list[LoopMatch] = []

    for compare_index, compare in enumerate(instructions):
        if compare.mnemonic != "cmpb":
            continue
        if not re.search(r"\$0x20\s*,", compare.operands, re.IGNORECASE):
            continue

        pointer_register: str | None = None

        for index in range(max(0, compare_index - 4), compare_index):
            candidate = instructions[index]
            inc_match = re.fullmatch(
                r"%(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|10|11|12|13|14|15))",
                candidate.operands,
            )
            add_match = re.fullmatch(
                r"\$0x1\s*,\s*"
                r"%(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|10|11|12|13|14|15))",
                candidate.operands,
            )

            if candidate.mnemonic == "incq" and inc_match:
                pointer_register = inc_match.group(1)
                break
            if candidate.mnemonic == "addq" and add_match:
                pointer_register = add_match.group(1)
                break

        if pointer_register is None:
            continue

        load_seen = False
        pointer_pattern = re.escape(f"%{pointer_register}")
        for index in range(max(0, compare_index - 6), compare_index):
            candidate = instructions[index]
            if (
                candidate.mnemonic.startswith("movzb")
                and re.search(
                    rf"(?:0x)?1\({pointer_pattern}\)",
                    candidate.operands,
                    re.IGNORECASE,
                )
            ):
                load_seen = True
                break

        if not load_seen:
            continue

        lea_match_result: tuple[Instruction, str] | None = None
        for index in range(max(0, compare_index - 24), compare_index):
            candidate = instructions[index]
            if candidate.mnemonic not in {"leaq", "lea"}:
                continue

            lea_expression = re.compile(
                rf"(-?0x[0-9a-f]+)"
                rf"\(%(rbp|rsp)\)\s*,\s*%{re.escape(pointer_register)}$",
                re.IGNORECASE,
            )
            lea_match = lea_expression.fullmatch(candidate.operands)
            if lea_match:
                lea_match_result = (candidate, lea_match.group(2))

        if lea_match_result is None:
            continue

        lea_instruction, frame_register = lea_match_result
        start_index = max(
            0,
            next(
                i
                for i, value in enumerate(instructions)
                if value.address == lea_instruction.address
            ) - 2,
        )
        end_index = min(len(instructions), compare_index + 3)
        excerpt = tuple(
            instruction.line
            for instruction in instructions[start_index:end_index]
        )

        matches.append(
            LoopMatch(
                lea_instruction=lea_instruction,
                compare_instruction=compare,
                pointer_register=pointer_register,
                frame_register=frame_register,
                disassembly_excerpt=excerpt,
            )
        )

    if not matches:
        raise GeneratorError(
            "The compiled CPUID brand leading-space loop was not recognized. "
            "No patch was generated."
        )
    if len(matches) > 1:
        addresses = ", ".join(
            f"0x{match.lea_instruction.address:x}" for match in matches
        )
        raise GeneratorError(
            "More than one possible CPUID brand loop was found "
            f"({addresses}). Refusing to guess."
        )
    return matches[0]


def decode_lea_displacement(
    instruction_bytes: bytes,
    skip_bytes: int,
) -> LeaEncoding:
    if len(instruction_bytes) < 4:
        raise GeneratorError("LEA instruction bytes are truncated")

    index = 0
    if 0x40 <= instruction_bytes[index] <= 0x4F:
        index += 1

    if index >= len(instruction_bytes) or instruction_bytes[index] != 0x8D:
        raise GeneratorError(
            "The selected pointer initialization is not an x86 LEA instruction"
        )
    index += 1

    if index >= len(instruction_bytes):
        raise GeneratorError("LEA ModR/M byte is missing")

    modrm = instruction_bytes[index]
    index += 1
    mod = (modrm >> 6) & 0x3
    rm = modrm & 0x7

    if mod == 3:
        raise GeneratorError("LEA unexpectedly uses a register source")

    if rm == 4:
        if index >= len(instruction_bytes):
            raise GeneratorError("LEA SIB byte is missing")
        index += 1

    if mod == 1:
        displacement_size = 1
    elif mod == 2 or (mod == 0 and rm == 5):
        displacement_size = 4
    else:
        displacement_size = 0

    if displacement_size == 0:
        raise GeneratorError(
            "LEA has no directly patchable displacement"
        )

    displacement_offset = index
    displacement_end = displacement_offset + displacement_size
    if displacement_end > len(instruction_bytes):
        raise GeneratorError("LEA displacement bytes are truncated")

    old_displacement = int.from_bytes(
        instruction_bytes[displacement_offset:displacement_end],
        "little",
        signed=True,
    )
    new_displacement = old_displacement + skip_bytes

    minimum = -(1 << (displacement_size * 8 - 1))
    maximum = (1 << (displacement_size * 8 - 1)) - 1
    if not minimum <= new_displacement <= maximum:
        raise GeneratorError(
            "The adjusted LEA displacement does not fit in the original "
            f"{displacement_size}-byte encoding"
        )

    return LeaEncoding(
        instruction_length=len(instruction_bytes),
        displacement_offset=displacement_offset,
        displacement_size=displacement_size,
        old_displacement=old_displacement,
        new_displacement=new_displacement,
    )


def count_overlapping(haystack: bytes, needle: bytes) -> int:
    if not needle:
        return 0
    count = 0
    position = 0
    while True:
        position = haystack.find(needle, position)
        if position < 0:
            return count
        count += 1
        position += 1


def choose_unique_context(
    function_bytes: bytes,
    container_bytes: bytes,
    instruction_offset: int,
    instruction_length: int,
    displacement_offset: int,
    displacement_size: int,
    new_displacement: int,
) -> tuple[bytes, bytes, int, int]:
    remaining = len(function_bytes) - instruction_offset
    if remaining < instruction_length:
        raise GeneratorError("LEA instruction extends beyond extracted function")

    minimum_length = max(instruction_length, 12)
    maximum_length = min(48, remaining)

    selected: tuple[bytes, bytes, int, int] | None = None

    for context_length in range(minimum_length, maximum_length + 1):
        find = function_bytes[
            instruction_offset:instruction_offset + context_length
        ]
        function_occurrences = count_overlapping(function_bytes, find)
        container_occurrences = count_overlapping(container_bytes, find)

        replace = bytearray(find)
        start = displacement_offset
        end = start + displacement_size
        replace[start:end] = new_displacement.to_bytes(
            displacement_size,
            "little",
            signed=True,
        )

        candidate = (
            find,
            bytes(replace),
            function_occurrences,
            container_occurrences,
        )

        if function_occurrences == 1 and container_occurrences == 1:
            return candidate
        if function_occurrences == 1 and selected is None:
            selected = candidate

    if selected is not None:
        return selected

    raise GeneratorError(
        "Could not construct a unique Find pattern inside the target function"
    )


def detect_target_substring(
    brand: str,
    explicit_target: str | None,
    *,
    interactive: bool,
) -> tuple[str, int]:
    if explicit_target is not None:
        if not explicit_target:
            raise GeneratorError("--target cannot be empty")
        index = brand.find(explicit_target)
        if index < 0:
            raise GeneratorError(
                f"The requested target substring {explicit_target!r} "
                "does not occur in the current CPU brand"
            )
        return explicit_target, index

    candidates = [
        (brand.find(token), token)
        for token in KNOWN_CANONICAL_TOKENS
        if brand.find(token) >= 0
    ]
    if candidates:
        index, token = min(candidates, key=lambda item: item[0])
        return token, index

    if not interactive:
        raise GeneratorError(
            "No known canonical CPU-vendor token was found. "
            "Provide --target with a substring already present in the brand."
        )

    print()
    print("No known CPU-vendor token was found automatically.")
    target = input(
        "Substring where the normalized CPU brand should begin: "
    ).strip()
    if not target:
        raise GeneratorError("No target substring was entered")
    index = brand.find(target)
    if index < 0:
        raise GeneratorError(
            f"{target!r} does not occur in the CPU brand"
        )
    return target, index


def looks_like_cpuid_brand_patch(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("Identifier") != "kernel":
        return False
    if entry.get("Base") not in SYMBOL_CANDIDATES:
        return False

    comment = str(entry.get("Comment", "")).lower()
    if GENERATOR_MARKER.lower() in comment:
        return True
    return "cpuid" in comment and "brand" in comment


def find_existing_current_patch(
    config: dict[str, Any],
    current_kernel: str,
) -> tuple[int, dict[str, Any]] | None:
    patches = config.get("Kernel", {}).get("Patch", [])
    if not isinstance(patches, list):
        return None

    for index, entry in enumerate(patches):
        if not looks_like_cpuid_brand_patch(entry):
            continue

        minimum = str(entry.get("MinKernel", ""))
        maximum = str(entry.get("MaxKernel", ""))
        if kernel_version_applies(current_kernel, minimum, maximum):
            return index, entry
    return None


def find_all_cpuid_brand_patches(
    config: dict[str, Any],
) -> list[tuple[int, dict[str, Any]]]:
    patches = config.get("Kernel", {}).get("Patch", [])
    if not isinstance(patches, list):
        return []

    found: list[tuple[int, dict[str, Any]]] = []
    for index, entry in enumerate(patches):
        if looks_like_cpuid_brand_patch(entry):
            found.append((index, entry))
    return found


def patch_value_for_display(value: Any) -> str:
    if isinstance(value, bytes):
        return hex_bytes(value) if value else "<empty Data>"
    if isinstance(value, bool):
        return "True" if value else "False"
    return str(value)


def patch_summary_lines(entry: dict[str, Any]) -> list[str]:
    ordered_fields = (
        "Arch",
        "Base",
        "Comment",
        "Count",
        "Enabled",
        "Find",
        "Identifier",
        "Limit",
        "Mask",
        "MaxKernel",
        "MinKernel",
        "Replace",
        "ReplaceMask",
        "Skip",
    )
    width = max(len(field) for field in ordered_fields)
    lines: list[str] = []
    for field in ordered_fields:
        if field in entry:
            lines.append(
                f"{field + ':':<{width + 2}}"
                f"{patch_value_for_display(entry[field])}"
            )
    return lines


def print_patch_dictionary(
    entry: dict[str, Any],
    *,
    title: str,
    index: int | None = None,
) -> None:
    print()
    print(title)
    if index is not None:
        print(f"Kernel -> Patch index: {index}")
    for line in patch_summary_lines(entry):
        print(line)


def print_patch_collection(
    entries: Sequence[tuple[int, dict[str, Any]]],
    *,
    title: str,
) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)
    if not entries:
        print("No CPUID brand patches were found in config.plist.")
        return

    for index, entry in entries:
        print_patch_dictionary(
            entry,
            title="Existing CPUID brand patch:",
            index=index,
        )


def remove_cpuid_brand_patches(
    config: dict[str, Any],
) -> list[tuple[int, dict[str, Any]]]:
    patches = validate_config_structure(config)
    removed: list[tuple[int, dict[str, Any]]] = []
    for index in range(len(patches) - 1, -1, -1):
        entry = patches[index]
        if looks_like_cpuid_brand_patch(entry):
            removed.append((index, entry))
            del patches[index]
    removed.reverse()
    return removed


def decode_nvram_text_value(value: Any) -> tuple[str, str, bytes | None]:
    if isinstance(value, str):
        return value.rstrip("\x00"), "str", None

    if isinstance(value, bytes):
        trailing = b""
        body = value
        while body.endswith(b"\x00"):
            trailing += b"\x00"
            body = body[:-1]

        try:
            text = body.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text = body.decode("latin-1")
            encoding = "latin-1"

        return text, encoding, trailing

    raise TypeError(f"unsupported revcpuname value type: {type(value).__name__}")


def encode_nvram_text_value(
    normalized_text: str,
    *,
    original_value: Any,
    encoding: str,
    trailing: bytes | None,
) -> Any:
    if isinstance(original_value, str):
        return normalized_text
    if isinstance(original_value, bytes):
        return normalized_text.encode(encoding) + (trailing or b"")
    raise TypeError(f"unsupported revcpuname value type: {type(original_value).__name__}")


def find_normalized_start(
    text: str,
    preferred_target: str | None,
) -> tuple[str, int] | None:
    candidates: list[tuple[int, str]] = []

    if preferred_target:
        index = text.find(preferred_target)
        if index >= 0:
            candidates.append((index, preferred_target))

    for token in KNOWN_CANONICAL_TOKENS:
        index = text.find(token)
        if index >= 0:
            candidates.append((index, token))

    if not candidates:
        return None

    index, token = min(candidates, key=lambda item: item[0])
    return token, index


@dataclass(frozen=True)
class RevCpuNameUpdate:
    guid: str
    key: str
    old_value: Any
    new_value: Any
    old_text: str
    new_text: str
    skipped_prefix: str
    value_type: str


def find_revcpuname_updates(
    config: dict[str, Any],
    *,
    preferred_target: str | None,
) -> list[RevCpuNameUpdate]:
    nvram = config.get("NVRAM")
    if not isinstance(nvram, dict):
        return []

    add = nvram.get("Add")
    if not isinstance(add, dict):
        return []

    updates: list[RevCpuNameUpdate] = []
    for guid, values in add.items():
        if not isinstance(values, dict):
            continue

        for key, value in values.items():
            if str(key).lower() != "revcpuname":
                continue

            try:
                text, encoding, trailing = decode_nvram_text_value(value)
            except TypeError:
                print()
                print(
                    f"revcpuname at NVRAM -> Add -> {guid} -> {key} has "
                    f"unsupported type {type(value).__name__}; leaving it unchanged."
                )
                continue

            normalized = find_normalized_start(
                text,
                preferred_target,
            )
            if normalized is None:
                print()
                print(
                    f"revcpuname at NVRAM -> Add -> {guid} -> {key} does "
                    "not contain a known normalized vendor token; leaving it unchanged."
                )
                continue

            token, index = normalized
            if index == 0:
                print()
                print(
                    f"revcpuname at NVRAM -> Add -> {guid} -> {key} already "
                    f"starts with {token!r}; no revcpuname update is needed."
                )
                continue

            new_text = text[index:]
            new_value = encode_nvram_text_value(
                new_text,
                original_value=value,
                encoding=encoding,
                trailing=trailing,
            )
            updates.append(
                RevCpuNameUpdate(
                    guid=str(guid),
                    key=str(key),
                    old_value=value,
                    new_value=new_value,
                    old_text=text,
                    new_text=new_text,
                    skipped_prefix=text[:index],
                    value_type="Data" if isinstance(value, bytes) else "String",
                )
            )

    return updates


def print_revcpuname_updates(
    updates: Sequence[RevCpuNameUpdate],
) -> None:
    print()
    print("=" * 78)
    print("REVCPUNAME CHECK")
    print("=" * 78)

    if not updates:
        print("No revcpuname value with a removable prefix was found.")
        return

    for update in updates:
        print()
        print(f"NVRAM -> Add -> {update.guid} -> {update.key}")
        print(f"Type:   {update.value_type}")
        print(f"Before: {update.old_text}")
        print(f"After:  {update.new_text}")
        print(f"Prefix removed from revcpuname: {update.skipped_prefix!r}")


def apply_revcpuname_updates(
    config: dict[str, Any],
    updates: Sequence[RevCpuNameUpdate],
) -> None:
    nvram = config.get("NVRAM")
    if not isinstance(nvram, dict):
        return
    add = nvram.get("Add")
    if not isinstance(add, dict):
        return

    for update in updates:
        values = add.get(update.guid)
        if not isinstance(values, dict):
            continue
        values[update.key] = update.new_value


def write_change_log(
    destination: Path,
    *,
    config_path: Path | None,
    removed_patches: Sequence[tuple[int, dict[str, Any]]],
    added_patch: dict[str, Any] | None,
    revcpuname_updates: Sequence[RevCpuNameUpdate],
    runtime_brand: str,
    normalized_brand: str | None,
) -> None:
    lines: list[str] = []
    lines.append(f"CPUID Brand Patch Generator v{VERSION} change log")
    lines.append("")
    lines.append(f"config.plist: {config_path if config_path else '<not modified>'}")
    lines.append(f"runtime brand before reboot: {runtime_brand}")
    if normalized_brand:
        lines.append(f"expected brand after reboot: {normalized_brand}")
    lines.append("")

    if removed_patches:
        lines.append("Removed old CPUID brand patches:")
        for index, entry in removed_patches:
            lines.append("")
            lines.append(f"Kernel -> Patch[{index}]")
            lines.extend(patch_summary_lines(entry))
    else:
        lines.append("Removed old CPUID brand patches: none")

    lines.append("")
    if added_patch is not None:
        lines.append("Added CPUID brand patch:")
        lines.extend(patch_summary_lines(added_patch))
    else:
        lines.append("Added CPUID brand patch: none")

    lines.append("")
    if revcpuname_updates:
        lines.append("Updated revcpuname values:")
        for update in revcpuname_updates:
            lines.append("")
            lines.append(f"NVRAM -> Add -> {update.guid} -> {update.key}")
            lines.append(f"Type:   {update.value_type}")
            lines.append(f"Before: {update.old_text}")
            lines.append(f"After:  {update.new_text}")
    else:
        lines.append("Updated revcpuname values: none")

    (destination / "config-change-log.txt").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def find_exact_duplicate(
    config: dict[str, Any],
    patch: dict[str, Any],
) -> tuple[int, dict[str, Any]] | None:
    patches = config.get("Kernel", {}).get("Patch", [])
    if not isinstance(patches, list):
        return None

    for index, entry in enumerate(patches):
        if not isinstance(entry, dict):
            continue
        if (
            entry.get("Identifier") == patch["Identifier"]
            and entry.get("Base") == patch["Base"]
            and entry.get("Find") == patch["Find"]
            and entry.get("Replace") == patch["Replace"]
        ):
            return index, entry
    return None


def load_plist(path: Path) -> tuple[dict[str, Any], plistlib.PlistFormat]:
    try:
        original = path.read_bytes()
    except OSError as exc:
        raise GeneratorError(f"Could not read {path}: {exc}") from exc

    format_value = (
        plistlib.FMT_BINARY if original.startswith(b"bplist00")
        else plistlib.FMT_XML
    )
    try:
        config = plistlib.loads(original)
    except Exception as exc:
        raise GeneratorError(f"Could not parse {path}: {exc}") from exc

    if not isinstance(config, dict):
        raise GeneratorError(f"{path} does not contain a root plist dictionary")
    return config, format_value


def validate_config_structure(config: dict[str, Any]) -> list[dict[str, Any]]:
    kernel = config.get("Kernel")
    if not isinstance(kernel, dict):
        raise GeneratorError("config.plist has no Kernel dictionary")

    patches = kernel.get("Patch")
    if not isinstance(patches, list):
        raise GeneratorError("config.plist has no Kernel -> Patch array")
    return patches


def write_config_with_backup(
    path: Path,
    config: dict[str, Any],
    plist_format: plistlib.PlistFormat,
) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(
        f"{path.name}.before-cpuid-brand-auto-{timestamp}"
    )
    temporary = path.with_name(f".{path.name}.cpuid-brand-auto.tmp")

    try:
        shutil.copy2(path, backup)
        with temporary.open("wb") as fp:
            plistlib.dump(
                config,
                fp,
                fmt=plist_format,
                sort_keys=False,
            )

        lint = run(
            ["/usr/bin/plutil", "-lint", str(temporary)],
            check=False,
        )
        if lint.returncode != 0:
            details = ((lint.stdout or "") + (lint.stderr or "")).strip()
            raise GeneratorError(
                "plutil rejected the modified configuration"
                + (f":\n{details}" if details else "")
            )

        try:
            shutil.copymode(path, temporary)
        except OSError:
            pass

        os.replace(temporary, path)
    except PermissionError as exc:
        raise GeneratorError(
            f"Permission denied while updating {path}. "
            "Run the generator with sudo or copy the EFI to a writable location."
        ) from exc
    finally:
        if temporary.exists():
            temporary.unlink()

    return backup


def prompt_config_path(
    supplied_path: str | None,
    *,
    no_config: bool,
    interactive: bool,
) -> Path | None:
    if no_config:
        return None
    if supplied_path:
        return Path(supplied_path).expanduser()

    if not interactive:
        return DEFAULT_CONFIG

    print()
    entered = input(
        f"OpenCore config.plist path [{DEFAULT_CONFIG}]\n"
        "(press Enter for the default, or type - to skip modification): "
    ).strip()

    if entered == "-":
        return None
    return Path(entered).expanduser() if entered else DEFAULT_CONFIG


def generate_patch(
    *,
    kc_path: Path,
    cpu_brand: str,
    target_substring: str,
    skip_bytes: int,
    kernel_version: str,
    macos_build: str,
    temporary_directory: Path,
) -> GeneratedPatch:
    nm_path = command_path("nm")
    otool_path = command_path("otool")

    nm_result = run([nm_path, "-an", str(kc_path)])
    symbols = parse_symbols(nm_result.stdout)

    candidate_symbols = [
        symbol
        for name in SYMBOL_CANDIDATES
        for symbol in symbols
        if symbol.name == name and symbol.symbol_type in {"T", "t"}
    ]
    if not candidate_symbols:
        raise GeneratorError(
            "Neither _cpuid_set_generic_info nor _cpuid_set_info "
            "was found in the kernel symbol table"
        )

    image = inspect_kernel_image(kc_path)
    container_bytes = kc_path.read_bytes()

    recognized: list[
        tuple[Symbol, bytes, int, LoopMatch, list[Instruction]]
    ] = []

    for symbol in candidate_symbols:
        function_bytes, function_fileoff = extract_function(
            kc_path,
            image,
            symbol,
            symbols,
        )
        synthetic_path = (
            temporary_directory
            / f"{symbol.name.lstrip('_')}-{symbol.address:x}.macho"
        )
        build_synthetic_macho(
            synthetic_path,
            symbol,
            function_bytes,
        )

        disassembly = run(
            [otool_path, "-tvV", "-p", symbol.name, str(synthetic_path)],
            check=False,
        )
        if disassembly.returncode != 0:
            continue

        instructions = parse_otool_disassembly(disassembly.stdout)
        if not instructions:
            continue

        disassembly_text = disassembly.stdout.lower()
        if not all(
            token in disassembly_text
            for token in ("80000002", "80000003", "80000004")
        ):
            continue

        try:
            loop_match = find_brand_space_loop(instructions)
        except GeneratorError:
            continue

        recognized.append(
            (
                symbol,
                function_bytes,
                function_fileoff,
                loop_match,
                instructions,
            )
        )

    if not recognized:
        raise GeneratorError(
            "A CPUID function was found, but no recognized brand-copy loop "
            "was found. The generator refuses to create an unverified patch."
        )
    if len(recognized) > 1:
        names = ", ".join(
            f"{item[0].name}@0x{item[0].address:x}"
            for item in recognized
        )
        raise GeneratorError(
            f"Multiple recognizable CPUID brand loops were found: {names}"
        )

    (
        symbol,
        function_bytes,
        function_fileoff,
        loop_match,
        instructions,
    ) = recognized[0]

    lea_address = loop_match.lea_instruction.address
    lea_offset = lea_address - symbol.address
    if not 0 <= lea_offset < len(function_bytes):
        raise GeneratorError("LEA address falls outside the extracted function")

    next_addresses = [
        instruction.address
        for instruction in instructions
        if instruction.address > lea_address
    ]
    if not next_addresses:
        raise GeneratorError("Could not determine the LEA instruction length")

    next_address = min(next_addresses)
    instruction_length = next_address - lea_address
    if not 3 <= instruction_length <= 15:
        raise GeneratorError(
            f"Unexpected LEA instruction length: {instruction_length}"
        )

    instruction_bytes = function_bytes[
        lea_offset:lea_offset + instruction_length
    ]
    lea_encoding = decode_lea_displacement(
        instruction_bytes,
        skip_bytes,
    )

    (
        find_bytes,
        replace_bytes,
        function_occurrences,
        container_occurrences,
    ) = choose_unique_context(
        function_bytes,
        container_bytes,
        lea_offset,
        instruction_length,
        lea_encoding.displacement_offset,
        lea_encoding.displacement_size,
        lea_encoding.new_displacement,
    )

    search_limit = max(
        1024,
        align(lea_offset + len(find_bytes) + 64, 256),
    )
    search_limit = min(search_limit, 0x10000)

    normalized_brand = cpu_brand[skip_bytes:]
    safe_original = cpu_brand.replace("\n", " ").strip()
    safe_normalized = normalized_brand.replace("\n", " ").strip()
    comment = (
        f"{GENERATOR_MARKER} {macos_build}: "
        f"skip {skip_bytes} bytes, {safe_original} -> {safe_normalized}"
    )
    if len(comment) > 180:
        comment = comment[:177] + "..."

    patch: dict[str, Any] = {
        "Arch": "x86_64",
        "Base": symbol.name,
        "Comment": comment,
        "Count": 1,
        "Enabled": True,
        "Find": find_bytes,
        "Identifier": "kernel",
        "Limit": search_limit,
        "Mask": b"",
        "MaxKernel": kernel_version,
        "MinKernel": kernel_version,
        "Replace": replace_bytes,
        "ReplaceMask": b"",
        "Skip": 0,
    }

    return GeneratedPatch(
        patch=patch,
        symbol=symbol,
        kernel_image=image,
        function_fileoff=function_fileoff,
        function_size=len(function_bytes),
        lea_offset_from_symbol=lea_offset,
        lea_encoding=lea_encoding,
        skip_bytes=skip_bytes,
        original_brand=cpu_brand,
        normalized_brand=normalized_brand,
        target_substring=target_substring,
        find_occurrences_in_function=function_occurrences,
        find_occurrences_in_container=container_occurrences,
        disassembly_excerpt=loop_match.disassembly_excerpt,
    )


def print_patch_summary(
    generated: GeneratedPatch,
    *,
    macos_version: str,
    macos_build: str,
    kernel_version: str,
) -> None:
    patch = generated.patch

    def format_patch_value(key: str, value: Any) -> str:
        if key in {"Find", "Mask", "Replace", "ReplaceMask"}:
            if not isinstance(value, bytes):
                return str(value)
            return hex_bytes(value) if value else "<empty Data>"
        if isinstance(value, bool):
            return "True" if value else "False"
        return str(value)

    ordered_fields = (
        "Arch",
        "Base",
        "Comment",
        "Count",
        "Enabled",
        "Find",
        "Identifier",
        "Limit",
        "Mask",
        "MaxKernel",
        "MinKernel",
        "Replace",
        "ReplaceMask",
        "Skip",
    )

    print()
    print("=" * 78)
    print("GENERATED OPENCORE PATCH")
    print("=" * 78)
    print(f"macOS:             {macos_version} ({macos_build})")
    print(f"Darwin kernel:     {kernel_version}")
    print(f"Kernel UUID:       {generated.kernel_image.uuid or '<not present>'}")
    print(f"CPU brand before:  {generated.original_brand}")
    print(f"CPU brand after:   {generated.normalized_brand}")
    print(f"Bytes skipped:     {generated.skip_bytes}")
    print(f"Target substring:  {generated.target_substring!r}")
    print(f"Symbol address:    0x{generated.symbol.address:x}")
    print(
        "LEA displacement:  "
        f"{format_signed_hex(generated.lea_encoding.old_displacement)} -> "
        f"{format_signed_hex(generated.lea_encoding.new_displacement)}"
    )
    print(
        "Find occurrences:  "
        f"{generated.find_occurrences_in_function} in function, "
        f"{generated.find_occurrences_in_container} in kernel container"
    )

    print()
    print(
        "If you want to add this patch dictionary manually, add it under "
        "Kernel -> Patch:"
    )
    print()

    width = max(len(field) for field in ordered_fields)
    for field in ordered_fields:
        print(
            f"{field + ':':<{width + 2}}"
            f"{format_patch_value(field, patch[field])}"
        )

    print()
    print(
        "Find base64:       "
        + base64.b64encode(patch["Find"]).decode("ascii")
    )
    print(
        "Replace base64:    "
        + base64.b64encode(patch["Replace"]).decode("ascii")
    )

    print()
    print("Recognized disassembly:")
    for line in generated.disassembly_excerpt:
        print(f"  {line}")


def write_generated_files(
    destination: Path,
    generated: GeneratedPatch,
    *,
    macos_version: str,
    macos_build: str,
    kernel_version: str,
    kc_path: Path,
) -> None:
    destination.mkdir(parents=True, exist_ok=True)

    with (destination / "Kernel-Patch-entry.plist").open("wb") as fp:
        plistlib.dump(
            {"KernelPatch": [generated.patch]},
            fp,
            fmt=plistlib.FMT_XML,
            sort_keys=False,
        )

    report = {
        "generator_version": VERSION,
        "macos_version": macos_version,
        "macos_build": macos_build,
        "kernel_version": kernel_version,
        "kernel_collection": str(kc_path),
        "kernel_uuid": generated.kernel_image.uuid,
        "symbol": asdict(generated.symbol),
        "function_fileoff": generated.function_fileoff,
        "function_size": generated.function_size,
        "lea_offset_from_symbol": generated.lea_offset_from_symbol,
        "lea_encoding": asdict(generated.lea_encoding),
        "skip_bytes": generated.skip_bytes,
        "original_brand": generated.original_brand,
        "normalized_brand": generated.normalized_brand,
        "target_substring": generated.target_substring,
        "find_hex": hex_bytes(generated.patch["Find"]),
        "replace_hex": hex_bytes(generated.patch["Replace"]),
        "find_base64": base64.b64encode(
            generated.patch["Find"]
        ).decode("ascii"),
        "replace_base64": base64.b64encode(
            generated.patch["Replace"]
        ).decode("ascii"),
        "find_occurrences_in_function": (
            generated.find_occurrences_in_function
        ),
        "find_occurrences_in_container": (
            generated.find_occurrences_in_container
        ),
        "disassembly_excerpt": list(generated.disassembly_excerpt),
    }
    (destination / "analysis.json").write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    values = f"""\
OpenCore CPUID brand patch generated by v{VERSION}

macOS: {macos_version} ({macos_build})
Darwin: {kernel_version}
Kernel UUID: {generated.kernel_image.uuid or "<not present>"}

CPU brand before:
{generated.original_brand}

CPU brand after:
{generated.normalized_brand}

If you want to add this patch dictionary manually, add it under Kernel -> Patch:

Arch:        {generated.patch["Arch"]}
Base:        {generated.patch["Base"]}
Comment:     {generated.patch["Comment"]}
Count:       {generated.patch["Count"]}
Enabled:     {generated.patch["Enabled"]}
Find:        {hex_bytes(generated.patch["Find"])}
Identifier:  {generated.patch["Identifier"]}
Limit:       {generated.patch["Limit"]}
Mask:        {"<empty Data>" if not generated.patch["Mask"] else hex_bytes(generated.patch["Mask"])}
MaxKernel:   {generated.patch["MaxKernel"]}
MinKernel:   {generated.patch["MinKernel"]}
Replace:     {hex_bytes(generated.patch["Replace"])}
ReplaceMask: {"<empty Data>" if not generated.patch["ReplaceMask"] else hex_bytes(generated.patch["ReplaceMask"])}
Skip:        {generated.patch["Skip"]}

Find base64:
{base64.b64encode(generated.patch["Find"]).decode("ascii")}

Replace base64:
{base64.b64encode(generated.patch["Replace"]).decode("ascii")}
"""
    (destination / "patch-values.txt").write_text(
        values,
        encoding="utf-8",
    )


def print_existing_patch(
    index: int,
    entry: dict[str, Any],
    config_path: Path,
) -> None:
    print()
    print("=" * 78)
    print("EXISTING PATCH FOUND")
    print("=" * 78)
    print(
        f"A CPUID brand patch applicable to the current kernel is already "
        f"present at Kernel -> Patch[{index}] in:"
    )
    print(f"  {config_path}")
    print(f"Enabled:   {entry.get('Enabled', False)}")
    print(f"Base:      {entry.get('Base', '')}")
    print(f"Comment:   {entry.get('Comment', '')}")
    print(f"MinKernel: {entry.get('MinKernel', '')}")
    print(f"MaxKernel: {entry.get('MaxKernel', '')}")
    find = entry.get("Find")
    replace = entry.get("Replace")
    if isinstance(find, bytes):
        print(f"Find:      {hex_bytes(find)}")
    if isinstance(replace, bytes):
        print(f"Replace:   {hex_bytes(replace)}")
    print()
    print("No changes were made.")


def self_test() -> None:
    known_instruction = bytes.fromhex("48 8D B5 4F FF FF FF")
    decoded = decode_lea_displacement(known_instruction, 9)
    assert decoded.old_displacement == -0xB1
    assert decoded.new_displacement == -0xA8
    assert decoded.displacement_offset == 3
    assert decoded.displacement_size == 4

    sample = """\
ffffff80004ba7cf\tleaq\t-0xb1(%rbp), %rsi
ffffff80004ba7d6\tnopw\t%cs:(%rax,%rax)
ffffff80004ba7e0\tmovzbl\t0x1(%rsi), %eax
ffffff80004ba7e4\tincq\t%rsi
ffffff80004ba7e7\tcmpb\t$0x20, %al
ffffff80004ba7e9\tje\t0xffffff80004ba7e0
ffffff80004ba7eb\tmovq\t%rsi, %rdx
"""
    instructions = parse_otool_disassembly(sample)
    match = find_brand_space_loop(instructions)
    assert match.lea_instruction.address == 0xFFFFFF80004BA7CF
    assert match.pointer_register == "rsi"
    assert match.frame_register == "rbp"

    function_bytes = bytes.fromhex(
        "90 90 "
        "48 8D B5 4F FF FF FF "
        "66 2E 0F 1F 84 00 00 00 00 00 "
        "0F B6 46 01 48 FF C6 3C 20 74 F5 "
        "90 90"
    )
    find, replace, function_count, container_count = choose_unique_context(
        function_bytes,
        b"\x00" * 20 + function_bytes + b"\x00" * 20,
        2,
        7,
        decoded.displacement_offset,
        decoded.displacement_size,
        decoded.new_displacement,
    )
    assert function_count == 1
    assert container_count == 1
    assert find[:7] == known_instruction
    assert replace[:7] == bytes.fromhex("48 8D B5 58 FF FF FF")

    print("Self-test passed.")
    print("Known 25F80 displacement: -0xB1 -> -0xA8")
    print(f"Generated test Find:    {hex_bytes(find)}")
    print(f"Generated test Replace: {hex_bytes(replace)}")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze the running x86_64 macOS kernel, generate a scoped "
            "OpenCore patch that removes an unwanted CPU-brand prefix, "
            "and optionally add it to config.plist."
        )
    )
    parser.add_argument(
        "--config",
        help=(
            "OpenCore config.plist path. Without this option, interactive "
            f"mode offers {DEFAULT_CONFIG} as the default."
        ),
    )
    parser.add_argument(
        "--no-config",
        action="store_true",
        help="Generate files only and do not prompt for or modify config.plist.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Apply generated changes without final confirmation prompts. "
            "This also updates prefixed revcpuname values unless "
            "--no-revcpuname is used."
        ),
    )
    parser.add_argument(
        "--keep-existing",
        action="store_true",
        help=(
            "When adding a new patch, keep old CPUID brand patches instead "
            "of replacing them. By default, stale CPUID brand patches are "
            "removed when the runtime brand still has a prefix."
        ),
    )
    parser.add_argument(
        "--no-revcpuname",
        action="store_true",
        help="Do not scan or update NVRAM -> Add -> revcpuname values.",
    )
    parser.add_argument(
        "--target",
        help=(
            "Substring where the normalized brand should begin, for example "
            "Intel or AMD. It must already occur in the CPU brand."
        ),
    )
    parser.add_argument(
        "--skip",
        type=int,
        help=(
            "Explicit number of leading bytes to skip. Normally inferred "
            "from --target or a known vendor token."
        ),
    )
    parser.add_argument(
        "--kernel-collection",
        default=str(DEFAULT_KC),
        help=f"Kernel collection or standalone kernel path (default: {DEFAULT_KC}).",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory for generated plist and analysis files.",
    )
    parser.add_argument(
        "--ignore-existing",
        action="store_true",
        help=(
            "Continue analysis even when a current CPUID brand patch is "
            "already present. Useful with --skip when the running brand "
            "is already normalized."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run parser/encoder tests without inspecting the system kernel.",
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0

    if sys.platform != "darwin":
        raise GeneratorError("This generator must run on macOS")
    if run(["/usr/bin/uname", "-m"]).stdout.strip() != "x86_64":
        raise GeneratorError(
            "This generator supports only x86_64 macOS kernels"
        )

    interactive = sys.stdin.isatty()
    kc_path = Path(args.kernel_collection).expanduser()
    if not kc_path.is_file():
        raise GeneratorError(
            f"Kernel collection was not found: {kc_path}"
        )

    macos_version = sw_vers_value("-productVersion")
    macos_build = sw_vers_value("-buildVersion")
    kernel_version = sysctl_value("kern.osrelease")
    cpu_brand = sysctl_value("machdep.cpu.brand_string")
    boot_arguments = sysctl_value("kern.bootargs")

    print(f"CPUID Brand Patch Generator v{VERSION}")
    print(f"macOS:         {macos_version} ({macos_build})")
    print(f"Darwin:        {kernel_version}")
    print(f"Current brand: {cpu_brand}")
    print(f"Kernel file:   {kc_path}")

    config_path = prompt_config_path(
        args.config,
        no_config=args.no_config,
        interactive=interactive,
    )

    loaded_config: dict[str, Any] | None = None
    config_format: plistlib.PlistFormat | None = None
    existing_patches: list[tuple[int, dict[str, Any]]] = []

    if config_path is not None:
        if config_path.is_file():
            loaded_config, config_format = load_plist(config_path)
            validate_config_structure(loaded_config)
            existing_patches = find_all_cpuid_brand_patches(loaded_config)
            print_patch_collection(
                existing_patches,
                title="CPUID BRAND PATCHES CURRENTLY IN CONFIG.PLIST",
            )
        else:
            print()
            print(f"Config path does not exist: {config_path}")
            if interactive:
                answer = input(
                    "Continue with patch generation only? [Y/n]: "
                ).strip().lower()
                if answer not in {"", "y", "yes"}:
                    print("Cancelled.")
                    return 0
            config_path = None

    if args.skip is not None:
        if args.skip < 0:
            raise GeneratorError("--skip cannot be negative")
        skip_bytes = args.skip
        if skip_bytes >= len(cpu_brand.encode("utf-8")):
            raise GeneratorError("--skip would remove the entire CPU brand")
        target_substring = (
            args.target
            if args.target is not None
            else cpu_brand[skip_bytes:]
        )
    else:
        target_substring, skip_bytes = detect_target_substring(
            cpu_brand,
            args.target,
            interactive=interactive,
        )

    revcpuname_updates: list[RevCpuNameUpdate] = []
    if loaded_config is not None and not args.no_revcpuname:
        revcpuname_updates = find_revcpuname_updates(
            loaded_config,
            preferred_target=target_substring,
        )
        print_revcpuname_updates(revcpuname_updates)

    if skip_bytes == 0:
        print()
        print(
            f"The current CPU brand already begins with "
            f"{target_substring!r}; no new prefix-removal kernel patch is needed."
        )
        if "revcpuname=" in boot_arguments:
            print(
                "Note: kern.bootargs still contains revcpuname=. "
                "The displayed brand may be affected by another patch."
            )

        if not revcpuname_updates or config_path is None or loaded_config is None:
            print("No config.plist changes are needed.")
            return 0

        if args.yes:
            update_revcpuname = True
        elif interactive:
            answer = input(
                "\nUpdate the prefixed revcpuname value(s) in config.plist? [y/N]: "
            ).strip().lower()
            update_revcpuname = answer in {"y", "yes"}
        else:
            update_revcpuname = False

        if not update_revcpuname:
            print("config.plist was not modified.")
            return 0

        apply_revcpuname_updates(loaded_config, revcpuname_updates)
        backup = write_config_with_backup(
            config_path,
            loaded_config,
            config_format if config_format is not None else plistlib.FMT_XML,
        )
        print()
        print("revcpuname value(s) updated successfully.")
        print(f"Modified: {config_path}")
        print(f"Backup:   {backup}")
        return 0

    normalized_brand = cpu_brand[skip_bytes:]
    print()
    print(f"Detected removable prefix: {cpu_brand[:skip_bytes]!r}")
    print(f"Normalized result:         {normalized_brand!r}")

    if existing_patches:
        print()
        print(
            "Runtime check says the CPU brand still has a prefix, so any "
            "existing CPUID brand patch in config.plist is treated as stale "
            "or not applicable to the current boot. A new patch will be "
            "generated for the current kernel."
        )
        if not args.keep_existing:
            print(
                "If you approve modification, the old CPUID brand patch "
                "dictionary/dictionaries listed above will be removed and "
                "replaced with the new one."
            )
        else:
            print(
                "--keep-existing was supplied; old CPUID brand patches will "
                "be left in place and the new one will be appended."
            )

    with tempfile.TemporaryDirectory(prefix="cpuid-brand-auto-") as temp:
        generated = generate_patch(
            kc_path=kc_path,
            cpu_brand=cpu_brand,
            target_substring=target_substring,
            skip_bytes=skip_bytes,
            kernel_version=kernel_version,
            macos_build=macos_build,
            temporary_directory=Path(temp),
        )

    print_patch_summary(
        generated,
        macos_version=macos_version,
        macos_build=macos_build,
        kernel_version=kernel_version,
    )

    if args.output_dir:
        output_dir = Path(args.output_dir).expanduser()
    else:
        timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        output_dir = (
            Path.home()
            / "Desktop"
            / f"CPUIDBrandPatch-{macos_build}-{timestamp}"
        )
        if not output_dir.parent.is_dir():
            output_dir = (
                Path.cwd()
                / f"CPUIDBrandPatch-{macos_build}-{timestamp}"
            )

    write_generated_files(
        output_dir,
        generated,
        macos_version=macos_version,
        macos_build=macos_build,
        kernel_version=kernel_version,
        kc_path=kc_path,
    )
    print()
    print(f"Generated files: {output_dir}")

    if config_path is None:
        write_change_log(
            output_dir,
            config_path=None,
            removed_patches=[],
            added_patch=None,
            revcpuname_updates=[],
            runtime_brand=cpu_brand,
            normalized_brand=normalized_brand,
        )
        print("No config.plist was modified.")
        return 0

    if loaded_config is None or config_format is None:
        loaded_config, config_format = load_plist(config_path)
        validate_config_structure(loaded_config)
        existing_patches = find_all_cpuid_brand_patches(loaded_config)
        if not args.no_revcpuname:
            revcpuname_updates = find_revcpuname_updates(
                loaded_config,
                preferred_target=target_substring,
            )

    exact_duplicate = find_exact_duplicate(
        loaded_config,
        generated.patch,
    )
    if exact_duplicate is not None and args.keep_existing:
        index, entry = exact_duplicate
        print_existing_patch(index, entry, config_path)
        return 0

    if args.yes:
        modify = True
    elif interactive:
        prompt = f"\nModify {config_path} now?"
        if existing_patches and not args.keep_existing:
            prompt += (
                "\nThis will remove the old CPUID brand patch(es) listed "
                "above and add the newly generated patch."
            )
        if revcpuname_updates:
            prompt += "\nThis will also update the prefixed revcpuname value(s)."
        answer = input(prompt + "\n[y/N]: ").strip().lower()
        modify = answer in {"y", "yes"}
    else:
        modify = False

    if not modify:
        write_change_log(
            output_dir,
            config_path=config_path,
            removed_patches=[],
            added_patch=None,
            revcpuname_updates=[],
            runtime_brand=cpu_brand,
            normalized_brand=normalized_brand,
        )
        print("config.plist was not modified.")
        return 0

    patches = validate_config_structure(loaded_config)
    removed_patches: list[tuple[int, dict[str, Any]]] = []

    if existing_patches and not args.keep_existing:
        removed_patches = remove_cpuid_brand_patches(loaded_config)
        print_patch_collection(
            removed_patches,
            title="REMOVED OLD CPUID BRAND PATCHES",
        )

    if (
        exact_duplicate is not None
        and not args.keep_existing
        and not removed_patches
    ):
        # This is defensive; normally the duplicate is also removed above.
        index, entry = exact_duplicate
        print_existing_patch(index, entry, config_path)
        return 0

    patches = validate_config_structure(loaded_config)
    patches.append(generated.patch)

    applied_revcpuname_updates: list[RevCpuNameUpdate] = []
    if revcpuname_updates and not args.no_revcpuname:
        if args.yes:
            update_revcpuname = True
        elif interactive:
            answer = input(
                "\nUpdate the prefixed revcpuname value(s) too? [y/N]: "
            ).strip().lower()
            update_revcpuname = answer in {"y", "yes"}
        else:
            update_revcpuname = False

        if update_revcpuname:
            apply_revcpuname_updates(loaded_config, revcpuname_updates)
            applied_revcpuname_updates = list(revcpuname_updates)
        else:
            print("revcpuname value(s) were left unchanged.")

    write_change_log(
        output_dir,
        config_path=config_path,
        removed_patches=removed_patches,
        added_patch=generated.patch,
        revcpuname_updates=applied_revcpuname_updates,
        runtime_brand=cpu_brand,
        normalized_brand=normalized_brand,
    )

    backup = write_config_with_backup(
        config_path,
        loaded_config,
        config_format,
    )

    print()
    print("config.plist updated successfully.")
    if removed_patches:
        print(f"Removed old CPUID brand patches: {len(removed_patches)}")
    print("Added new CPUID brand patch: 1")
    if applied_revcpuname_updates:
        print(f"Updated revcpuname values: {len(applied_revcpuname_updates)}")
    print(f"Modified: {config_path}")
    print(f"Backup:   {backup}")
    print(f"Change log: {output_dir / 'config-change-log.txt'}")
    print()
    print(
        "Run the ocvalidate binary matching your OpenCore release before "
        "rebooting. Keep a bootable backup EFI."
    )
    if "revcpuname=" in boot_arguments:
        print(
            "Remove the temporary revcpuname= boot argument and restore the "
            "official RestrictEvents.kext before testing this kernel patch."
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GeneratorError as exc:
        eprint()
        eprint(f"Error: {exc}")
        eprint("No OpenCore configuration changes were made.")
        raise SystemExit(1)
    except KeyboardInterrupt:
        eprint("\nCancelled. No OpenCore configuration changes were made.")
        raise SystemExit(130)
