# Headerless raw-binary analysis with Ghidra

REA admits a headerless executable or memory snapshot when the caller supplies
the CPU family, load address and entry point. That interpretation is not
inferred from a `.bin` suffix or from unrecognized bytes.

## Open and inspect

```bash
rea inspect /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea function /absolute/path/to/ecu.bin 0x8000000 --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/ecu.bin --target-format raw-binary --architecture arm --entry-point 0x8000000 --provider ghidra --json
```

```json
{
  "name": "open_binary",
  "arguments": {
    "path": "/absolute/path/to/ecu.bin",
    "format": "raw-binary",
    "architecture": "arm",
    "entry_point": "0x8000000",
    "provider_id": "ghidra"
  }
}
```

`architecture` is one of `x86`, `x86_64`, `arm`, `arm64`, `6502`, or `huc6280`.
`entry_point` and optional `load_address` (CLI `--load-address`) are hexadecimal
addresses of the form `0x…`. File offset 0 maps to `load_address`; omitting it
defaults to `entry_point`, preserving the existing workflow. The entry must lie
inside the mapped file. Ghidra seeds an `entry` function at that entry point,
not at an unrelated load address, before auto-analysis.
ARM and AArch64 entries must be 4-byte aligned; x86 and the 8-bit CPU entries may be byte-aligned.
For 6502 and HuC6280, the entry and complete mapped file must fit within `0x0000..0xffff`;
images that cross the 16-bit boundary are rejected before provider startup.
`open_binary` and an open `binary_session` return canonical `entry_point` and `load_address`
for raw targets so callers can verify the selected mapping directly.
Omitted `format` keeps header-based detection; architecture and entry without
`format=raw-binary` are rejected. `load_address` is also exclusive to raw targets.

Ghidra imports a private snapshot with `BinaryLoader` and these little-endian
languages and compiler specifications:

| architecture | language_id                  | compiler_spec_id |
| ------------ | ---------------------------- | ---------------- |
| x86          | `x86:LE:32:default`          | `gcc`            |
| x86_64       | `x86:LE:64:default`          | `gcc`            |
| arm          | `ARM:LE:32:v7`               | `default`        |
| arm64        | `AARCH64:LE:64:v8A`          | `default`        |
| 6502         | `6502:LE:16:default`         | `default`        |
| huc6280      | `HuC6280:LE:16:experimental` | `default`        |

Compiler specifications select analysis conventions; they do not identify the
original compiler or ABI of a headerless target. Ghidra's x86 languages do not
provide a compiler specification named `default`.

Those settings, the caller-supplied entry and load address, and `language_selection:
caller-supplied-v1` are committed in the analysis profile. A different entry,
load address or architecture is a different profile; snapshots from header-detected targets
do not replay.

The mapped start is independent of Ghidra's program image base, which remains
`0x0` for BinaryLoader. Ghidra may report additional language-defined entry
points, including unmapped ARM vectors. Load-image verification requires the
caller-supplied entry and preserves those other entries as observations.
For 6502, BinaryLoader maps the file before adding its language-defined zero-page
and stack blocks. Conflicting default blocks are skipped; low-address files stay
in the default address space rather than an overlay. Non-conflicting uninitialized
blocks remain observations, not file-backed bytes.
Independent raw verification streams the complete private snapshot digest and
extent with bounded memory and supports cancellation during the read.
It also requires the source-backed block to be initialized, loaded, and
non-overlay in the bound language's default address space. Contradictory mapping
observations are retained with `mismatch`, even when the source hashes agree.

Hopper and IDA refuse raw-binary targets. Windows Ghidra P0 admits native PE
applications/DLLs and explicitly selected raw 6502 images. Other raw CPU families
remain outside the Windows boundary. Native path admission, private DACLs, Job
Object ownership, immutable snapshots, and the no-mutation policy still apply.

## NMOS 6502

```bash
rea function /absolute/path/to/image.bin 0x8001 --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
rea inspect-native-load-image /absolute/path/to/image.bin --target-format raw-binary --architecture 6502 --entry-point 0x8001 --provider ghidra --json
```

Select only headerless NMOS 6502 code with a known load address and entry.
The built-in Ghidra processor supplies static instructions, functions,
pseudocode, and references. Evidence preserves `architecture: "6502"`, the
selected language, entry, file digest, and verified source mapping. Register and
calling conventions are analysis conventions, not a recovered source ABI.

This lane does not interpret iNES headers, cartridge mappers, bank switching,
or other console-specific memory layouts. 65C02 and 65816 programs need different
processor semantics and are not admitted as those variants. REA does not infer
the CPU from the file suffix, guess the reset vector, or emulate the target.

`npm run verify:ghidra:6502` assembles and links the source-owned fixture with
`ca65` and `ld65` (tested from cc65 tag `V2.19`, whose tools report `V2.18`).
Set `REA_CA65` and `REA_LD65` to explicit executable paths if needed. The lane
checks real CLI/MCP load-image parity, mapped bytes, decoded calls, decompilation,
invalid mappings, unchanged source bytes and runtime cleanup.
Low-memory checks include a file spanning the zero-page/stack boundary at `0xff`
and a complete 64-KiB image at `0x0`, with verified default-space mappings through
both CLI and MCP. On Windows, the lane also checks that a caller-selected
junction path is rejected at snapshot admission through CLI and MCP, with
unchanged source bytes and complete runtime cleanup. Windows requires the
matching native addon; the POSIX provider path has not been exercised by the
Windows run.

## Frozen HuC6280 memory images

For a paused PC Engine game, an external debugger such as romlab can provide a
CPU logical-memory image with its observed MPR values. Select `huc6280` explicitly
and install the optional [processor source](console-localization.md#processor-prerequisites)
in the caller-owned Ghidra installation. This does not select stock 6502 semantics.

For a captured `$2000..$FFFF` image whose executed call is at `$6286`:

```sh
rea decompile /path/logical-2000-ffff.bin 0x6286 --target-format raw-binary --architecture huc6280 --load-address 0x2000 --entry-point 0x6286 --provider ghidra --format json
rea inspect-native-load-image /path/logical-2000-ffff.bin --target-format raw-binary --architecture huc6280 --load-address 0x2000 --entry-point 0x6286 --provider ghidra --json
```

MCP `open_binary` accepts the same `architecture`, `load_address` and
`entry_point`. Existing function seeds can identify additional observed entries.
The image includes logical zero page and stack at `$2000..$21FF`; it excludes
MMIO at `$0000..$1FFF`. That coverage is a capture choice, not a universal map.

Retain the capture's own SHA-256, source ROM/disc and BIOS digests, paused PC,
cycle/frame, all eight MPR values, exact logical range and debugger source
offsets in a separate receipt. Check that state stayed fixed across the read.
REA verifies the supplied file's load mapping; it does not certify the external
capture or infer its original disc-file offsets. A file offset in this analysis
belongs to the memory-image file.

Analysis uses one frozen logical map. Later `TAM` instructions do not remap
the image, and MMIO, CD loading, timing and interrupts are not emulated. References
after a bank change need another runtime observation. Self-modifying code also
retains the captured instruction operands; take another observation after the
write to establish the executed instruction. Pseudocode remains
provisional under the experimental HuC6280 processor's documented limits.

`tests/conformance/ghidra/ReaRawLoadEntryProbe.java` checks the real loader before
auto-analysis: the complete source extent, file offset zero, the declared entry
function, and absence of an invented function at a distinct load base. Its
arguments are load address, entry address and file length. Run it after
`ReaGhidraPrepareRaw.java` with `-noanalysis`; require its explicit
`REA_RAW_LOAD_ENTRY_OK` marker. Public CLI/MCP load-image checks additionally
verify the imported file digest and named output contracts.

## Limitations

- Headers are not discovered from file bytes. This increment does not guess
  load addresses, vector tables, or memory maps.
- Big-endian, Thumb-only, Cortex-M, and other Ghidra processor variants are
  unsupported.
- Reset vectors, memory-mapped I/O, and firmware boot sequences are not
  emulated.
- Independent load-image verification covers source identity, mapped file
  bytes, the bound language, and the caller-supplied entry. Original bytes
  stay unchanged.
