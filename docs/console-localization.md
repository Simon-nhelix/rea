# REA with romlab for localization

REA reads ROM bytes and creates ephemeral Ghidra analysis databases. romlab
supplies execution, CPU state, memory observations, input and screenshots. Keep
the ROM SHA-256 and the distinction between these evidence sources throughout
the investigation. A successful decompile does not establish correct CPU
semantics, complete references, or a working localization patch.

## Start with the question

Use `search-rom-strings`, `discover-pointer-tables`, `scan-pointer-table` and
`find-code-caves` to locate candidate text, pointer tables and padding. They can
read local ROM bytes without starting Ghidra. `search-rom-strings` and
`scan-pointer-table` default to `resolve_xrefs: false`; CLI
`--no-resolve-xrefs` makes that choice explicit.

```sh
node scripts/rea.mjs search-rom-strings /path/game.sfc \
  --encoding sjis --start-offset 0x20000 --length 65536 \
  --no-resolve-xrefs --format json
```

### Disc images and unrecognized files

The four ROM text tools also read files that are not admitted as an executable
or console ROM. `--target-format data` reads plain bytes: addresses are file
offsets and no CPU mapping is assumed. When the format is not recognized and no
`--target-format` is given, the CLI falls back to the same mode and reports
`source.reason: "format_not_recognized"`. A `.cue` sheet is read as the
concatenated 2048-byte user data of its first data track (MODE1/2048,
MODE1/2352, or MODE2/2352 Form 1). Matches then carry `sector`
(track-relative, the `.iso` sector number), `offset_in_sector`, and `lba`
(absolute disc LBA); `source.disc` names the image file, its SHA-256, the
first LBA, other data tracks, and sectors whose sync or mode byte did not
match. A `.iso` whose size is a multiple of 2048 reports `sector` and
`offset_in_sector` only. Writing patched sectors back (EDC/ECC) is out of scope.

`inspect-disc-image` reports the cue layout and, when sector 1 carries the
`PC Engine CD-ROM SYSTEM` ID, the PC Engine CD IPL boot record (IPLBLK,
IPLBLN, IPLSTA, IPLJMP, MPR2..6, opening graphics/ADPCM fields, program name):

```sh
node scripts/rea.mjs inspect-disc-image "/path/Game.cue" --format json
```

Some games store text in 16-bit words. `sjis-le16` reads a two-byte Shift-JIS
code from a little-endian word (`C7 82` = `82C7` = 「ど」). `tile-le16` and
`tile-be16` read tilemap words such as PC Engine BAT entries: `word &
tile_mask` (default `0x0FFF`) is a tile index looked up in a `.tbl` whose keys
are tile indexes (`0170=ア`), and `tile_attribute` (for example `0xF000`)
fixes the remaining palette/flip bits; without it each string keeps one
consistent attribute value. `--terminator-word` and `--newline-word` set
16-bit control words. Word scans examine both offset parities by default
(`--word-parity both`) because strings can start at odd offsets; their cursors
keep one restart point per parity.

Range scans accept caller-selected noise filters: `--fullwidth-only` (single-byte
characters end a string), `--min-kana N`, `--max-level2-kanji-ratio R` (share of
JIS level-2 kanji among a string's kanji), `--min-text-score S`, and
`--require-terminator`. `text_score` (shown with `--include-score`) is a
heuristic mean of per-character weights; it is not proof that bytes are text or
data. Placeholder symbols such as `￥` and `§` lower it. `--dedupe` returns each
distinct byte string once with `occurrences` (every file offset) across the
whole selected range.

The CLI `--output <file>` writes every match as JSON Lines without page or
result limits; without a query or range it scans the whole file. The file is
staged beside the destination and published only when complete; an existing
file is replaced only with `--overwrite`. The command prints a summary with the
record count and the output's SHA-256. MCP keeps cursor paging.

For example, on Record of Lodoss War II (PC Engine Super CD-ROM², 46,649,344
bytes of user data):

```sh
node scripts/rea.mjs search-rom-strings "/path/Lodoss II.cue" \
  --encoding sjis-le16 --terminator-word 0xFFFF --newline-word 0xFFFE \
  --min-length 1 --require-terminator --min-text-score 0.6 \
  --output lodoss.jsonl --format json
node scripts/rea.mjs search-rom-strings lodoss2_02.iso \
  --encoding tile-le16 --table-path ui_tiles.tbl --tile-attribute 0xF000 \
  --terminator-word 0 --require-terminator --dedupe --output tiles.jsonl
```

In that game the first command kept 73,520 strings. The project's verified
manuscript lists 70,636 string locations; 70,364 of them start at a returned
offset. The misses are 8 distinct strings, mostly short battle messages built
from placeholders such as `￥の攻撃§`, which fall below the score. With
`--require-terminator` alone, 82,175 strings contain all 70,636 locations
(70,528 start exactly; the others follow data bytes that the project's
extractor trims). The tile scan found the same 37,118 BAT word lists (503
distinct) as the project's own scanner. These counts describe one game and one
table; they are not general precision figures.

### Overlay-relative pointer tables

Disc games often load a block of sectors (an overlay) into one RAM window and
store each string pointer as an offset from the block start, not as a CPU
address. The same block can sit on the disc many times. `--segment
<start>:<length>` (file offsets, decimal or `0x` hex) reads every pointer value
as `start + value`; values at or past `length` point outside the segment.
Segment options select `--base-mode segment`; `--base-mode address` (the
default otherwise) keeps `base_address + value` through the target's address
mapping. In segment mode `--base-address` must stay 0, and the tools need local
file bytes.

`discover-pointer-tables --segment-align <bytes> --segment-length <bytes>`
tries every multiple of `segment-align` as the start of a segment that still
contains the table, and reports the start that fits as `segment_start` on each
table. With a single `--segment` and no range options, the scan covers that
segment. In segment mode a value of 0 or all ones (`0xFFFF` for 16-bit
pointers) ends a table.

`--target-after-terminator` accepts only sentence starts as targets: the
previous byte or word is the terminator, the target is the segment start, or the
string begins exactly where the table ends. The last case covers the common
layout where the first string follows the last table entry instead of a
terminator; every such entry must then point at the table end. Empty strings (a
lone terminator) count as targets, but a table still needs two distinct
non-empty targets.

Each discovered table, and each `scan-pointer-table` result, reports
`coverage` when a terminator is known. The region runs from the lowest target to
the end of the farthest target string. The walk steps from string to string by
terminators and counts `strings`, `referenced_strings`, `unreferenced_offsets`
(first 16), `targets_inside_strings` (targets that are not at a walked string
start), `padding_bytes` (terminators that no entry points at) and
`unreached_targets` (targets after a walk that found no terminator within 4096
bytes). `ratio` is `referenced_strings / (strings + targets_inside_strings +
unreached_targets)`. `complete` means every walked string is a target, no target
falls inside a string, and the walk ended exactly at `region_end`.
`adjacent_to_table` means the region starts where the table ends.
`--min-coverage R` keeps only tables whose `ratio` reaches `R`; a rejected run
does not hide a table that starts inside it. Coverage assumes strings separated
by one terminator unit, so tables that share string suffixes score below 1.

`--max-tables` accepts up to 1000. When the limit stops a scan, the result has
`truncated: true` and `next_start_offset`; pass that value as
`--start-offset` to continue.

On Record of Lodoss War II (the `.iso` above):

```sh
node scripts/rea.mjs discover-pointer-tables lodoss2_02.iso \
  --pointer-size 2 --encoding sjis-le16 --terminator-word 0xFFFF \
  --newline-word 0xFFFE --min-string-length 1 --min-entries 3 \
  --segment-align 2048 --segment-length 0x10000 --target-after-terminator \
  --min-coverage 1 --start-offset 0 --end-offset 46649344 \
  --max-tables 1000 --format json
node scripts/rea.mjs scan-pointer-table lodoss2_02.iso \
  --pointer-size 2 --encoding sjis-le16 --terminator-word 0xFFFF \
  --newline-word 0xFFFE --table-offset 0x24c75 --count 256 \
  --segment 0x19800:0xD800 --format json
```

The whole-disc scan took about 15 seconds in two pages and returned 1,887
tables with `ratio` 1. They include, with the right `segment_start` and entry
count, all 81 dialogue blocks that the project's own scanner finds by their
header (words 2..4 = table offset, word 5 = region end). The 43 town and event
blocks are among them, and every block is `complete` and `adjacent_to_table`.
They also include both tables of the shared module (sector 51, 27 sectors: 16
and 256 entries) in all 66 copies. The project's scanner had counted 15 and
255 entries there, because it required a terminator before every target. The
first entry of each table points at the string that follows the table. Most
other results are item, spell and class name tables that each scene pack
copies (for example a 129-entry item table in 13 copies). Some 3- and 4-entry
results are coincidences. These counts describe one game; they are not general
precision figures.

Use Ghidra when the question needs decoded instructions or analyzed references:

```sh
node scripts/rea.mjs decompile /path/game.sfc entry --provider ghidra --format json
node scripts/rea.mjs instructions /path/game.sfc 0x808000 --provider ghidra --format json
node scripts/rea.mjs xrefs /path/game.sfc 0x808000 --provider ghidra --format json
```

`--resolve-xrefs` opts string/table workflows into that provider. An empty
reference list means no references were established in the analyzed coverage.
It does not prove padding is unused, a string is unreachable, or an indirect
pointer is absent. Raw opcode-shaped data and split immediates are not promoted
to confirmed references. Adjacent pointer distances are allocation candidates,
not proof that the intervening bytes are exclusively owned by that string.

### In-string control codes

Console dialogue mixes glyph bytes with codes that break the line, pause, pick
a colour or name a speaker, and many of those codes carry argument bytes. Those
arguments are raw values, not glyphs. Without a declared argument count a
decoder reads them as text, and an argument that happens to equal the
terminator ends the string early, so the manuscript text, its `byte_length` and
its budget are all wrong.

`scan-pointer-table` accepts `control_codes`, a list the caller declares.
Nothing is inferred from the bytes, because the same byte means different
things in different games.

| Field            | Meaning                                                                                                                                       |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `hex`            | The code's own bytes as stored, e.g. `0A` or `FFFE`. The longest declared match at an offset wins.                                            |
| `name`           | Written into the text as `{NAME}`, so a translator keeps the code in place.                                                                   |
| `argument_bytes` | Raw bytes that follow and are skipped, never decoded. Default 0.                                                                              |
| `role`           | `plain` keeps the code in the line; `line-break` and `page-break` start a new line (and a new page); `end` stops the string. Default `plain`. |

With declarations, each manuscript record adds the units a translator writes
against: `lines`, `pages` through the line list, `character_length` (code
points, counting no code and no argument byte), `longest_line_characters`, and
`control_codes` with each occurrence's `offset`, `byte_length` and
`arguments_hex`. A code whose arguments run past the read window is reported
with `arguments_truncated`. The string terminator ends the string without
appearing in the text or in the occurrence list; a declared code of the same
byte takes precedence, because the declaration states what that byte means
here.

```sh
cat > codes.json <<'JSON'
[
  { "hex": "1B", "name": "COLOR", "argument_bytes": 1 },
  { "hex": "0A", "name": "LINE", "role": "line-break" },
  { "hex": "0C", "name": "PAGE", "role": "page-break" }
]
JSON
node scripts/rea.mjs scan-pointer-table /path/game.bin \
  --table-offset 0x1000 --count 256 --pointer-size 2 \
  --control-codes codes.json --manuscript-only --format json
```

`--control-codes-json '[...]'` declares the same list inline. Giving both flags
at once is refused rather than resolved by precedence. The 16-bit word
encodings (`sjis-le16`, `tile-le16`, `tile-be16`) refuse `control_codes`:
there, `terminator_word` already ends strings and `newline_word` already breaks
lines, and a byte-declared code could land on half a word.

`character_length` counts what the glyph decoder produced. It is not a pixel
width: a proportional font still needs its own width table, and that table is
not read here.

## SNES addresses and instruction state

Ordinary LoROM and HiROM aliases come from one admitted file mapping used by
both local scans and the Ghidra loader. A 4 MiB LoROM includes its final two
physical banks through CPU banks `$FE/$FF`; `$7E/$7F` remain WRAM. Copier headers
are included in file offsets. ExLoROM, ExHiROM, cartridge coprocessors and
mapper-specific layouts are not established by this mapping. Unmodeled file
offsets remain unresolved rather than receiving an invented address.

65816 immediate instruction length depends on E/M/X state. Reset has E=M=X=1.
Native interrupt vectors do not establish M/X, and different entries into the
same bytes can have different modes. A CPU mirror is also a distinct decoding
address: seeding one address does not assert the state of every mirror.

For an otherwise unreachable entry, first use romlab's execution breakpoint
and CPU snapshot to establish the state there. Retain that observation, its
ROM digest and its source-file offset. Then use the existing
[analysis seed workflow](installation.md#ghidra-import-language-and-analysis-seeds).
For an observed native entry with 16-bit accumulator and index registers:

```text
0x9a86a3	context	ctx_EF=0x0
0x9a86a3	context	ctx_MF=0x0
0x9a86a3	context	ctx_XF=0x0
0x9a86a3	function
```

The separators above are literal tabs. Set `REA_GHIDRA_SEED_FILE` to the absolute
path of that file, then reopen analysis. Context values are caller assertions
committed by digest in the analysis profile, not observations made by Ghidra.
Unknown, oversized, overlapping-conflicting or non-context register assignments
are rejected. Code/function seeds need initialized mapped memory.

```sh
REA_GHIDRA_SEED_FILE=/path/entry-state.tsv \
  node scripts/rea.mjs decompile /path/game.sfc 0x9a86a3 --provider ghidra --format json
REA_GHIDRA_SEED_FILE=/path/entry-state.tsv \
  node scripts/rea.mjs decompile /path/game.sfc --file-offset 0x0d06a3 --provider ghidra --format json
```

File-offset selection is supported by the decompile operation. Other procedure
operations use the resolved analysis address or procedure name. Preserve both
the selected file offset and returned address. An address without known 65816
context must not silently acquire a guessed M/X state. PLP/RTI and XCE with
unknown carry still limit proof of downstream instruction widths; inspect the
returned limitations and use another observed entry when needed.

## Processor prerequisites

These are optional source corrections for an existing, caller-owned Ghidra
installation. REA setup does not install them or modify Ghidra. Back up an
existing processor module and compile with that installation's Sleigh compiler.
Generated SLA files and ROMs do not belong in the repository.

| Target    | Selected language            | Scope                                                                                                                                                                                                                                                                                                          |
| --------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SNES      | `65816:LE:16:default`        | [Pinned source patch](https://github.com/morluto/rea/tree/main/bridge/ghidra/processors/65816). Restored call/return, stack, status and addressing semantics; dynamic mode boundaries remain limited.                                                                                                          |
| Game Boy  | `SM83:LE:16:default`         | [Dedicated SM83 source](https://github.com/morluto/rea/tree/main/bridge/ghidra/processors/sm83), rather than a Z80 mode patch. Hardware timing and mapper transitions are not emulated.                                                                                                                        |
| PC Engine | `HuC6280:LE:16:experimental` | [Experimental HuC6280 source](https://github.com/morluto/rea/tree/main/bridge/ghidra/processors/huc6280). T-mode arithmetic and logical block transfers have bounded validation. Explicit raw memory images can expose CD-loaded code; dynamic MPR remapping remains unresolved and pseudocode is provisional. |

Missing dedicated processor IDs fail instead of falling back to stock Z80 or
65C02. The source directories preserve upstream revisions, licenses, rebuild
instructions and validation limits. Generic language availability is not
evidence of support for a console CPU variant.

For raw Dreamcast code use `--target-format dc-bin`, including binaries such
as `1NOSDC.BIN`. Arbitrary `.bin` opcode or pointer coincidences do not identify
a Dreamcast image. Automatic basename recognition is limited to `1ST_READ.BIN`.
Saturn standalone IP.BIN boot analysis is distinct from the separately loaded
game executable. NDS entry analysis covers the selected ARM9 image; it does not
establish ARM7 or runtime overlay coverage. Bank-switched consoles expose
static mapped windows, not every possible runtime bank selection.

PC Engine cartridge admission establishes only bank0 at `$E000..$FFFF` for
reset analysis. The reset value is preserved even when it points outside that
known window. Neither a pointer's storage location nor its file offset proves
the MPR mapping of its target. In the tested System Card 3 BIOS, `TAM #$40`
sets MPR6 to 1 before `JSR $CB0F`: romlab reads file `$2B0F` there. The former
fixed-window assumption selected file `$AB0F`, which contains unrelated data.
The revised mapping leaves this destination unresolved. Its mapping scope is
included in the analysis profile digest.

CD-loaded game code requires a separate memory image. Capture a paused logical
range in romlab, record MPR/source mappings and verify that CPU state did not
change across the read. Analyze the file with `format=raw-binary`,
`architecture=huc6280`, and distinct `load_address` and `entry_point` when needed.
The [raw memory-image workflow](raw-binary.md#frozen-huc6280-memory-images) explains
the required provenance and limits. REA reads that selected file; it does not
acquire memory or attach to the emulator.

In the tested Ziria Korean build, the font hook at `$6286` calls `$8E88` in CD RAM
(RAM offsets `$2286` and `$4E88` with observed MPR3=`$81`, MPR4=`$82`).
A capture of `$2000..$FFFF` maps those instructions to snapshot-file offsets
`$4286` and `$6E88`. These offsets have different origins and must remain distinct.
The snapshot does not establish a disc-file origin or a valid map after `TAM`.

That font routine also rewrites its own bank and `TII` source operands. In one
observed glyph path, character bytes `95 80` selected MPR6=`$68`, then
`TII $D280,$33CD,#$0020` copied 32 bytes from Card RAM offset `$1280` to Work RAM
offset `$13CD`, with identical source and destination bytes after the step.
The earlier snapshot contained different operands. Its static pseudocode
therefore explains the patching logic but cannot establish the later copy
source. Capture after the code write and bank switch when inspecting that copy.

## Match static analysis to execution

1. Open the same digest in romlab. Use an execution watch on the source ROM
   offset when mirrors could hide the executed CPU address.
2. At the hit, record PC, status, data bank, direct page and stack pointer. Read
   the instruction bytes and source mapping. A seed for one entry does not
   establish all downstream CPU state.
3. Compare REA's decoded instruction and typed reference with romlab. For a
   call, step one instruction and check the destination and stack effect.
4. Exercise the actual text/menu routine, including cancel or failure when
   relevant, its return and the next input. Inspect the screenshots directly.
5. Close the romlab connection and REA session. Keep code-level findings,
   visual observations and tested gameplay branches separate.

The local FE5 validation used this sequence for the suspend confirmation:
`$9A86A3` / file `$0D06A3` contains `22 33 80 85` (`JSL $858033`). At the actual
breakpoint P=`$81` and S=`$1F8E`; one step reached `$858033`, changed S to
`$1F8B`, and stored return bytes `A6 86 9A` at `$1F8C..$1F8E`. This validates
that selected path and state, not all code in the game. The confirmation was
displayed, declined, and cursor input worked after returning to the map.

## Repeatable verification

The installed-SLA probes in `tests/conformance/ghidra` use synthetic bytes and
Ghidra p-code emulation: `Rea65816SemanticsProbe.java` and
`ReaGbPceSemanticsProbe.java`. Require their explicit success markers; Ghidra's
process exit status alone can hide a failed script. Their bounded assertions
do not establish exhaustive ISA or hardware conformance.

`ReaHuC6280SemanticsProbe.java` extends this with 256 opcode decode slots,
arithmetic and T-flag sequences, pointer wrapping, and five logical-memory
block transfers. Its 17 observed-state cases match the self-authored
`pce-fixture.mjs` HuCard executed through romlab, including final PC, registers,
flags and 32 RAM bytes. This does not validate hardware timing, interrupt
interleaving, MPR remapping or MMIO transfer side effects.

For caller-owned real ROMs, use a private manifest with a unique `id`, absolute
`path`, `format`, and optional `procedures`, `xrefs`, `mappings`, `instructions`,
`strings`, and absolute `seeds` path. For example:

```json
[
  {
    "id": "snes-reset",
    "path": "/path/game.sfc",
    "format": "snes",
    "procedures": ["entry"]
  }
]
```

```sh
npm run build:cached
GHIDRA_INSTALL_DIR=/path/ghidra \
  node scripts/verify-real-ghidra-console.mjs /path/cases.json /path/results
```

The verifier uses real public MCP calls, validates named contracts, retains
responses and timings, and checks input hashes after closing each case.
Optional mapping/byte and instruction/reference expectations strengthen a
nonempty-result check. Requests reuse one analysis session per ROM. Token counts
are estimates for serialized tool requests/responses and exclude SDK framing,
discovery schemas, prompts and billed agent usage; CPU
and peak process-family memory require a separate measurement. A workflow pass
does not waive processor limitations or prove gameplay behavior.

For a caller-owned memory image, the manifest also accepts `format: "raw-binary"`,
`architecture`, `entry_point`, optional `load_address`, and `load_image: true`
to require independent load-image verification. Retain its external capture
receipt alongside the report; a raw file's digest alone cannot establish the
state from which it was acquired.
