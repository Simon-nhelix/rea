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
