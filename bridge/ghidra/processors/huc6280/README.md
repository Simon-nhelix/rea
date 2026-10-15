# HuC6280 experimental source prototype

Language ID: `HuC6280:LE:16:experimental`. **Not validated for production
HuC6280 decompilation.** This source isolates the previously modified local
Ghidra 12.1.4 `65c02.slaspec` and its stock 6502 dependencies into a separate
processor module. Stock 65C02 language files are not changed. Ghidra's base
source is Apache-2.0 (included LICENSE); the appended local HuC6280 constructors
were received in the caller-owned installation without independent provenance.
They must not be represented as official Ghidra HuC6280 support.

Bounded corrections: indexed TST uses X; its zero-page indexed address wraps at
8 bits and uses HuC6280 logical zero page $2000; absolute indexed TST adds X in
16 bits. SET/CSL/CSH emit explicit opaque userops instead of empty semantics.
These userops expose unknown effects; they do not implement the hardware.

Boundary corrections also relocate ordinary zero-page operands to $2000, wrap
zero-page pointer reads, and use per-byte wrapped stack accesses at $2100,
including JSR/BSR saved return-address bias and RTS restoration. Processor default
blocks use these logical pages. Vector symbols use HuC6280 vector locations;
BRK targets IRQ2 at $FFF6. ST0/ST1/ST2 use explicit opaque port userops, avoiding
incorrect ordinary RAM writes to $0000/$0002/$0003.

Known blocking gaps: HuC6280 T-directed ALU effects are absent; TAM/TMA and block transfers
are opaque userops without MMR mapping/copy effects, length-zero or alternation
semantics. Other ISA conflicts and status behavior have not been fully audited.
Do not use this module's decompiler output as an accurate HuC6280 model.
REA explicitly selects this experimental ID and records these limitations in
Evidence. Selecting stock 65C02 as a fallback is incorrect.

## Rebuild

Use existing Ghidra and copy this directory to
`$GHIDRA_INSTALL_DIR/Ghidra/Processors/ReaHuC6280`, backing up an existing
installation first. Then run:

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" "$GHIDRA_INSTALL_DIR/Ghidra/Processors/ReaHuC6280/data/languages/huc6280.slaspec"
```

Do not commit generated `.sla` files. Ghidra 12.1.4 compilation succeeded.
The installed-SLA `tests/conformance/ghidra/ReaGbPceSemanticsProbe.java` passed
19 assertions on synthetic bytes using Ghidra pcode emulation: ordinary/indexed
zero page, indirect pointer wrapping, indexed TST addresses/flags, JSR/RTS stack
wrapping and return restoration, and SET's opaque effect. Run it as a headless
postScript with `-noanalysis`, the exact experimental ID and a small raw
placeholder import; require the explicit `REA_GB_PCE_SEMANTICS_OK` marker.
This is bounded primitive evidence. No target code was executed, and no complete
ISA differential or hardware emulation test was performed. Original local files
were backed up under the caller's validation cache before creating dedicated
modules.

Hardware references: [HuC6280 manual source](https://github.com/MiSTer-devel/TurboGrafx16_MiSTer/tree/master/docs),
[MAME HuC6280 implementation](https://github.com/mamedev/mame/blob/master/src/devices/cpu/h6280/h6280.cpp).
