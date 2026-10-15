# HuC6280 experimental static processor

Language ID: `HuC6280:LE:16:experimental`. The source isolates the caller's
modified Ghidra 12.1.4 65C02 processor into a dedicated module. Stock installed
6502/65C02 files are unchanged. Ghidra's base source is Apache-2.0 (included
LICENSE); the initial appended HuC6280 constructors came from the caller's local
installation without independently established upstream provenance. This is not
official Ghidra HuC6280 support.

## Modeled behavior

- Logical zero page at $2000, eight-bit indexed/pointer wrapping, and bytewise
  stack wrapping within $2100-$21FF. JSR/BSR and RTS preserve the hardware return
  address bias; RTI restores the exact saved PC/status. Absolute and indexed
  indirect JMP pointer reads wrap at the 16-bit logical boundary.
- Runtime T flag: SET affects the immediately following instruction; ordinary
  instructions consume it, PHP stores it cleared, and PLP/RTI can restore it.
  ADC/AND/EOR/ORA redirect the accumulator operand and result to logical
  `$2000 + X`, while leaving A unchanged. SBC consumes T and still operates on A.
- Binary ADC/SBC carry, borrow, overflow and N/Z flags; decimal ADC/SBC with
  preserved V and adjusted-result N/Z. Validation covers valid packed BCD inputs.
- BIT, including immediate BIT, copies operand bits into N/V and tests A for Z.
  Memory BIT captures its operand once for all flags. TRB/TSB take N/V from
  the original memory byte and Z from the modified byte.
  CLA/CLX/CLY preserve arithmetic flags and consume T.
- TII/TDD/TIN/TIA/TAI perform sequential logical-memory byte transfers, including
  overlap propagation, alternation, 16-bit address wrapping and length zero
  meaning 65,536 bytes. Their wrapped stack save/restore of Y/A/X is represented;
  overlapping writes into that saved stack can therefore affect restored values.
- All 256 opcode slots have the mnemonic/length recorded by the reference
  decoder; undefined slots are one-byte NOPs, rather than W65C02 WAI/STP.

## Deliberate limitations

TAM/TMA remain opaque MMR userops. This processor does not dynamically translate
logical addresses through MPR registers. Static ROM mappings and CPU logical
memory are different facts; a correct instruction decode does not establish that
a referenced file bank is known. ST0/ST1/ST2 and speed controls remain explicit
opaque hardware userops. Device side effects, cycle counts, interrupt delivery,
reset sequencing, a game-specific ABI, and exhaustive CPU semantics remain
unverified. Decompiler output is provisional, especially across unknown bank
mapping or hardware operations. Stock 65C02 is not an acceptable fallback.

## References and a resolved disagreement

The [Hudson hardware manual](https://github.com/MiSTer-devel/TurboGrafx16_MiSTer/blob/master/docs/HuC6280%20-%20CMOS%208-bit%20Microprocessor%20Hardware%20Manual.pdf)
(HB-5) limits T-directed operations to ADC/AND/EOR/ORA. The
[software manual](https://github.com/MiSTer-devel/TurboGrafx16_MiSTer/blob/master/docs/HuC6280%20-%20CMOS%208-bit%20Microprocessor%20Software%20Manual.pdf)
provides opcode, status and transfer definitions. The independent
[Mesen CPU implementation](https://github.com/SourMesen/Mesen2/blob/master/Core/PCE/PceCpu.Instructions.cpp)
and [opcode/fetch boundary](https://github.com/SourMesen/Mesen2/blob/master/Core/PCE/PceCpu.cpp)
agree with that T/SBC distinction. The
[MAME implementation](https://github.com/mamedev/mame/blob/master/src/devices/cpu/h6280/h6280.cpp)
instead directs SBC through T. This module follows the Hudson manual and Mesen;
the dedicated runtime fixture also observed accumulator-only SET/SBC. These are
bounded source/emulator comparisons, not independent silicon verification.

## Rebuild and verification

Use an existing caller-owned Ghidra installation. Back up an existing destination,
then copy this directory to `$GHIDRA_INSTALL_DIR/Ghidra/Processors/ReaHuC6280`.
Compile the installed source, preserving the repository's source-only tree:

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" "$GHIDRA_INSTALL_DIR/Ghidra/Processors/ReaHuC6280/data/languages/huc6280.slaspec"
```

Do not commit generated `.sla` files. Restart Ghidra processes that cached the
language catalog. Ghidra 12.1.4/Sleigh compilation and the installed-SLA
`tests/conformance/ghidra/ReaHuC6280SemanticsProbe.java` passed **5,085 assertions**:
256 opcode mnemonic/length rows, binary/valid-BCD arithmetic boundaries, T
consumption/restoration, bit/clear operations, single memory reads for all BIT
forms and one read/write for six RMW families, wrapped indirect JMP, five transfer
modes, sequential overlap, address wrap and zero-length transfer.

The probe also embeds all **17 independently observed romlab/Mesen cases** from
the self-authored `tests/conformance/ghidra/pce-fixture.mjs`. Each runs identical
instruction bytes at the same logical address with matching register/RAM inputs;
PC, low-byte SP, A/X/Y, full status and 32 RAM bytes match the runtime observations.
These comparisons do not establish full BIOS/game equivalence or hardware timing.
The processor probe itself executes only synthetic Ghidra pcode, never a game.

Run it as a headless postScript using `-noanalysis`, this exact processor ID,
and a small raw placeholder import. Require the explicit
`REA_HUC6280_SEMANTICS_OK` marker and all 17 `REA_HUC6280_RUNTIME_MATCH` markers:
headless process exit status alone does not prove script assertions passed.
