# Local 65816 processor correction

This is an optional source patch for a bring-your-own Ghidra processor, not a
REA-installed provider or an assertion of complete 65816 emulation.

Source: https://github.com/achan1989/ghidra-65816
Base commit: `b70cb21d5297ebae8dee54e5d140bacd612d670c`.
The upstream module is unmaintained; retain its `LICENSE` (MIT) when distributing
or installing source. `rea-65816.patch` contains source changes only, no SLA.

From a clean checkout of the pinned base:

```sh
git apply /absolute/path/to/rea-65816.patch
/path/to/ghidra/Ghidra/Features/Decompiler/os/mac_arm_64/sleigh data/languages/65816.slaspec
```

Use the matching Sleigh compiler for the host architecture and Ghidra version.
Install the resulting processor directory as `Ghidra/Processors/65816` in a
separate local Ghidra installation. Back up an existing module first. This patch
does not install Ghidra, Java, or any other dependency. The local validation used
Ghidra 12.1.4 and its bundled mac_arm_64 compiler.

The patch preserves upstream bytewise stack, direct-page and bank wrapping,
stack effects for calls and returns, and decimal arithmetic. It fixes static
branch/direct destinations, distinguishes computed jump/call destinations,
zero-extends stack addresses to the bus width, propagates REP/SEP context to the
following instruction, restores runtime status mode bits, and corrects XBA. The legacy compiler-spec
`type` attribute is removed for Ghidra 12.1.4 compatibility. Runtime M/X/E flags
are separate byte registers (`MF`, `XF`, `EF`), rather than reusing decoder
context storage; a p-code emulator must initialize these registers to its known
entry state as well as supplying decoder context. REP/SEP/XCE and status pulls
update runtime mode state explicitly. Status packing initializes its local byte
before bit assignments.
The upstream unknown calling convention is retained rather than inventing a
universal register ABI.

XCE exchanges carry/emulation at runtime. Decoder context follows carry proved
by CLC/SEC; potential carry writers and calls invalidate that proof. Unknown
carry emits `unknown_xce_mode` and does not establish the following decoder
mode. Native PLP/RTI restore runtime M/X but static decode mode remains unknown;
`unknown_native_status_pull` marks that boundary. An analyst or analyzer must
supply proven context after these boundaries. Do not claim downstream decoding
is verified merely because Ghidra produces pseudocode. Conflicting control-flow
paths, entry state, memory mapping, data-bank/direct-page assumptions, operand
fetch across a program-bank boundary, and original upstream instruction bugs
still require independent validation.

`tests/conformance/ghidra/Rea65816SemanticsProbe.java` checks the installed SLA
through real instruction decoding and p-code, including call/return memory
effects, direct/computed control flow, mode-dependent widths and mode propagation.
The Ghidra 12.1.4 headless run passed 164 assertions, including actual p-code
emulation for native stack wrap, emulation JSR wrap, PHP M/X packing, XCE
runtime exchange and constraints, and REP/SEP runtime updates. These checks do
not establish exhaustive CPU or emulator conformance.
