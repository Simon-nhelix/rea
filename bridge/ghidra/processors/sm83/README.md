# Dedicated SM83 language

Language ID: `SM83:LE:16:default`. This is a processor-only snapshot of
[Gekkio/GhidraBoy](https://github.com/Gekkio/GhidraBoy) commit
`42032f9d97e9e502dc10a14743bdb3d1b9388588` (Apache-2.0; included LICENSE).
The Java loader and emulator are not included or invoked. Source copyright
notices are retained. REA modifications: ordinary STOP consumes its following
padding byte and retains the upstream stop userop; POP AF masks F's low nibble.

The dedicated ISA has SM83 flag positions, E8/F8 half-carry/carry calculations,
CB SWAP and SM83 opcode selection. It avoids selecting patched or unmodified
stock Z80. This is static analysis support, not evidence of complete CPU or
hardware emulation: HALT/STOP and interrupt controls remain abstract userops;
STOP glitch/speed switching and interrupt timing are not modeled. The inherited
compiler convention is a decompiler approximation, not a game-specific ABI.
No complete instruction differential test has been performed for this snapshot.

## Rebuild and installation

Use an existing caller-owned Ghidra installation. Copy this entire directory to
its `Ghidra/Processors/ReaSM83` directory, backing up an existing destination
first. Compile that installed source with:

```sh
"$GHIDRA_INSTALL_DIR/support/sleigh" "$GHIDRA_INSTALL_DIR/Ghidra/Processors/ReaSM83/data/languages/sm83.slaspec"
```

Do not compile into the repository or commit generated `.sla` files. Restart any
Ghidra process that had cached its language catalog. REA must require this exact
language ID; stock `z80:LE:16:default` is not an acceptable fallback.

Validation on Ghidra 12.1.4: Sleigh compilation succeeded. The installed-SLA
`tests/conformance/ghidra/ReaGbPceSemanticsProbe.java` passed 21 assertions using
synthetic instruction bytes and Ghidra pcode emulation: STOP length/userop,
invalid Z80 E3, CB SWAP with flags, POP AF masking/SP update, and E8/F8 signed
positive/negative displacement plus Z/N/H/C. This is bounded primitive evidence,
not exhaustive ISA, game-specific decompilation, or hardware timing validation.
Run the probe as a headless postScript with `-noanalysis`, the exact SM83
processor ID and a small raw placeholder import; require the explicit
`REA_GB_PCE_SEMANTICS_OK` marker because a headless process exit status alone
does not establish that a script's assertions passed.
