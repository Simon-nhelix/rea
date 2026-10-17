/** What the static MIPS reference scan cannot see or assumes. */
export const CODE_REFERENCE_LIMITATIONS: readonly string[] = [
  "gp_relative hits need the $gp value: it is taken from the caller or from the first lui/addiu $gp initializer found, and applied to every file that opts in (overlays are assumed to share it). When no value is known those references are skipped; after $gp is rewritten inside a function tracking stops until that function ends.",
  "Static linear sweep of aligned 32-bit words; branch targets, delay-slot effects and real control flow are approximated. Register constants are forgotten at jr/j/unconditional branches and call-clobbered registers after jal/jalr.",
  "Not detected: addresses computed indirectly (base plus runtime index, values loaded from memory, arithmetic beyond lui plus addiu/ori/load/store offset), jr jump-table dispatch other than the table's own pointer words, self-modifying code, compressed or encrypted code/data, and references from code or overlays that were not supplied.",
  "pointer_word hits are aligned 32-bit values equal to a target address in any scanned byte, including data that merely looks like a pointer; address_pair and call hits can also come from data decoded as instructions.",
  "Files with the same load address cannot be resident together at runtime; the file a hit belongs to matters, and hits are never merged across files.",
];
