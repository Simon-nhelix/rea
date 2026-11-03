import {
  isMipsCodeReferenceArchitecture,
  type CodeReferenceArchitecture,
} from "./romCodeReferences.js";

/** What the static MIPS reference scan cannot see or assumes. */
const MIPS_LIMITATIONS: readonly string[] = [
  "gp_relative hits need the $gp value: it is taken from the caller or from the first lui/addiu $gp initializer found, and applied to every file that opts in (overlays are assumed to share it). When no value is known those references are skipped; after $gp is rewritten inside a function tracking stops until that function ends.",
  "Static linear sweep of aligned 32-bit words; branch targets, delay-slot effects and real control flow are approximated. Register constants are forgotten at jr/j/unconditional branches and call-clobbered registers after jal/jalr.",
  "Not detected: addresses computed indirectly (base plus runtime index, values loaded from memory, arithmetic beyond lui plus addiu/ori/load/store offset), jr jump-table dispatch other than the table's own pointer words, self-modifying code, compressed or encrypted code/data, and references from code or overlays that were not supplied.",
  "pointer_word hits are aligned 32-bit values equal to a target address in any scanned byte, including data that merely looks like a pointer; address_pair and call hits can also come from data decoded as instructions.",
  "Files with the same load address cannot be resident together at runtime; the file a hit belongs to matters, and hits are never merged across files.",
];

/** What the x86 byte sweep over DOS programs cannot see or assumes. */
const X86_LIMITATIONS: readonly string[] = [
  "Static byte-by-byte x86 candidate scan: every offset is decoded as a possible instruction start, so hits can come from data or the middle of another instruction. Prefixes, real control flow and register values are not tracked.",
  "address_pair hits are absolute operands: mov r,imm, push imm, mov to/from moffs, and ModRM displacements of common ALU, mov, lea, movzx/movsx and group instructions. Stack-frame [bp/ebp/esp+disp] operands are skipped; base-plus-index tables report only their displacement.",
  "x86-16 near operands become DS * 16 + offset with one data segment per file (the caller's data_segment, the startup mov ds of an MZ program, or 0x1000 for COM); code that changes DS or reads through ES/SS is not resolved. Far calls, far jumps and relocated far pointers use segment * 16 + offset with load segment 0x1000.",
  "pointer_word hits are relocation or fixup sites when the file header lists them (MZ far pointers, LE/LX offset32 fixups), otherwise aligned 32-bit words in x86-32 raw scans. MZ overlays, segments set at runtime and pointers built from separate words are not found.",
  "Indirect runtime calculations, self-modifying/compressed code, unprovided overlays and DOS extender import fixups remain unresolved.",
  "Hits retain each source file and mapping; identical addresses in different files are not merged.",
];

/** Report the selected decoder's coverage rather than MIPS assumptions for every CPU. */
export const codeReferenceLimitations = (
  architecture: CodeReferenceArchitecture,
): readonly string[] => {
  if (isMipsCodeReferenceArchitecture(architecture)) return MIPS_LIMITATIONS;
  if (architecture === "x86-16" || architecture === "x86-32")
    return X86_LIMITATIONS;
  const decoder =
    architecture === "sh2-be" || architecture === "sh4-le"
      ? "Static aligned 16-bit SuperH sweep with selected PC-literal loads, moves, immediate additions and branches. Call arguments require an available decoded delay slot. Unmodelled instructions discard register constants."
      : architecture === "arm-le" || architecture === "thumb-le"
        ? "Static ARM/Thumb sweep in the selected instruction set only; mode switches and real control flow are not resolved. Argument constants survive only supported straight-line instructions; unknown and conditional writes invalidate them."
        : "Static byte-by-byte opcode candidate scan, not instruction-boundary recovery. CPU/bank state and variable-width immediate decoding are not established; pointer_word and call argument recovery are not implemented for this architecture.";
  return [
    decoder,
    "Address and call candidates can come from data or instruction operands. A match does not establish runtime execution or that a storage region is unused.",
    "Indirect runtime calculations, self-modifying/compressed code, unprovided overlays and unobserved bank mappings remain unresolved.",
    "Hits retain each source file and mapping; identical virtual addresses in different overlays are not merged.",
  ];
};
