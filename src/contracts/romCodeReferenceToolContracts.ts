import {
  findCodeReferencesInputSchema,
  findCodeReferencesResultSchema,
} from "../domain/romCodeReferences.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

/** Reference search over several MIPS code files; independent of any open target. */
export const ROM_CODE_REFERENCE_TOOL_CONTRACTS = [
  {
    name: "find_code_references",
    ...toolContractMetadata("find_code_references"),
    kind: "artifact-provider",
    description:
      "Find static references to addresses (functions, strings, tables, or whole address ranges) across several MIPS little-endian code files, each with its own load address (PS-X EXE header supplies it; headerless overlays take load_address), without opening a target or a disassembler. Detects jal/j targets (call/jump), lui plus addiu/ori/load/store address formation (address_pair, reporting the exact formed address), and aligned 32-bit pointer words (pointer_word, e.g. function or string pointer tables). Each hit lists file, file offset, virtual address, instruction text or bytes, register and the exact target address; the summary gives counts per target and states explicitly when 0 references were found. Files sharing a load address cannot coexist at runtime, so the file of a hit matters. Static scan only: indirect addresses, jr jump tables, compressed or encrypted code and absent overlays are not seen.",
    inputSchema: findCodeReferencesInputSchema,
    outputSchema: evidenceResultOf(findCodeReferencesResultSchema),
    examples: [
      {
        title: "Who calls a function, and does anything point at a string?",
        input: {
          files: [
            { path: "/game/SLPS_026.36" },
            { path: "/game/OVL/SNMP_GRP.BIN", load_address: "0x800D61D8" },
          ],
          targets: [{ address: "0x800CBA44" }],
        },
      },
      {
        title: "References into a whole string table",
        input: {
          files: [{ path: "/game/SLPS_026.36" }],
          targets: [{ address: "0x80010000", length: 4096, name: "strings" }],
          kinds: ["pointer_word", "address_pair"],
        },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
