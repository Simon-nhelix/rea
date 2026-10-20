import {
  findCodeReferencesInputSchema,
  findCodeReferencesResultSchema,
} from "../domain/romCodeReferences.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { evidenceResultOf } from "./toolOutputSchemaPrimitives.js";

/** Reference search over several code files; independent of any open target. */
export const ROM_CODE_REFERENCE_TOOL_CONTRACTS = [
  {
    name: "find_code_references",
    ...toolContractMetadata("find_code_references"),
    kind: "artifact-provider",
    description:
      "Find static references to addresses (functions, strings, tables, or whole address ranges) across several code files (mips-le, mips-be, sh2-be, sh4-le, 65816, 6502, huc6280, arm-le, thumb-le), each with its own load address (PS-X EXE, multi-PT_LOAD ELF32, Saturn IP.BIN, iNES, GBA, or Nintendo 64 cartridge headers supply it automatically; headerless overlays take load_address), without opening a target or a disassembler. Detects call/jump targets, register/PC-literal address formation (address_pair, including MIPS lui+addiu/load/store, SuperH mov.l @(disp,PC) literal loads and jsr @Rn, 65816 long addressing, HuC6280 tii/tai block transfers, and ARM/Thumb literal pools), $gp-relative accesses (gp_relative), and pointer words (pointer_word). Optional resolve_call_arguments reports immediate/address argument registers at call sites, and include_caller_signatures attaches surrounding instruction hex for rom-qa overlay disambiguation.",
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
