import { z } from "incur";
import type { Logger } from "pino";
import { CodeReferenceService } from "../application/romhacking/CodeReferenceService.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";
import { logCliCommand } from "../cliLogging.js";
import { CODE_REFERENCE_ARCHITECTURES } from "../domain/romCodeReferences.js";
import { absoluteCallerPath } from "../filesystem/callerPath.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import type { CliInstance } from "./types.js";

/** `path` or `path:0x800D61D8` (the load address follows the last colon). */
export const parseFileSpec = (
  spec: string,
): { path: string; load_address?: string } => {
  const match = /^(.+):(0[xX][0-9a-fA-F]{1,8})$/u.exec(spec);
  return match?.[1] === undefined || match[2] === undefined
    ? { path: absoluteCallerPath(spec) }
    : { path: absoluteCallerPath(match[1]), load_address: match[2] };
};

/** `0x800CBCE8[:name]` or `0x800D6590+0x40[:name]` (start, optional byte length, optional label). */
export const parseTargetSpec = (
  spec: string,
): { address: string; length?: number; name?: string } => {
  const colonIdx = spec.indexOf(":");
  const core = colonIdx >= 0 ? spec.slice(0, colonIdx) : spec;
  const rawName = colonIdx >= 0 ? spec.slice(colonIdx + 1).trim() : "";
  const namePart = rawName.length > 0 ? { name: rawName } : {};
  const [address = core, length] = core.split("+");
  if (length === undefined) return { address, ...namePart };
  const parsed = Number(length);
  return Number.isSafeInteger(parsed)
    ? { address, length: parsed, ...namePart }
    : { address: core, ...namePart };
};

export const registerCodeReferenceCommands = (
  cli: CliInstance,
  logger: Logger,
): void => {
  const service = new CodeReferenceService();
  cli.command(CLI_COMMANDS.findCodeReferences, {
    description:
      "Find static call/jump, address-formation, PC-literal, block-transfer, and pointer-word references to addresses across code files (MIPS, SuperH, 65816, 6502/HuC6280, ARM/Thumb)",
    options: z.object({
      file: z
        .array(z.string())
        .describe(
          "Repeat per code file: PATH (PS-X EXE/ELF/header supplies load address) or PATH:0xLOADADDR for headerless overlays",
        ),
      target: z
        .array(z.string())
        .describe(
          "Repeat per target: 0xADDRESS[:name] or 0xADDRESS+LENGTH[:name] for a range",
        ),
      architecture: z
        .enum(CODE_REFERENCE_ARCHITECTURES)
        .default("mips-le")
        .describe(
          "Instruction set to scan (mips-le, mips-be, sh2-be, sh4-le, 65816, 6502, huc6280, arm-le, thumb-le)",
        ),
      gp: z
        .string()
        .optional()
        .describe(
          "Value of $gp for gp-relative references; found automatically from lui/addiu $gp when omitted",
        ),
      gpRelative: z
        .boolean()
        .default(true)
        .describe("Detect gp-relative references (--no-gp-relative to skip)"),
      resolveCallArguments: z
        .boolean()
        .default(false)
        .describe(
          "Resolve immediate/address argument registers at call sites (--resolve-call-arguments)",
        ),
      includeCallerSignatures: z
        .boolean()
        .default(false)
        .describe(
          "Include caller_signature surrounding instruction hex at call/jump sites for rom-qa overlay disambiguation (--include-caller-signatures)",
        ),
      kind: z
        .array(
          z.enum([
            "call",
            "jump",
            "address_pair",
            "gp_relative",
            "pointer_word",
          ]),
        )
        .optional()
        .describe("Reference kinds to report (default all)"),
      maxReferences: z
        .number()
        .int()
        .min(1)
        .max(20_000)
        .default(500)
        .describe("Maximum references listed; summary counts stay exact"),
    }),
    run: ({ options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.findCodeReferences, () =>
          finishAnalysisCommand(
            () =>
              service.find(
                {
                  files: options.file.map(parseFileSpec),
                  targets: options.target.map(parseTargetSpec),
                  architecture: options.architecture,
                  ...(options.gp === undefined ? {} : { gp: options.gp }),
                  gp_relative: options.gpRelative,
                  resolve_call_arguments: options.resolveCallArguments,
                  include_caller_signatures: options.includeCallerSignatures,
                  ...(options.kind === undefined
                    ? {}
                    : { kinds: options.kind }),
                  max_references: options.maxReferences,
                },
                { signal },
              ),
            service,
            "rom-code-references",
            "find_code_references",
            signal,
          ),
        ),
      ),
  });
};
