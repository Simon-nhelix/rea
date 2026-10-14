import { z } from "zod";
import { CONSOLE_TARGET_FORMATS } from "./consoleRom.js";
import { err, ok, type Result } from "./result.js";

/** Explicit executable or console ROM interpretation selected by the caller. */
export const executableFormatHintSchema = z.enum([
  "dos-com",
  "raw-binary",
  ...CONSOLE_TARGET_FORMATS,
]);
/** Explicit executable interpretation for raw, DOS COM, or console targets. */
export type ExecutableFormatHint = z.infer<typeof executableFormatHintSchema>;

/** Validate the single 64 KiB COM segment, excluding its 256-byte PSP prefix. */
export const validateDosComLength = (length: number): Result<null, string> =>
  Number.isSafeInteger(length) && length >= 1 && length <= 0xff00
    ? ok(null)
    : err(
        "DOS COM requires 1..65280 file bytes (64 KiB segment minus the 256-byte PSP prefix)",
      );
