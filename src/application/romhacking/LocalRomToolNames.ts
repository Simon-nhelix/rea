/** ROM text tools that can run directly on local file bytes. */
export type LocalRomToolName =
  | "search_rom_strings"
  | "scan_pointer_table"
  | "discover_pointer_tables"
  | "find_code_caves";

export const isLocalRomToolName = (tool: string): tool is LocalRomToolName =>
  tool === "search_rom_strings" ||
  tool === "scan_pointer_table" ||
  tool === "discover_pointer_tables" ||
  tool === "find_code_caves";
