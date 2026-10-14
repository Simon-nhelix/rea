import { z } from "zod";

import { enhancedInputSchemas } from "./enhancedInputs.js";
import { enhancedOutputSchemas } from "./toolOutputSchemaGroups.js";
import { requireOutputSchema } from "./toolOutputSchemaPrimitives.js";
import { examplesFor } from "./toolContractHelpers.js";
import type { ToolContract } from "./toolContractTypes.js";
import { toolContractMetadata } from "./toolEffects.js";
import { FUNCTION_WORKFLOW_TOOL_CONTRACTS } from "./functionWorkflowToolContracts.js";

const enhanced = <Name extends string, Schema extends z.ZodObject>(
  name: Name,
  description: string,
  inputSchema: Schema,
) =>
  ({
    name,
    ...toolContractMetadata(name),
    description,
    kind: "enhanced",
    inputSchema,
    outputSchema: requireOutputSchema(enhancedOutputSchemas, name),
    examples: examplesFor(name, inputSchema),
  }) satisfies ToolContract<Name, Schema>;

/** Workflow tools composed from one or more provider operations. */
export const ENHANCED_TOOL_CONTRACTS = [
  enhanced(
    "inspect_native_dispatch_metadata",
    "Inspect the bound provider's name inventory for Objective-C class/method symbols and Swift mangled symbols, returning at most max_records decoded names. Includes target SHA-256 when available, provider identity/version, analysis-profile digest, facet coverage, and per-record Evidence. This is symbol-level evidence, not runtime metadata: ivar layouts, protocol conformances, witness/class tables, and relative pointers are explicitly marked unsupported unless a provider supplies those decoders. The provider controls how its name inventory is acquired.",
    enhancedInputSchemas.inspect_native_dispatch_metadata,
  ),
  enhanced(
    "get_objc_classes",
    "Discover and deduplicate Objective-C class labels, optionally filtering by literal substring.",
    enhancedInputSchemas.get_objc_classes,
  ),
  enhanced(
    "get_objc_protocols",
    "Discover and deduplicate Objective-C and Swift protocol labels.",
    enhancedInputSchemas.get_objc_protocols,
  ),
  enhanced(
    "batch_decompile",
    "Decompile each explicit procedure symbol or address concurrently. Preserves each input selector in address and reports the observed canonical entry and entry label in procedure; identity or label failures remain explicit without discarding usable pseudocode. Returns ordered per-item success or error results and aggregate counts.",
    enhancedInputSchemas.batch_decompile,
  ),
  enhanced(
    "get_call_graph",
    "Resolve one symbol or address to its canonical procedure entry, then traverse the bound provider's caller or callee relationships until the reachable graph is exhausted. Every node uses a canonical address and has an ok/error status; failures use safe typed projections. Unresolved indirect calls may be missing and results are not a whole-program CFG.",
    enhancedInputSchemas.get_call_graph,
  ),
  enhanced(
    "analyze_swift_types",
    'Categorize analyzed Swift procedure names using their manglings or same-address Swift symbol aliases. Decodes legacy and literal modern nominal contexts into classes, structs, enums, protocols, and extensions. Preserves provider names and supporting mangled_names; unresolved categories appear in other and in unclassified, which remains inline even under category filters. Returns deduplicated procedure-name counts, not unique source types, plus identification limitations. Optionally select one category and/or apply a case-sensitive literal filter to provider names or supporting manglings; for example, use {category: "structs", pattern: "Pair"}.',
    enhancedInputSchemas.analyze_swift_types,
  ),
  enhanced(
    "find_xrefs_to_name",
    "Resolve an exact name against the bound provider's name inventory and return a resolved or unresolved result. Unresolved names use the stable name_not_found reason; this xref workflow returns address-only projections.",
    enhancedInputSchemas.find_xrefs_to_name,
  ),
  enhanced(
    "binary_overview",
    "Return the bound document and exhaustive procedure/string counts, plus every segment and segment_count when the provider supports segment enumeration. If segment fields are omitted, segment coverage is unavailable rather than empty. When every observed segment agrees on an analysis image base, return it as image_base so callers can relate provider addresses to their loader coordinates. Use search_procedures, list_procedures, or analyze_function directly when you already know which procedure to inspect.",
    enhancedInputSchemas.binary_overview,
  ),
  ...FUNCTION_WORKFLOW_TOOL_CONTRACTS,
  enhanced(
    "trace_feature",
    "Trace the complete literal query, preserving spaces, through every matching string and procedure, their xrefs, and truthful containing-procedure resolution. Returns observations, operation count, and residual unknowns without inferring reference kinds.",
    enhancedInputSchemas.trace_feature,
  ),
  enhanced(
    "trace_call_path",
    "Resolve start and optional goal symbols or addresses to canonical procedure entries, then trace direct callers or callees until the graph is exhausted or the goal is reached. Results use canonical addresses; Evidence preserves supplied selectors. Returns visited nodes, direct-call edges, a shortest traversal path, provider failures, and residual unknowns. A requested goal is unknown when unresolved expansions prevent proving it absent; unresolved indirect calls remain unknown.",
    enhancedInputSchemas.trace_call_path,
  ),
  enhanced(
    "trace_native_ui_action",
    "Trace one unique compiled UI action, object ID, native symbol or exact function address through authored connections, encoded or symbolized Objective-C handlers, and bounded static call references. Typed direct and resolved indirect calls, ambiguous candidates, inferred untyped provider callees, and targetless sites remain distinct. Runtime reachability is unknown; use trace_native_values for recovered value dependencies.",
    enhancedInputSchemas.trace_native_ui_action,
  ),
  enhanced(
    "trace_native_values",
    "Trace a bounded static dependency graph from one explicit native procedure. Includes high-p-code def-use, constants, operators, memory and branch operations, resolved call edges, and derived argument/parameter and return/output bindings. Missing bindings, alias semantics, persistent state and RNG roles remain unknown. Budgets bound depth, decompilations, graph size and payloads; nodes are paginated.",
    enhancedInputSchemas.trace_native_values,
  ),
  enhanced(
    "search_rom_strings",
    "Search or scan console ROM memory for localized text in Shift-JIS (sjis/cp932), EUC-JP, UTF-8, UTF-16LE/BE, ASCII, or custom .tbl character tables. Returns virtual addresses, ROM file offsets, raw hex bytes, decoded text, and incoming cross-references for localization and ROM hacking workflows.",
    enhancedInputSchemas.search_rom_strings,
  ),
  enhanced(
    "scan_pointer_table",
    "Scan a 16-bit, 24-bit, or 32-bit pointer table in console ROM or executable memory with configurable endianness, bank base_address, and entry stride. Resolves each slot's target virtual address, ROM file offset, in-place byte budget, decoded string preview (Shift-JIS/EUC-JP/UTF/ASCII/.tbl), optional locbatch.py manuscript records, and incoming cross-references.",
    enhancedInputSchemas.scan_pointer_table,
  ),
  enhanced(
    "discover_pointer_tables",
    "Automatically discover candidate 16-bit, 24-bit, or 32-bit string pointer tables in console ROM or executable memory by scanning for contiguous sequences of pointers whose targets decode to valid strings in Shift-JIS, EUC-JP, UTF, ASCII, or custom .tbl character tables. Reports entry counts, unique target counts, min/max/average string byte lengths for UI width triage, and sample string previews.",
    enhancedInputSchemas.discover_pointer_tables,
  ),
  enhanced(
    "find_code_caves",
    "Find contiguous sequences of unreferenced padding bytes (0x00 or 0xFF, or an explicit fill_byte) in console ROM or executable segments suitable for injecting VWF font hooks, glyph tables, or relocated localized strings. Returns virtual addresses, ROM file offsets, aligned byte lengths, region names, and optional incoming cross-references.",
    enhancedInputSchemas.find_code_caves,
  ),
] as const satisfies readonly ToolContract[];
