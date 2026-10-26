import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { parseEvidence } from "../dist/domain/evidence.js";
import {
  requireMcpOperationResult,
  requireMcpToolError,
} from "./lib/mcp-verifier-results.mjs";
import {
  createVerifierRun,
  completeVerifierRun,
  assertVerifierCleanupComplete,
} from "./lib/verifier-run.mjs";

if (process.argv.length !== 3 || process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Usage: GHIDRA_INSTALL_DIR=... node scripts/verify-real-ghidra-universal.mjs /path/to/universal",
  );
const path = resolve(process.argv[2]);
const bytes = await readFile(path);
const digest = (value) => createHash("sha256").update(value).digest("hex");
const sha256 = digest(bytes);
const run = createVerifierRun();
const started = performance.now();
const workspace = await mkdtemp(join(tmpdir(), "rea-universal-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [fileURLToPath(new URL("./rea.mjs", import.meta.url)), "mcp"],
  env: {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    TMPDIR: runtime,
    REA_LOG_LEVEL: "silent",
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_PROCESS_RUN_ID: run.run_id,
    GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
    ...(process.env.JAVA_HOME === undefined
      ? {}
      : { JAVA_HOME: process.env.JAVA_HOME }),
  },
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-universal-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
try {
  await client.connect(transport);
  const opened = await call("open_binary", { path });
  const overview = await call("binary_overview");
  const slice =
    overview.analysis_profile.parameters.upstream_analysis_profile.parameters
      .universal_slice;
  assert.ok(slice && Number.isSafeInteger(slice.offset) && slice.size > 0);
  const image = await call("inspect_native_load_image");
  const sources = image.normalized_result.observations.source_files;
  assert.ok(
    sources.some(
      (source) =>
        source.original_sha256 ===
          digest(bytes.subarray(slice.offset, slice.offset + slice.size)) &&
        source.size === slice.size,
    ),
  );
  const procedures = await call("list_procedures");
  const rows = procedures.normalized_result;
  const procedure = rows.find(
    (item) => !item.procedure?.external && item.address?.startsWith("0x"),
  );
  assert.ok(procedure, JSON.stringify(rows));
  const mapping = await call("address_to_file_offset", {
    address: procedure.address,
  });
  const offset = mapping.normalized_result;
  assert.equal(offset.file_offset, offset.provider_file_offset + slice.offset);
  assert.equal(offset.image_base_file_offset, slice.offset);
  assert.equal(offset.source_path, path);
  assert.ok(
    offset.file_offset >= slice.offset &&
      offset.file_offset < slice.offset + slice.size,
  );
  const memory = await call("read_bytes", {
    address: procedure.address,
    length: 16,
  });
  assert.equal(
    memory.normalized_result.bytes_hex,
    bytes.subarray(offset.file_offset, offset.file_offset + 16).toString("hex"),
  );
  const pseudo = await call("procedure_pseudo_code", {
    procedure: `file-offset:0x${offset.file_offset.toString(16)}`,
  });
  assert.ok(JSON.stringify(pseudo).includes(procedure.address));
  const outside = await client.callTool(
    {
      name: "procedure_pseudo_code",
      arguments: { procedure: "file-offset:0x0" },
    },
    { timeout: 240000 },
  );
  const outsideError = requireMcpToolError(outside);
  assert.equal(outsideError.code, "invalid_request");
  assert.match(
    JSON.stringify(outsideError),
    /outside the selected universal Mach-O slice/u,
  );
  await call("close_binary");
  assert.equal(digest(await readFile(path)), sha256);
  assert.deepEqual(
    (await readdir(runtime)).filter((name) => name.startsWith("rea-ghidra-")),
    [],
  );
  report = {
    path,
    sha256,
    imported_sha256: digest(
      bytes.subarray(slice.offset, slice.offset + slice.size),
    ),
    opened,
    overview,
    image,
    mapping,
    memory,
    pseudo,
    outside,
  };
} catch (error) {
  process.stderr.write(stderr);
  throw error;
} finally {
  await client.close();
}
const completed = await completeVerifierRun(run);
assertVerifierCleanupComplete(completed.process_lineage);
await rm(workspace, { recursive: true, force: true });
process.stdout.write(
  JSON.stringify(
    {
      ...report,
      run: completed,
      elapsed_ms: performance.now() - started,
      performance_scope:
        "Cold session elapsed time; token usage, process-family CPU and peak memory not measured",
      cleanup: "complete",
    },
    null,
    2,
  ) + "\n",
);

async function call(name, args = {}) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  const projected = requireMcpOperationResult(result, name);
  if (name === "open_binary" || name === "close_binary") return projected;
  const evidence = parseEvidence(result.structuredContent);
  assert.equal(evidence.subject.digest.sha256, sha256);
  assert.equal(evidence.subject.format, "mach-o-universal");
  return evidence;
}
