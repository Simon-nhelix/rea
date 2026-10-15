import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { estimateTokenCount } from "tokenx";
import { toolContract } from "../dist/contracts/toolContracts.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";

// Caller-owned ROMs and expected observations stay in a private local manifest.
// This checks public MCP workflows, never executes or distributes a ROM.
const [manifestPath, outputPath] = process.argv.slice(2);
if (!manifestPath || !outputPath || process.argv.length !== 4)
  throw new Error(
    "Usage: node scripts/verify-real-ghidra-console.mjs manifest.json output-directory",
  );
if (!process.env.GHIDRA_INSTALL_DIR)
  throw new Error("Set GHIDRA_INSTALL_DIR to a bring-your-own installation");
const cases = JSON.parse(await readFile(manifestPath, "utf8"));
assert.ok(
  Array.isArray(cases) && cases.length > 0,
  "Manifest must be a nonempty case array",
);
assert.equal(
  new Set(cases.map((spec) => spec.id)).size,
  cases.length,
  "Manifest case IDs must be unique",
);
const root = fileURLToPath(new URL("..", import.meta.url));
const output = resolve(outputPath);
await mkdir(output, { recursive: true });
let interrupted = false;
let activeCall;
for (const signal of ["SIGINT", "SIGTERM"])
  process.once(signal, () => {
    interrupted = true;
    activeCall?.abort();
  });
const report = {
  started_at: new Date().toISOString(),
  node: process.version,
  scope:
    "Real Ghidra public MCP analysis; runtime gameplay and exhaustive CPU semantics are separate",
  token_measurement:
    "tokenx estimate of serialized tool requests and responses; excludes SDK framing, discovery schemas, prompts and actual agent/model usage",
  cpu_time: null,
  peak_process_family_memory: null,
  resource_limitations: [
    "CPU time and peak process-family memory unmeasured",
    "Each case is a fresh analysis session; later calls reuse that session; no cross-run warm cache measurement",
  ],
  cases: [],
};

for (const [index, spec] of cases.entries()) {
  if (interrupted) break;
  assert.ok(typeof spec.id === "string" && /^[a-z0-9_-]+$/u.test(spec.id));
  assert.ok(typeof spec.path === "string" && isAbsolute(spec.path));
  assert.ok(typeof spec.format === "string");
  const folder = join(
    output,
    `${index.toString().padStart(2, "0")}-${spec.id}`,
  );
  await mkdir(folder, { recursive: true });
  const bytes = await readFile(spec.path);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const result = {
    id: spec.id,
    path: spec.path,
    format: spec.format,
    sha256,
    bytes: bytes.length,
    calls: [],
    errors: [],
  };
  const start = performance.now();
  const env = {
    ...process.env,
    REA_ANALYSIS_PROVIDER: "ghidra",
    REA_LOG_LEVEL: "silent",
  };
  delete env.REA_GHIDRA_SEED_FILE;
  if (spec.seeds) env.REA_GHIDRA_SEED_FILE = resolve(spec.seeds);
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [join(root, "scripts/rea.mjs"), "mcp"],
    env,
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => {
    stderr = (stderr + chunk.toString()).slice(-262144);
  });
  const client = new Client({ name: "rea-console-verification", version: "1" });
  let connected = false;
  async function call(name, args = {}, check) {
    const callStart = performance.now();
    const ordinal = result.calls.length;
    const record = {
      name,
      arguments: args,
      request_tokens_estimate: estimateTokenCount(
        JSON.stringify({ name, arguments: args }),
      ),
      file: `${ordinal}-${name}.json`,
    };
    result.calls.push(record);
    const timeout = Number(env.REA_GHIDRA_STARTUP_TIMEOUT_MS ?? 330000) + 90000;
    const controller = new AbortController();
    activeCall = controller;
    let response;
    try {
      // MCP SDK 2 accepts (params, options). The old three-argument API silently
      // used the 60-second default and cancelled legitimate cold imports.
      response = await client.callTool(
        { name, arguments: args },
        {
          timeout,
          maxTotalTimeout: timeout,
          signal: controller.signal,
        },
      );
    } catch (cause) {
      record.elapsed_ms = Math.round(performance.now() - callStart);
      record.status = "transport-failed";
      await writeFile(
        join(folder, record.file),
        JSON.stringify(
          { error: String(cause), elapsed_ms: record.elapsed_ms },
          null,
          2,
        ),
        { mode: 0o600 },
      );
      const error = new Error(`${name}: ${String(cause)}`, { cause });
      error.abortCase = true;
      throw error;
    } finally {
      activeCall = undefined;
    }
    record.elapsed_ms = Math.round(performance.now() - callStart);
    record.response_tokens_estimate = estimateTokenCount(
      JSON.stringify(response),
    );
    await writeFile(
      join(folder, record.file),
      JSON.stringify(response, null, 2),
      { mode: 0o600 },
    );
    if (response.isError) {
      const text =
        response.content?.find((item) => item.type === "text")?.text ?? "";
      let failure;
      try {
        failure = JSON.parse(text).error;
      } catch {
        /* contract error may be plain text */
      }
      if (
        ["execution_failure", "timeout", "resource_constraint"].includes(
          failure?.code,
        )
      ) {
        record.status = "failed";
        const error = new Error(`${name}: ${text}`);
        error.abortCase = true;
        throw error;
      }
    }
    const value = requireMcpOperationResult(response, name, toolContract(name));
    record.status = "returned-valid-contract";
    if (check) {
      check(value);
      record.status = "verified";
    }
    return value;
  }
  async function attempt(name, args, check) {
    try {
      return await call(name, args, check);
    } catch (error) {
      result.errors.push({ name, args, message: String(error) });
      if (error.abortCase) throw error;
    }
  }
  try {
    await client.connect(transport);
    connected = true;
    await call("open_binary", {
      path: spec.path,
      format: spec.format,
      provider_id: "ghidra",
    });
    await attempt("binary_session");
    for (const procedure of spec.procedures ?? ["entry"]) {
      await attempt("procedure_pseudo_code", { procedure }, (v) =>
        assert.ok(
          typeof v === "string" && v.trim().length > 0,
          "nonempty pseudocode",
        ),
      );
      // File-offset selection is a pseudocode operation contract; the other
      // operations take a procedure name or analysis address.
      if (!procedure.startsWith("file-offset:")) {
        await attempt("analyze_function", { procedure });
        await attempt("read_function_instructions", { procedure });
      }
    }
    for (const observation of spec.xrefs ?? []) {
      const address =
        typeof observation === "string" ? observation : observation.address;
      await attempt(
        "xrefs",
        { address },
        typeof observation === "string"
          ? undefined
          : (v) => {
              for (const from of observation.contains ?? [])
                assert.ok(v.includes(from), `missing xref ${from}`);
              for (const from of observation.excludes ?? [])
                assert.ok(!v.includes(from), `unproven xref ${from}`);
            },
      );
    }
    for (const observation of spec.mappings ?? []) {
      await attempt(
        "address_to_file_offset",
        { address: observation.address },
        (v) => assert.equal(v.file_offset, observation.offset),
      );
      await attempt(
        "read_bytes",
        { address: observation.address, length: observation.length ?? 16 },
        (v) =>
          assert.equal(
            v.bytes_hex.toLowerCase(),
            bytes
              .subarray(
                observation.offset,
                observation.offset + (observation.length ?? 16),
              )
              .toString("hex"),
          ),
      );
    }
    for (const observation of spec.instructions ?? [])
      await attempt(
        "inspect_native_instruction",
        { address: observation.address },
        (v) => {
          if (observation.mnemonic)
            assert.equal(
              v.mnemonic.toUpperCase(),
              observation.mnemonic.toUpperCase(),
            );
          if (observation.target)
            assert.ok(
              v.references.some((r) => r.target_address === observation.target),
            );
        },
      );
    if (spec.strings)
      await attempt("search_rom_strings", {
        ...spec.strings,
        resolve_xrefs: true,
      });
  } catch (error) {
    result.errors.push({ name: "session", message: String(error) });
  } finally {
    if (connected) {
      try {
        await attempt("close_binary");
      } catch {
        /* already recorded; always finish client cleanup and reporting */
      }
    }
    await client
      .close()
      .catch((error) =>
        result.errors.push({ name: "client-close", message: String(error) }),
      );
    await writeFile(join(folder, "stderr.log"), stderr, { mode: 0o600 });
    result.elapsed_ms = Math.round(performance.now() - start);
    result.input_preserved =
      createHash("sha256")
        .update(await readFile(spec.path))
        .digest("hex") === sha256;
    if (!result.input_preserved)
      result.errors.push({ name: "input", message: "ROM digest changed" });
    result.status =
      result.errors.length === 0 ? "workflow-checks-passed" : "failed";
    report.cases.push(result);
    await writeFile(
      join(output, "report.json"),
      JSON.stringify(report, null, 2),
      { mode: 0o600 },
    );
    console.log(
      `${spec.id}: ${result.status}; ${result.calls.length} calls; ${(result.elapsed_ms / 1000).toFixed(1)}s; errors=${result.errors.length}`,
    );
  }
}
report.finished_at = new Date().toISOString();
report.interrupted = interrupted;
await writeFile(join(output, "report.json"), JSON.stringify(report, null, 2), {
  mode: 0o600,
});
if (
  interrupted ||
  report.cases.some((c) => c.status !== "workflow-checks-passed")
)
  process.exitCode = 1;
