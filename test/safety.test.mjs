/**
 * Covers src/safety.ts: the tool-tier classifier, the SOPHOS_MCP_READONLY /
 * SOPHOS_MCP_ALLOW_DESTRUCTIVE env policy, and that applySafetyGating
 * actually suppresses registration (not just annotation) for a disallowed
 * tool. No credentials and no network.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  applySafetyGating,
  classifyTool,
  isDestructiveAllowed,
  isReadonlyMode,
  isToolAllowed,
} from "../dist/safety.js";

test("classifyTool: representative real tool names from this repo", () => {
  const cases = [
    ["sophos_list_endpoints", "read"],
    ["sophos_get_alert", "read"],
    ["sophos_search_alerts", "read"],
    ["sophos_create_case", "write"],
    ["sophos_update_policy", "write"],
    ["sophos_delete_endpoint", "destructive"],
    ["sophos_isolate_endpoint", "destructive"],
    ["sophos_clawback_message", "destructive"],
    ["sophos_bulk_delete_endpoints", "destructive"],
    ["sophos_wipe_mobile_device", "destructive"],
  ];
  for (const [name, tier] of cases) {
    assert.equal(classifyTool(name), tier, `${name} -> ${tier}`);
  }
});

test("classifyTool: overrides for this repo's actual query-execution tool names", () => {
  // These differ from upstream rijul170/sophos-central-mcp's own tool
  // names (e.g. "sophos_run_detections_query" here vs
  // "sophos_start_detections_query" there) -- verified live against this
  // repo's registered tools, not assumed from the upstream source this
  // module was ported from.
  assert.equal(classifyTool("sophos_run_xdr_query"), "read");
  assert.equal(classifyTool("sophos_run_detections_query"), "read");
  assert.equal(classifyTool("sophos_run_detection_groups_query"), "read");
  // Live Discover executes osquery on managed endpoints -- gated like RTR
  // despite the 'run' verb normally meaning a recoverable write.
  assert.equal(classifyTool("sophos_run_live_discover_query"), "destructive");
  // Cancelling your own query run is a benign control op, not the
  // destructive "cancel" the word list otherwise assumes.
  assert.equal(classifyTool("sophos_cancel_xdr_query_run"), "write");
});

test("classifyTool: fails safe on an unknown name", () => {
  assert.equal(classifyTool("sophos_mystery_operation"), "write");
});

test("isReadonlyMode accepts common truthy values", () => {
  for (const v of ["1", "true", "TRUE", "yes", "on"]) {
    assert.equal(isReadonlyMode({ SOPHOS_MCP_READONLY: v }), true, v);
  }
  assert.equal(isReadonlyMode({ SOPHOS_MCP_READONLY: "false" }), false);
  assert.equal(isReadonlyMode({}), false);
});

test("isDestructiveAllowed supports 'true' and per-tool name lists", () => {
  assert.equal(isDestructiveAllowed("sophos_delete_endpoint", {}), false);
  assert.equal(
    isDestructiveAllowed("sophos_delete_endpoint", { SOPHOS_MCP_ALLOW_DESTRUCTIVE: "true" }),
    true
  );
  assert.equal(
    isDestructiveAllowed("sophos_delete_endpoint", {
      SOPHOS_MCP_ALLOW_DESTRUCTIVE: "sophos_isolate_endpoint, sophos_delete_endpoint",
    }),
    true
  );
  assert.equal(
    isDestructiveAllowed("sophos_delete_tenant", {
      SOPHOS_MCP_ALLOW_DESTRUCTIVE: "sophos_isolate_endpoint",
    }),
    false
  );
});

test("read-only mode wins over a destructive opt-in", () => {
  const env = { SOPHOS_MCP_READONLY: "true", SOPHOS_MCP_ALLOW_DESTRUCTIVE: "true" };
  assert.equal(isToolAllowed("sophos_delete_endpoint", env), false);
  assert.equal(isToolAllowed("sophos_create_case", env), false);
  assert.equal(isToolAllowed("sophos_list_endpoints", env), true);
});

// --- applySafetyGating: exercised against this repo's real registerTool
// shape (name, { title, description, inputSchema, ... }, handler), via an
// actual McpServer and its own tools/list, not a mocked internal field --
// so this proves registration is genuinely suppressed, not just annotated.

const schema = { tenant_id: z.string() };
const handler = async () => ({ content: [] });

function withEnv(overrides, fn) {
  const keys = ["SOPHOS_MCP_READONLY", "SOPHOS_MCP_ALLOW_DESTRUCTIVE"];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  for (const k of keys) delete process.env[k];
  Object.assign(process.env, overrides);
  try {
    return fn();
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

function makeGatedServer() {
  const server = new McpServer({ name: "safety-test", version: "0.0.0" });
  applySafetyGating(server);
  server.registerTool(
    "sophos_list_widgets",
    { title: "List widgets", description: "List widgets", inputSchema: schema },
    handler
  );
  server.registerTool(
    "sophos_create_widget",
    { title: "Create a widget", description: "Create a widget", inputSchema: schema },
    handler
  );
  server.registerTool(
    "sophos_delete_widget",
    { title: "Delete a widget", description: "Delete a widget", inputSchema: schema },
    handler
  );
  return server;
}

async function listNames(server) {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "0.0.0" });
  await client.connect(clientTransport);
  const { tools } = await client.listTools();
  await client.close();
  await server.close();
  return tools.map((t) => t.name).sort();
}

function toolAnnotations(tools, name) {
  return tools.find((t) => t.name === name)?.annotations;
}

test("applySafetyGating: suppresses destructive tools by default", async () => {
  const names = await withEnv({}, () => listNames(makeGatedServer()));
  assert.deepEqual(names, ["sophos_create_widget", "sophos_list_widgets"]);
});

test("applySafetyGating: read-only mode exposes only read tools", async () => {
  const names = await withEnv({ SOPHOS_MCP_READONLY: "true" }, () => listNames(makeGatedServer()));
  assert.deepEqual(names, ["sophos_list_widgets"]);
});

test("applySafetyGating: destructive opt-in arms everything", async () => {
  const names = await withEnv({ SOPHOS_MCP_ALLOW_DESTRUCTIVE: "true" }, () => listNames(makeGatedServer()));
  assert.deepEqual(names, ["sophos_create_widget", "sophos_delete_widget", "sophos_list_widgets"]);
});

test("applySafetyGating: attaches readOnlyHint/destructiveHint annotations", async () => {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");

  await withEnv({ SOPHOS_MCP_ALLOW_DESTRUCTIVE: "true" }, async () => {
    const server = makeGatedServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "test-client", version: "0.0.0" });
    await client.connect(clientTransport);
    const { tools } = await client.listTools();

    assert.match(JSON.stringify(toolAnnotations(tools, "sophos_list_widgets")), /"readOnlyHint":true/);
    assert.match(JSON.stringify(toolAnnotations(tools, "sophos_list_widgets")), /"destructiveHint":false/);
    assert.match(JSON.stringify(toolAnnotations(tools, "sophos_delete_widget")), /"readOnlyHint":false/);
    assert.match(JSON.stringify(toolAnnotations(tools, "sophos_delete_widget")), /"destructiveHint":true/);

    await client.close();
    await server.close();
  });
});
