import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

/**
 * Safety gating for tool registration.
 *
 * Ported from rijul170/sophos-central-mcp's src/safety.ts (upstream had an
 * enforced, tested gate; this repo previously only had advisory
 * readOnlyHint/destructiveHint annotations with nothing stopping a
 * disallowed tool from being exposed at all). Adapted here for this repo's
 * actual registration API: every tool in src/tools/ and src/fusion/ calls
 * server.registerTool(name, { title, description, inputSchema, ... },
 * handler) -- the config-object shape the current MCP SDK uses -- not the
 * older positional server.tool(name, description, schema, handler) that
 * upstream patches. The gate below wraps registerTool instead, merging the
 * safety annotations into that config object rather than inserting a new
 * positional argument.
 *
 * SOPHOS_MCP_READONLY=true
 *   Register only read tools. Write and destructive tools are never exposed
 *   to the AI client, regardless of what is asked.
 *
 * SOPHOS_MCP_ALLOW_DESTRUCTIVE=true | tool1,tool2,...
 *   Destructive tools (deletes, endpoint isolation, Live Discover execution,
 *   message clawback, mobile device wipe, ...) are suppressed by default
 *   even with writes enabled. Set to 'true' to arm all of them, or list
 *   specific tool names.
 */

export type ToolTier = "read" | "write" | "destructive";

const TRUTHY = new Set(["1", "true", "yes", "on", "all"]);

// Words that signal an irreversible or high-impact operation.
const DESTRUCTIVE_WORDS = new Set([
  "delete", "remove", "isolate", "deisolate", "revoke", "cancel", "release",
  "clawback", "wipe", "reset", "purge", "execute", "force", "block",
  "deauth", "strip", "expire", "deprovision", "uninstall", "reboot",
  "restart", "shutdown", "scan", "upgrade", "migrate", "lock", "unenroll",
]);

// Words that signal a state-changing (but recoverable) operation.
const WRITE_WORDS = new Set([
  "create", "update", "add", "set", "start", "request", "manage", "accept",
  "clone", "acknowledge", "reattach", "approve", "snooze", "apply", "bulk",
  "assign", "enable", "disable", "upload", "send", "move", "rename",
  "transfer", "invite", "register", "install", "trigger", "push", "import",
  "renew", "retry", "restore", "enroll", "publish", "claim", "allow",
  "configure", "locate", "sync", "take", "run",
]);

// Words that signal a pure read. Only used when no mutating word matched.
const READ_WORDS = new Set([
  "get", "list", "search", "check", "preview", "download", "whoami",
  "export", "query", "count", "lookup", "status", "summary", "health",
  "usage", "playbook", "mitre", "soc",
]);

// Tools whose names look mutating but aren't (or vice versa). Re-derived
// against this repo's actual 310 registered tool names (grepped from
// src/tools/*.ts and src/fusion/*.ts 2026-10-01), not copied blind from
// upstream's own tool names -- several differ (this repo says
// "sophos_run_detections_query" where upstream says
// "sophos_start_detections_query", for instance).
const TIER_OVERRIDES: Record<string, ToolTier> = {
  // XDR Data Lake SQL runs against cloud telemetry -- pure read analytics
  // despite the 'run' verb.
  sophos_run_xdr_query: "read",
  // Detections queries are read analytics despite the 'run' verb.
  sophos_run_detections_query: "read",
  sophos_run_detection_groups_query: "read",
  // Live Discover executes osquery ON managed endpoints -- gate like RTR.
  sophos_run_live_discover_query: "destructive",
  // Cancelling your own query run is a benign control operation, not the
  // destructive "cancel" the word list otherwise assumes.
  sophos_cancel_xdr_query_run: "write",
};

export function classifyTool(name: string): ToolTier {
  const override = TIER_OVERRIDES[name];
  if (override) return override;
  const words = new Set(name.split("_"));
  for (const w of words) if (DESTRUCTIVE_WORDS.has(w)) return "destructive";
  for (const w of words) if (WRITE_WORDS.has(w)) return "write";
  for (const w of words) if (READ_WORDS.has(w)) return "read";
  // Fail-safe: unknown names are treated as mutating so they are
  // suppressed in read-only mode rather than accidentally exposed.
  return "write";
}

export function isReadonlyMode(env: NodeJS.ProcessEnv = process.env): boolean {
  return TRUTHY.has((env.SOPHOS_MCP_READONLY ?? "").trim().toLowerCase());
}

export function isDestructiveAllowed(
  name: string,
  env: NodeJS.ProcessEnv = process.env
): boolean {
  const value = (env.SOPHOS_MCP_ALLOW_DESTRUCTIVE ?? "").trim();
  if (!value) return false;
  if (TRUTHY.has(value.toLowerCase())) return true;
  return value.split(",").map((t) => t.trim()).includes(name);
}

/** Decide whether a tool may be registered under the current policy. */
export function isToolAllowed(
  name: string,
  env: NodeJS.ProcessEnv = process.env
): boolean {
  const tier = classifyTool(name);
  if (isReadonlyMode(env) && tier !== "read") return false;
  if (tier === "destructive" && !isDestructiveAllowed(name, env)) return false;
  return true;
}

/** The shape of registerTool's second (config) argument that this gate cares about. */
interface RegisterToolConfig {
  annotations?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Patch server.registerTool so every registration passes through the safety
 * policy and carries readOnlyHint/destructiveHint/openWorldHint
 * annotations. Registrar modules in src/tools/ and src/fusion/ stay
 * untouched -- they keep calling
 * server.registerTool(name, { title, description, inputSchema, ... }, handler)
 * exactly as before; this only intercepts that one method on the server
 * instance passed in.
 *
 * A tool refused by policy is simply never registered: it does not appear
 * in tools/list at all, not just hinted as destructive. This must run
 * before any register*Tools(...) call in src/index.ts, since it works by
 * wrapping the method those calls invoke.
 */
export function applySafetyGating(server: McpServer): McpServer {
  const original = server.registerTool.bind(server);

  (server as unknown as { registerTool: (...args: unknown[]) => unknown }).registerTool = (
    ...args: unknown[]
  ) => {
    const name = args[0] as string;
    if (!isToolAllowed(name)) {
      return undefined;
    }
    const tier = classifyTool(name);
    const config = (args[1] ?? {}) as RegisterToolConfig;
    const mergedConfig: RegisterToolConfig = {
      ...config,
      annotations: {
        ...config.annotations,
        readOnlyHint: tier === "read",
        destructiveHint: tier === "destructive",
        openWorldHint: true,
      },
    };
    return (original as (...a: unknown[]) => unknown)(
      name,
      mergedConfig,
      ...args.slice(2)
    );
  };

  return server;
}
