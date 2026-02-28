/**
 * Damage Control - OpenClaw Security Extension
 * =============================================
 * 
 * Blocks dangerous commands and protects sensitive files via before_tool_call hooks.
 * 
 * Three protection layers:
 * 1. bashToolPatterns - Regex patterns to block dangerous exec commands
 * 2. zeroAccessPaths - Paths blocked for ALL operations (read/write/exec)
 * 3. readOnlyPaths - Paths that can be read but not modified
 * 4. noDeletePaths - Paths that can be read/written but not deleted
 */

import type { OpenClawPluginApi, PluginHookBeforeToolCallEvent, PluginHookBeforeToolCallResult } from "openclaw";
import { existsSync, readFileSync } from "fs";
import { dirname, join, basename } from "path";
import { homedir } from "os";
import { parse as parseYaml } from "yaml";

// =============================================================================
// TYPES
// =============================================================================

interface Pattern {
  pattern: string;
  reason: string;
}

interface Config {
  bashToolPatterns: Pattern[];
  zeroAccessPaths: string[];
  readOnlyPaths: string[];
  noDeletePaths: string[];
}

interface CheckResult {
  block: boolean;
  reason?: string;
}

// =============================================================================
// GLOB PATTERN UTILITIES
// =============================================================================

function isGlobPattern(pattern: string): boolean {
  return pattern.includes('*') || pattern.includes('?') || pattern.includes('[');
}

function globToRegex(globPattern: string): string {
  let result = "";
  for (const char of globPattern) {
    if (char === '*') {
      result += '[^\\s/]*';
    } else if (char === '?') {
      result += '[^\\s/]';
    } else if ('.+^${}()|[]\\'.includes(char)) {
      result += '\\' + char;
    } else {
      result += char;
    }
  }
  return result;
}

// =============================================================================
// PATH MATCHING
// =============================================================================

function expandPath(p: string): string {
  return p.replace(/^~/, homedir());
}

function matchPath(filePath: string, pattern: string): boolean {
  if (!filePath) return false;
  
  const normalizedFilePath = expandPath(filePath);
  const normalizedPattern = expandPath(pattern);
  
  if (isGlobPattern(pattern)) {
    // Convert glob to regex
    const regex = new RegExp(
      pattern.replace(/\./g, '\\.').replace(/\*/g, '.*'),
      'i'
    );
    return regex.test(normalizedFilePath) || regex.test(basename(filePath));
  }
  
  // Directory pattern (ends with /)
  if (normalizedPattern.endsWith('/')) {
    return normalizedFilePath.startsWith(normalizedPattern) || 
           normalizedFilePath.startsWith(normalizedPattern.slice(0, -1));
  }
  
  // Exact match or prefix match
  return normalizedFilePath === normalizedPattern || 
         normalizedFilePath.startsWith(normalizedPattern + '/') ||
         basename(normalizedFilePath) === pattern ||
         filePath === pattern;
}

// =============================================================================
// OPERATION PATTERNS FOR EXEC COMMANDS
// =============================================================================

type PatternTuple = [string, string]; // [regex pattern, operation name]

const WRITE_PATTERNS: PatternTuple[] = [
  [">\\s*{path}", "write"],
  ["\\btee\\s+(?!.*-a).*{path}", "write"],
];

const APPEND_PATTERNS: PatternTuple[] = [
  [">>\\s*{path}", "append"],
  ["\\btee\\s+-a\\s+.*{path}", "append"],
];

const EDIT_PATTERNS: PatternTuple[] = [
  ["\\bsed\\s+-i.*{path}", "edit"],
  ["\\bperl\\s+-[^\\s]*i.*{path}", "edit"],
];

const MOVE_COPY_PATTERNS: PatternTuple[] = [
  ["\\bmv\\s+.*\\s+{path}", "move"],
  ["\\bcp\\s+.*\\s+{path}", "copy"],
];

const DELETE_PATTERNS: PatternTuple[] = [
  ["\\brm\\s+.*{path}", "delete"],
  ["\\bunlink\\s+.*{path}", "delete"],
  ["\\brmdir\\s+.*{path}", "delete"],
  ["\\bshred\\s+.*{path}", "delete"],
];

const PERMISSION_PATTERNS: PatternTuple[] = [
  ["\\bchmod\\s+.*{path}", "chmod"],
  ["\\bchown\\s+.*{path}", "chown"],
];

const TRUNCATE_PATTERNS: PatternTuple[] = [
  ["\\btruncate\\s+.*{path}", "truncate"],
  [":\\s*>\\s*{path}", "truncate"],
];

// All modification patterns (for read-only paths)
const READ_ONLY_BLOCKED: PatternTuple[] = [
  ...WRITE_PATTERNS,
  ...APPEND_PATTERNS,
  ...EDIT_PATTERNS,
  ...MOVE_COPY_PATTERNS,
  ...DELETE_PATTERNS,
  ...PERMISSION_PATTERNS,
  ...TRUNCATE_PATTERNS,
];

// Delete-only patterns (for no-delete paths)
const NO_DELETE_BLOCKED: PatternTuple[] = DELETE_PATTERNS;

// =============================================================================
// COMMAND CHECKING
// =============================================================================

function checkPathInCommand(
  command: string,
  path: string,
  patterns: PatternTuple[],
  pathType: string
): CheckResult {
  const expanded = expandPath(path);
  const escapedExpanded = expanded.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedOriginal = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  if (isGlobPattern(path)) {
    const globRegex = globToRegex(path);
    for (const [patternTemplate, operation] of patterns) {
      try {
        const cmdPrefix = patternTemplate.replace("{path}", "");
        if (cmdPrefix) {
          const regex = new RegExp(cmdPrefix + globRegex, "i");
          if (regex.test(command)) {
            return {
              block: true,
              reason: `Blocked: ${operation} operation on ${pathType} ${path}`,
            };
          }
        }
      } catch {
        continue;
      }
    }
  } else {
    for (const [patternTemplate, operation] of patterns) {
      const patternExpanded = patternTemplate.replace("{path}", escapedExpanded);
      const patternOriginal = patternTemplate.replace("{path}", escapedOriginal);
      try {
        const regexExpanded = new RegExp(patternExpanded);
        const regexOriginal = new RegExp(patternOriginal);
        if (regexExpanded.test(command) || regexOriginal.test(command)) {
          return {
            block: true,
            reason: `Blocked: ${operation} operation on ${pathType} ${path}`,
          };
        }
      } catch {
        continue;
      }
    }
  }

  return { block: false };
}

function checkExecCommand(command: string, config: Config): CheckResult {
  // 1. Check against bashToolPatterns (regex match on command)
  for (const { pattern, reason } of config.bashToolPatterns) {
    try {
      if (new RegExp(pattern, 'i').test(command)) {
        return { block: true, reason: `Blocked: ${reason}` };
      }
    } catch {
      continue;
    }
  }

  // 2. Check zeroAccessPaths - block if command mentions these at all
  for (const zeroPath of config.zeroAccessPaths) {
    if (isGlobPattern(zeroPath)) {
      const globRegex = globToRegex(zeroPath);
      try {
        const regex = new RegExp(globRegex, 'i');
        if (regex.test(command)) {
          return {
            block: true,
            reason: `Blocked: zero-access pattern ${zeroPath} (no operations allowed)`,
          };
        }
      } catch {
        continue;
      }
    } else {
      const expanded = expandPath(zeroPath);
      if (command.includes(expanded) || command.includes(zeroPath)) {
        return {
          block: true,
          reason: `Blocked: zero-access path ${zeroPath} (no operations allowed)`,
        };
      }
    }
  }

  // 3. Check readOnlyPaths - block write/edit/delete operations
  for (const roPath of config.readOnlyPaths) {
    const result = checkPathInCommand(command, roPath, READ_ONLY_BLOCKED, "read-only path");
    if (result.block) {
      return result;
    }
  }

  // 4. Check noDeletePaths - block only delete operations
  for (const ndPath of config.noDeletePaths) {
    const result = checkPathInCommand(command, ndPath, NO_DELETE_BLOCKED, "no-delete path");
    if (result.block) {
      return result;
    }
  }

  return { block: false };
}

function checkFilePath(filePath: string, config: Config, operation: "read" | "write" | "edit"): CheckResult {
  // For read operations, only check zeroAccessPaths
  // For write/edit operations, also check readOnlyPaths
  
  for (const zeroPath of config.zeroAccessPaths) {
    if (matchPath(filePath, zeroPath)) {
      return { block: true, reason: `Blocked: zero-access ${zeroPath} (no operations allowed)` };
    }
  }

  if (operation === "write" || operation === "edit") {
    for (const roPath of config.readOnlyPaths) {
      if (matchPath(filePath, roPath)) {
        return { block: true, reason: `Blocked: read-only ${roPath} (cannot ${operation})` };
      }
    }
  }

  return { block: false };
}

// =============================================================================
// CONFIGURATION LOADING
// =============================================================================

function loadConfig(extensionDir: string): Config {
  const configPath = join(extensionDir, "patterns.yaml");
  
  if (!existsSync(configPath)) {
    console.warn(`[damage-control] Config not found at ${configPath}`);
    return { bashToolPatterns: [], zeroAccessPaths: [], readOnlyPaths: [], noDeletePaths: [] };
  }

  try {
    const content = readFileSync(configPath, "utf-8");
    const config = parseYaml(content) as Partial<Config>;
    return {
      bashToolPatterns: config.bashToolPatterns || [],
      zeroAccessPaths: config.zeroAccessPaths || [],
      readOnlyPaths: config.readOnlyPaths || [],
      noDeletePaths: config.noDeletePaths || [],
    };
  } catch (err) {
    console.error(`[damage-control] Failed to load config: ${err}`);
    return { bashToolPatterns: [], zeroAccessPaths: [], readOnlyPaths: [], noDeletePaths: [] };
  }
}

// =============================================================================
// PLUGIN REGISTRATION
// =============================================================================

export default function register(api: OpenClawPluginApi) {
  const extensionDir = dirname(import.meta.url.replace("file://", ""));
  const config = loadConfig(extensionDir);
  
  console.log(`[damage-control] Loaded ${config.bashToolPatterns.length} bash patterns, ${config.zeroAccessPaths.length} zero-access, ${config.readOnlyPaths.length} read-only, ${config.noDeletePaths.length} no-delete paths`);

  api.on('before_tool_call', async (event: PluginHookBeforeToolCallEvent): Promise<PluginHookBeforeToolCallResult> => {
    const { toolName, params } = event;

    // Check exec/Bash commands
    if (toolName === 'exec' || toolName === 'Bash') {
      const command = (params.command as string) || "";
      if (command) {
        const result = checkExecCommand(command, config);
        if (result.block) {
          return { block: true, blockReason: result.reason };
        }
      }
    }

    // Check file operations (read, write, edit, Read, Write, Edit)
    const normalizedTool = toolName.toLowerCase();
    if (['read', 'write', 'edit'].includes(normalizedTool)) {
      const filePath = (params.path as string) || (params.file_path as string) || "";
      if (filePath) {
        const operation = normalizedTool as "read" | "write" | "edit";
        const result = checkFilePath(filePath, config, operation);
        if (result.block) {
          return { block: true, blockReason: result.reason };
        }
      }
    }

    return {}; // Allow
  }, { priority: 100 });
}
