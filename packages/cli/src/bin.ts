#!/usr/bin/env node
import { buildProgram } from './program.js';

/**
 * Process entry point.
 *
 * `process.exitCode` is set by the command handlers rather than calling
 * `process.exit()`: an abrupt exit can truncate a pending stdout write, and a
 * truncated JSON envelope is worse than a slow one for the agents that parse it.
 */
buildProgram()
  .parseAsync(process.argv)
  .catch((error: unknown) => {
    // Anything reaching here escaped a command's own error handling. The
    // message is printed without a stack, because a stack can embed a value
    // that was on the call frame when it was thrown.
    console.error(`agent-secrets: ${error instanceof Error ? error.message : 'unexpected error'}`);
    process.exitCode = 10;
  });
