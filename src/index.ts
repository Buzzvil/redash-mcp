#!/usr/bin/env node

import { startStdioServer } from "./server.js";

export { createRedashMcpServer, startStdioServer } from "./server.js";

startStdioServer().catch((error) => {
  console.error(`Failed to start Redash MCP server: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
