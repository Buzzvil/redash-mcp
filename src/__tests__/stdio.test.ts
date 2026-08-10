import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

jest.setTimeout(30_000);

function childEnvironment(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) env[key] = value;
  }

  delete env.MCP_TRANSPORT;
  env.NODE_NO_WARNINGS = '1';
  env.REDASH_URL = 'https://redash.example.com';
  env.REDASH_OIDC_ISSUER = 'https://idp.example.com';
  env.REDASH_OIDC_CLIENT_ID = 'redash-api';
  return env;
}

async function listTools(args: string[]): Promise<string[]> {
  const client = new Client({ name: 'stdio-regression-test', version: '1.0.0' });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ['--loader', 'ts-node/esm', 'src/cli.ts', ...args],
    env: childEnvironment(),
  });

  try {
    await client.connect(transport);
    const result = await client.listTools();
    return result.tools.map((tool) => tool.name);
  } finally {
    await client.close();
  }
}

describe.each([
  ['default invocation', []],
  ['serve subcommand', ['serve']],
] as const)('stdio compatibility: %s', (_label, args) => {
  it('initializes over stdio without contaminating protocol stdout', async () => {
    const tools = await listTools([...args]);

    expect(tools).toContain('list_queries');
    expect(tools).toContain('get_dashboard');
    expect(tools.length).toBeGreaterThan(10);
  });
});
