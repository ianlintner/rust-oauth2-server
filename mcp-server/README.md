# OAuth2 Server MCP Server

Model Context Protocol (MCP) server for interacting with the Rust OAuth2 Server API. This enables AI agents like Claude to perform CRUD operations on OAuth2 clients, tokens, and users through natural language commands.

## Features

- **Client Management**: Register and manage OAuth2 clients
- **Token Operations**: Get, refresh, introspect, and revoke tokens
- **Health Monitoring**: Check server health and readiness
- **Metrics Access**: Retrieve Prometheus metrics
- **OpenID Discovery**: Access server configuration

## Installation

```bash
cd mcp-server
npm install
```

## Configuration

Create a `.env` file based on `.env.example`:

```bash
cp .env.example .env
```

Edit `.env` with your OAuth2 server details:

```env
OAUTH2_BASE_URL=http://localhost:8080
OAUTH2_CLIENT_ID=your_client_id_here
OAUTH2_CLIENT_SECRET=your_client_secret_here
```

## Usage

### Running the MCP Server

```bash
npm start
```

Or for development with auto-reload:

```bash
npm run dev
```

### Configure with Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "oauth2-server": {
      "command": "node",
      "args": [
        "/path/to/rust_oauth2_server/mcp-server/src/index.js"
      ],
      "env": {
        "OAUTH2_BASE_URL": "http://localhost:8080"
      }
    }
  }
}
```

### Configure with Other MCP Clients

The server uses stdio transport and can be integrated with any MCP-compatible client.

## Available Tools

### Client Management

#### `register_client`

Register a new OAuth2 client application.

```typescript
{
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  scope?: string;
}
```

### Token Operations

#### `get_token`

Get an access token using client credentials grant.

```typescript
{
  client_id: string;
  client_secret: string;
  scope?: string;
}
```

#### `exchange_code`

Exchange an authorization code for an access token.

```typescript
{
  code: string;
  client_id: string;
  client_secret: string;
  redirect_uri: string;
  code_verifier?: string;
}
```

#### `refresh_token`

Refresh an access token using a refresh token.

```typescript
{
  refresh_token: string;
  client_id: string;
  client_secret: string;
}
```

#### `introspect_token`

Introspect a token to get its metadata.

```typescript
{
  token: string;
  client_id: string;
  client_secret: string;
}
```

#### `revoke_token`

Revoke an access or refresh token.

```typescript
{
  token: string;
  client_id: string;
  client_secret: string;
  token_type_hint?: 'access_token' | 'refresh_token';
}
```

### Monitoring

#### `get_health`

Check the health status of the OAuth2 server.

#### `get_readiness`

Check if the OAuth2 server is ready to accept requests.

#### `get_metrics`

Get Prometheus metrics from the OAuth2 server.

#### `get_openid_config`

Get OAuth2 server OpenID Connect discovery configuration.

## Example Usage with AI

Once configured, you can ask Claude (or other AI assistants) to:

- "Register a new OAuth2 client called 'My App' with redirect URI http://localhost:3000/callback"
- "Get an access token for client ID abc123"
- "Introspect this token: eyJhbGc..."
- "Check the health status of the OAuth2 server"
- "Show me the server metrics"

## Documentation

For more information about the OAuth2 Server API:

- [API Endpoints](../docs/api/endpoints.md)
- [Authorization Code Flow](../docs/flows/authorization-code.md)
- [Client Credentials Flow](../docs/flows/client-credentials.md)
- [OAuth2 Server README](../README.md)

## Development

### Project Structure

```
mcp-server/
├── src/
│   └── index.js       # Main MCP server implementation
├── .env.example       # Environment variable template
├── package.json       # Node.js dependencies
└── README.md          # This file
```

### Adding New Tools

To add new tools, edit `src/index.js`:

1. Add tool definition in the `ListToolsRequestSchema` handler
2. Add tool implementation in the `CallToolRequestSchema` handler
3. Add corresponding method in the `OAuth2Client` class if needed

## Security Considerations

- Never commit `.env` files with real credentials
- Use HTTPS in production (`OAUTH2_BASE_URL=https://...`)
- Rotate client secrets regularly
- Limit scope permissions appropriately
- Monitor access logs for unusual activity

## Troubleshooting

### Server not connecting

- Ensure the OAuth2 server is running at the configured URL
- Check that the port is accessible
- Verify firewall settings

### Authentication errors

- Verify client credentials are correct
- Ensure the client is registered in the OAuth2 server
- Check token expiration

### Tool execution errors

- Check the OAuth2 server logs for details
- Verify request parameters are correct
- Ensure required scopes are granted

## License

This project is licensed under either of:

- MIT License
- Apache License, Version 2.0

at your option.
