#!/usr/bin/env node

/**
 * OAuth2 Server MCP (Model Context Protocol) Server
 * 
 * This MCP server provides tools to interact with the Rust OAuth2 Server API,
 * enabling AI agents to perform CRUD operations on clients, tokens, and users.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

// Configuration
const OAUTH2_BASE_URL = process.env.OAUTH2_BASE_URL || 'http://localhost:8080';
const OAUTH2_CLIENT_ID = process.env.OAUTH2_CLIENT_ID;
const OAUTH2_CLIENT_SECRET = process.env.OAUTH2_CLIENT_SECRET;

/**
 * OAuth2 API Client
 */
class OAuth2Client {
  constructor(baseURL) {
    this.baseURL = baseURL;
    this.axios = axios.create({
      baseURL,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  /**
   * Register a new OAuth2 client
   */
  async registerClient(data) {
    const response = await this.axios.post('/clients/register', data);
    return response.data;
  }

  /**
   * Get access token using client credentials
   */
  async getToken(clientId, clientSecret, scope = '') {
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
      scope,
    });

    const response = await this.axios.post('/oauth/token', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  /**
   * Exchange authorization code for token
   */
  async exchangeCode(code, clientId, clientSecret, redirectUri, codeVerifier = null) {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    });

    if (codeVerifier) {
      params.append('code_verifier', codeVerifier);
    }

    const response = await this.axios.post('/oauth/token', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  /**
   * Refresh an access token
   */
  async refreshToken(refreshToken, clientId, clientSecret) {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
      client_secret: clientSecret,
    });

    const response = await this.axios.post('/oauth/token', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  /**
   * Introspect a token
   */
  async introspectToken(token, clientId, clientSecret) {
    const params = new URLSearchParams({
      token,
      client_id: clientId,
      client_secret: clientSecret,
    });

    const response = await this.axios.post('/oauth/introspect', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  }

  /**
   * Revoke a token
   */
  async revokeToken(token, clientId, clientSecret, tokenTypeHint = null) {
    const params = new URLSearchParams({
      token,
      client_id: clientId,
      client_secret: clientSecret,
    });

    if (tokenTypeHint) {
      params.append('token_type_hint', tokenTypeHint);
    }

    const response = await this.axios.post('/oauth/revoke', params.toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.status === 200;
  }

  /**
   * Get server health status
   */
  async getHealth() {
    const response = await this.axios.get('/health');
    return response.data;
  }

  /**
   * Get server readiness status
   */
  async getReadiness() {
    const response = await this.axios.get('/ready');
    return response.data;
  }

  /**
   * Get server metrics
   */
  async getMetrics() {
    const response = await this.axios.get('/metrics');
    return response.data;
  }

  /**
   * Get OpenID configuration
   */
  async getOpenIDConfiguration() {
    const response = await this.axios.get('/.well-known/openid-configuration');
    return response.data;
  }
}

/**
 * MCP Server implementation
 */
class OAuth2MCPServer {
  constructor() {
    this.server = new Server(
      {
        name: 'oauth2-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.oauth2Client = new OAuth2Client(OAUTH2_BASE_URL);
    this.setupToolHandlers();
  }

  setupToolHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'register_client',
          description: 'Register a new OAuth2 client application. Creates client credentials for accessing the OAuth2 server. See docs: https://github.com/ianlintner/rust_oauth2_server/blob/main/docs/api/endpoints.md#register-client',
          inputSchema: {
            type: 'object',
            properties: {
              client_name: {
                type: 'string',
                description: 'Name of the client application',
              },
              redirect_uris: {
                type: 'array',
                items: { type: 'string' },
                description: 'Array of allowed redirect URIs',
              },
              grant_types: {
                type: 'array',
                items: { type: 'string' },
                description: 'Supported grant types (e.g., authorization_code, client_credentials, refresh_token)',
              },
              scope: {
                type: 'string',
                description: 'Space-separated list of scopes',
              },
            },
            required: ['client_name', 'redirect_uris', 'grant_types'],
          },
        },
        {
          name: 'get_token',
          description: 'Get an access token using client credentials grant. See docs: https://github.com/ianlintner/rust_oauth2_server/blob/main/docs/flows/client-credentials.md',
          inputSchema: {
            type: 'object',
            properties: {
              client_id: {
                type: 'string',
                description: 'OAuth2 client ID',
              },
              client_secret: {
                type: 'string',
                description: 'OAuth2 client secret',
              },
              scope: {
                type: 'string',
                description: 'Optional space-separated list of scopes',
              },
            },
            required: ['client_id', 'client_secret'],
          },
        },
        {
          name: 'exchange_code',
          description: 'Exchange an authorization code for an access token. Part of the authorization code flow. See docs: https://github.com/ianlintner/rust_oauth2_server/blob/main/docs/flows/authorization-code.md',
          inputSchema: {
            type: 'object',
            properties: {
              code: {
                type: 'string',
                description: 'Authorization code received from /oauth/authorize',
              },
              client_id: {
                type: 'string',
                description: 'OAuth2 client ID',
              },
              client_secret: {
                type: 'string',
                description: 'OAuth2 client secret',
              },
              redirect_uri: {
                type: 'string',
                description: 'Redirect URI used in the authorization request',
              },
              code_verifier: {
                type: 'string',
                description: 'PKCE code verifier (if PKCE was used)',
              },
            },
            required: ['code', 'client_id', 'client_secret', 'redirect_uri'],
          },
        },
        {
          name: 'refresh_token',
          description: 'Refresh an access token using a refresh token. See docs: https://github.com/ianlintner/rust_oauth2_server/blob/main/docs/flows/refresh-token.md',
          inputSchema: {
            type: 'object',
            properties: {
              refresh_token: {
                type: 'string',
                description: 'Refresh token received from previous token request',
              },
              client_id: {
                type: 'string',
                description: 'OAuth2 client ID',
              },
              client_secret: {
                type: 'string',
                description: 'OAuth2 client secret',
              },
            },
            required: ['refresh_token', 'client_id', 'client_secret'],
          },
        },
        {
          name: 'introspect_token',
          description: 'Introspect a token to get its metadata and check if it is active. See docs: https://github.com/ianlintner/rust_oauth2_server/blob/main/docs/api/endpoints.md#token-introspection',
          inputSchema: {
            type: 'object',
            properties: {
              token: {
                type: 'string',
                description: 'Token to introspect',
              },
              client_id: {
                type: 'string',
                description: 'OAuth2 client ID',
              },
              client_secret: {
                type: 'string',
                description: 'OAuth2 client secret',
              },
            },
            required: ['token', 'client_id', 'client_secret'],
          },
        },
        {
          name: 'revoke_token',
          description: 'Revoke an access or refresh token. See docs: https://github.com/ianlintner/rust_oauth2_server/blob/main/docs/api/endpoints.md#token-revocation',
          inputSchema: {
            type: 'object',
            properties: {
              token: {
                type: 'string',
                description: 'Token to revoke',
              },
              client_id: {
                type: 'string',
                description: 'OAuth2 client ID',
              },
              client_secret: {
                type: 'string',
                description: 'OAuth2 client secret',
              },
              token_type_hint: {
                type: 'string',
                description: 'Hint about token type (access_token or refresh_token)',
              },
            },
            required: ['token', 'client_id', 'client_secret'],
          },
        },
        {
          name: 'get_health',
          description: 'Check the health status of the OAuth2 server',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_readiness',
          description: 'Check if the OAuth2 server is ready to accept requests',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_metrics',
          description: 'Get Prometheus metrics from the OAuth2 server',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_openid_config',
          description: 'Get OAuth2 server OpenID Connect discovery configuration',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
      ],
    }));

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        const { name, arguments: args } = request.params;

        switch (name) {
          case 'register_client':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.registerClient(args),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'get_token':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.getToken(
                      args.client_id,
                      args.client_secret,
                      args.scope || ''
                    ),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'exchange_code':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.exchangeCode(
                      args.code,
                      args.client_id,
                      args.client_secret,
                      args.redirect_uri,
                      args.code_verifier
                    ),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'refresh_token':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.refreshToken(
                      args.refresh_token,
                      args.client_id,
                      args.client_secret
                    ),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'introspect_token':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.introspectToken(
                      args.token,
                      args.client_id,
                      args.client_secret
                    ),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'revoke_token':
            const revoked = await this.oauth2Client.revokeToken(
              args.token,
              args.client_id,
              args.client_secret,
              args.token_type_hint
            );
            return {
              content: [
                {
                  type: 'text',
                  text: revoked
                    ? 'Token revoked successfully'
                    : 'Failed to revoke token',
                },
              ],
            };

          case 'get_health':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.getHealth(),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'get_readiness':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.getReadiness(),
                    null,
                    2
                  ),
                },
              ],
            };

          case 'get_metrics':
            return {
              content: [
                {
                  type: 'text',
                  text: await this.oauth2Client.getMetrics(),
                },
              ],
            };

          case 'get_openid_config':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    await this.oauth2Client.getOpenIDConfiguration(),
                    null,
                    2
                  ),
                },
              ],
            };

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Error: ${error.message}\n${error.response?.data ? JSON.stringify(error.response.data, null, 2) : ''}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('OAuth2 MCP Server running on stdio');
  }
}

// Start the server
const server = new OAuth2MCPServer();
server.run().catch(console.error);
