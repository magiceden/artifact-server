import {afterEach, beforeEach, describe, expect, test} from "vitest";
import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type JWTPayload,
  type JWTVerifyGetKey,
  SignJWT,
} from "jose";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
} from "@modelcontextprotocol/server";
import {z} from "zod";

import {
  browserLoginKinds,
  privateTeamBrowserAccess,
} from "../../src/core/browser-access.js";
import {CloudflareAccessVerifier} from
  "../../src/identity/cloudflare-access-verifier.js";
import {
  createTestInstallation,
  removeTestInstallation,
  type RunningTestServer,
  startTestServer,
  type TestInstallation,
} from "../support/runtime-harness.js";

const teamDomain = "team.cloudflareaccess.com";
const audience =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const otherAudience =
  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const keyId = "access-signing-key-1";
const protocolVersion = "2026-07-28";

const sessionSchema = z.object({
  authenticationMethod: z.string(),
  principal: z.object({
    kind: z.literal("human"),
    membershipRole: z.enum(["administrator", "member"]),
  }),
});
const contextSchema = z.object({
  accessMode: z.literal("private_team"),
  login: z.object({kind: z.literal("cloudflare_access")}),
});

interface AccessAssertionPayload extends JWTPayload {
  common_name?: string;
  email?: string;
}

interface AssertionClaims {
  readonly audience?: string;
  readonly commonName?: string;
  readonly email?: string;
  readonly expiresIn?: string;
  readonly subject: string;
}

describe("Cloudflare Access identity", () => {
  let installation: TestInstallation;
  let server: RunningTestServer;
  let privateKey: Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
  let keySource: JWTVerifyGetKey;

  beforeEach(async () => {
    const pair = await generateKeyPair("RS256", {extractable: true});
    privateKey = pair.privateKey;
    const publicJwk = await exportJWK(pair.publicKey);
    keySource = createLocalJWKSet({
      keys: [{...publicJwk, alg: "RS256", kid: keyId, use: "sig"}],
    });
    installation = await createTestInstallation();
    server = await startTestServer(installation, {
      autoAdmitEmailDomains: ["example.test"],
      bootstrapAdministratorEmail: "admin@example.test",
      browserAccess: privateTeamBrowserAccess(browserLoginKinds.cloudflareAccess),
      cloudflareAccessVerifier: new CloudflareAccessVerifier({
        audience,
        keySource,
        teamDomain,
      }),
    });
  });

  afterEach(async () => {
    await server.stop();
    await removeTestInstallation(installation);
  });

  async function assertion(claims: AssertionClaims): Promise<string> {
    const payload: AccessAssertionPayload = {};
    if (claims.email !== undefined) payload.email = claims.email;
    if (claims.commonName !== undefined) payload.common_name = claims.commonName;
    return new SignJWT(payload)
      .setProtectedHeader({alg: "RS256", kid: keyId})
      .setIssuer(`https://${teamDomain}`)
      .setAudience(claims.audience ?? audience)
      .setSubject(claims.subject)
      .setIssuedAt()
      .setExpirationTime(claims.expiresIn ?? "1h")
      .sign(privateKey);
  }

  async function browserLogin(token: string | null): Promise<Response> {
    const headers = new Headers();
    if (token !== null) headers.set("Cf-Access-Jwt-Assertion", token);
    return fetch(`${server.baseUrl}/auth/login?returnTo=%2Freview`, {
      headers,
      redirect: "manual",
    });
  }

  async function sessionRole(login: Response): Promise<string> {
    const cookie = login.headers.getSetCookie()
      .map((value) => value.split(";")[0] ?? "")
      .filter((value) => value !== "")
      .join("; ");
    const session = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Cookie: cookie},
    });
    expect(session.status).toBe(200);
    return sessionSchema.parse(await session.json()).principal.membershipRole;
  }

  test("browser login trusts only a verified assertion and admits by the installation's own rules", async () => {
    const context = await fetch(`${server.baseUrl}/auth/context`);
    expect(contextSchema.parse(await context.json()).login.kind).toBe("cloudflare_access");

    expect((await browserLogin(null)).status).toBe(401);
    expect((await fetch(`${server.baseUrl}/auth/callback?code=x&state=${"y".repeat(16)}`, {
      redirect: "manual",
    })).status).toBe(404);

    const administrator = await browserLogin(await assertion({
      email: "admin@example.test",
      subject: "access-user-admin",
    }));
    expect(administrator.status).toBe(303);
    expect(administrator.headers.get("location")).toBe("/review");
    expect(await sessionRole(administrator)).toBe("administrator");

    const colleague = await browserLogin(await assertion({
      email: "Priya.Natarajan@Example.Test",
      subject: "access-user-natarajan",
    }));
    expect(colleague.status).toBe(303);
    expect(await sessionRole(colleague)).toBe("member");

    expect((await browserLogin(await assertion({
      email: "outside@elsewhere.example",
      subject: "access-user-outside",
    }))).status).toBe(403);

    expect((await browserLogin(await assertion({
      audience: otherAudience,
      email: "admin@example.test",
      subject: "access-user-admin",
    }))).status).toBe(401);

    expect((await browserLogin(await assertion({
      email: "admin@example.test",
      expiresIn: "-5m",
      subject: "access-user-admin",
    }))).status).toBe(401);

    expect((await browserLogin(await assertion({
      commonName: "service-token-client-id",
      subject: "",
    }))).status).toBe(401);
  });

  test("the same assertion authenticates the HTTP API and MCP as that person", async () => {
    const token = await assertion({
      email: "engineer@example.test",
      subject: "access-user-engineer",
    });

    const api = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Authorization: `Bearer ${token}`},
    });
    expect(api.status).toBe(200);
    const session = sessionSchema.parse(await api.json());
    expect(session.principal.membershipRole).toBe("member");

    const mcp = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({
        id: crypto.randomUUID(),
        jsonrpc: "2.0",
        method: "server/discover",
        params: {
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "artifact-server-test", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: protocolVersion,
          },
        },
      }),
      headers: {
        "Accept": "application/json, text/event-stream",
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocolVersion,
        "Mcp-Method": "server/discover",
      },
      method: "POST",
    });
    const mcpBody = await mcp.text();
    expect(mcp.status).toBe(200);
    expect(mcpBody).toContain("\"result\"");
    expect(mcpBody).toContain("no Authorization header");
    expect(mcpBody).not.toContain("using the same bearer credential");

    const capabilities = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({
        id: crypto.randomUUID(),
        jsonrpc: "2.0",
        method: "tools/call",
        params: {
          arguments: {},
          name: "artifact_capabilities",
          _meta: {
            [CLIENT_CAPABILITIES_META_KEY]: {},
            [CLIENT_INFO_META_KEY]: {name: "artifact-server-test", version: "1"},
            [PROTOCOL_VERSION_META_KEY]: protocolVersion,
          },
        },
      }),
      headers: {
        "Accept": "application/json, text/event-stream",
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocolVersion,
        "Mcp-Method": "tools/call",
        "Mcp-Name": "artifact_capabilities",
      },
      method: "POST",
    });
    expect(capabilities.status).toBe(200);
    const capabilitiesBody = z.object({
      result: z.object({
        structuredContent: z.object({
          publishing: z.object({uploadAuthentication: z.string()}),
        }),
      }),
    }).parse(await capabilities.json());
    expect(capabilitiesBody.result.structuredContent.publishing.uploadAuthentication)
      .toBe("network_edge");

    const mcpUnauthenticated = await fetch(`${server.baseUrl}/mcp`, {
      body: JSON.stringify({id: 1, jsonrpc: "2.0", method: "server/discover", params: {}}),
      headers: {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": protocolVersion,
        "Mcp-Method": "server/discover",
      },
      method: "POST",
    });
    expect(mcpUnauthenticated.status).toBe(401);

    const unauthenticated = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Authorization: `Bearer ${await assertion({
        audience: otherAudience,
        email: "engineer@example.test",
        subject: "access-user-engineer",
      })}`},
    });
    expect(unauthenticated.status).toBe(401);

    const serviceToken = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Authorization: `Bearer ${await assertion({
        commonName: "service-token-client-id",
        subject: "",
      })}`},
    });
    expect(serviceToken.status).toBe(401);

    const denied = await fetch(`${server.baseUrl}/api/v1/session`, {
      headers: {Authorization: `Bearer ${await assertion({
        email: "outside@elsewhere.example",
        subject: "access-user-outside",
      })}`},
    });
    expect(denied.status).toBe(403);
  });
});
