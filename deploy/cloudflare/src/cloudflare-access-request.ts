const accessAssertionHeader = "cf-access-jwt-assertion";
const managedKeyBearer = /^bearer\s+as_key_/iu;

/**
 * When Cloudflare Access fronts the Worker it attaches a signed assertion to
 * every authenticated request. Present it as the bearer credential for
 * cookie-less callers (MCP clients, the CLI, curl) so the application's own
 * verifier can read the person. Browser requests carry cookies and keep the
 * session-and-CSRF path; Artifact Server managed keys keep precedence.
 */
export function liftCloudflareAccessAssertion(request: Request): Request {
  const assertion = request.headers.get(accessAssertionHeader);
  if (assertion === null || assertion.trim() === "") return request;
  if (request.headers.has("cookie")) return request;
  const authorization = request.headers.get("authorization");
  if (authorization !== null && managedKeyBearer.test(authorization)) {
    return request;
  }
  const headers = new Headers(request.headers);
  headers.set("authorization", `Bearer ${assertion.trim()}`);
  return new Request(request, {headers});
}
