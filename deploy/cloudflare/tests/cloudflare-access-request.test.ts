import {describe, expect, it} from "vitest";

import {liftCloudflareAccessAssertion} from "../src/cloudflare-access-request.ts";

const assertion = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature";

function request(headers: Record<string, string>): Request {
  return new Request("https://artifacts.example.com/mcp", {
    headers,
    method: "POST",
  });
}

describe("liftCloudflareAccessAssertion", () => {
  it("presents the Access assertion as the bearer for cookie-less callers", () => {
    const lifted = liftCloudflareAccessAssertion(request({
      "authorization": "Bearer access-oauth-token",
      "cf-access-jwt-assertion": assertion,
    }));
    expect(lifted.headers.get("authorization")).toBe(`Bearer ${assertion}`);
  });

  it("adds a bearer when the caller sent none", () => {
    const lifted = liftCloudflareAccessAssertion(request({
      "cf-access-jwt-assertion": assertion,
    }));
    expect(lifted.headers.get("authorization")).toBe(`Bearer ${assertion}`);
  });

  it("keeps Artifact Server managed keys ahead of the assertion", () => {
    const original = request({
      "authorization": "Bearer as_key_abc_secret",
      "cf-access-jwt-assertion": assertion,
    });
    const lifted = liftCloudflareAccessAssertion(original);
    expect(lifted.headers.get("authorization")).toBe("Bearer as_key_abc_secret");
  });

  it("never rewrites browser requests that carry cookies", () => {
    const original = request({
      "cf-access-jwt-assertion": assertion,
      "cookie": "CF_Authorization=edge-session",
    });
    const lifted = liftCloudflareAccessAssertion(original);
    expect(lifted).toBe(original);
    expect(lifted.headers.get("authorization")).toBeNull();
  });

  it("is a no-op without an assertion", () => {
    const original = request({authorization: "Bearer as_key_abc_secret"});
    expect(liftCloudflareAccessAssertion(original)).toBe(original);
  });
});
