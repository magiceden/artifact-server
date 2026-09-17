import {
  createRemoteJWKSet,
  errors as joseErrors,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import {Effect, Predicate, Redacted, Schema} from "effect";

import type {
  ExternalMcpBearerVerifier,
  VerifiedExternalMcpBearer,
} from "../application/authentication.js";
import {
  AuthenticationRequired,
  IdentityProviderFailure,
} from "../core/errors.js";
import type {ExternalIdentity} from "../core/installation-identity.js";

export const cloudflareAccessProviderName = "cloudflare-access";

const accessClaims = Schema.Struct({
  aud: Schema.Union([Schema.String, Schema.Array(Schema.String)]),
  common_name: Schema.optionalKey(Schema.String),
  email: Schema.optionalKey(Schema.String),
  exp: Schema.Number,
  sub: Schema.String,
});
const decodeAccessClaims = Schema.decodeUnknownEffect(accessClaims);

export interface CloudflareAccessVerifierConfig {
  /** The Access application AUD tag the JWT must be issued for. */
  readonly audience: string;
  /** Key source override for tests; defaults to the team's published certs. */
  readonly keySource?: JWTVerifyGetKey | undefined;
  /** Zero Trust team domain, for example `team.cloudflareaccess.com`. */
  readonly teamDomain: string;
}

/**
 * Verify the `Cf-Access-Jwt-Assertion` that Cloudflare Access attaches after
 * it has authenticated a request, and expose the verified person as an
 * external identity. Service-token assertions carry no person and are
 * rejected here so callers fall back to Artifact Server API keys.
 */
export class CloudflareAccessVerifier implements ExternalMcpBearerVerifier {
  readonly #audience: string;
  readonly #issuer: string;
  readonly #keys: JWTVerifyGetKey;

  constructor(config: CloudflareAccessVerifierConfig) {
    this.#audience = requireAudience(config.audience);
    this.#issuer = `https://${requireTeamDomain(config.teamDomain)}`;
    this.#keys = config.keySource ?? createRemoteJWKSet(
      new URL("/cdn-cgi/access/certs", this.#issuer),
      {
        cacheMaxAge: 10 * 60 * 1_000,
        cooldownDuration: 30 * 1_000,
        timeoutDuration: 5_000,
      },
    );
  }

  readonly verify = Effect.fn("CloudflareAccessVerifier.verify")(
    function*(this: CloudflareAccessVerifier, credential: Redacted.Redacted) {
      const payload = yield* Effect.tryPromise({
        try: async () => {
          const result = await jwtVerify(
            Redacted.value(credential),
            this.#keys,
            {
              algorithms: ["RS256"],
              audience: this.#audience,
              issuer: this.#issuer,
            },
          );
          return result.payload;
        },
        catch: (cause) => verificationFailure(cause),
      });
      return yield* validateClaims(payload, this.#audience);
    },
  );

  readonly resolveIdentity = Effect.fn(
    "CloudflareAccessVerifier.resolveIdentity",
  )(function*(
    this: CloudflareAccessVerifier,
    verified: VerifiedExternalMcpBearer,
  ) {
    if (
      verified.provider !== cloudflareAccessProviderName ||
      verified.identity === undefined
    ) {
      return yield* invalidToken(
        "The Cloudflare Access assertion does not identify a person.",
      );
    }
    return verified.identity;
  });
}

function validateClaims(
  payload: JWTPayload,
  audience: string,
): Effect.Effect<VerifiedExternalMcpBearer, AuthenticationRequired> {
  return Effect.gen(function*() {
    const claims = yield* decodeAccessClaims(payload).pipe(
      Effect.mapError(() => invalidToken(
        "The Cloudflare Access assertion is missing required claims.",
      )),
    );
    if (!hasAudience(claims.aud, audience)) {
      return yield* invalidToken(
        "The Cloudflare Access assertion is for a different application.",
      );
    }
    const email = claims.email?.trim().toLocaleLowerCase("en-US") ?? "";
    if (email === "" || claims.sub.trim() === "") {
      return yield* invalidToken(
        "Cloudflare Access service tokens do not identify a person; use an Artifact Server API key.",
      );
    }
    const identity: ExternalIdentity = {
      displayName: email,
      email,
      emailVerified: true,
      provider: cloudflareAccessProviderName,
      subject: claims.sub,
    };
    return {
      clientId: null,
      expiresAt: claims.exp,
      identity,
      provider: cloudflareAccessProviderName,
      scopes: ["mcp"],
      subject: claims.sub,
    };
  });
}

function hasAudience(
  audience: string | readonly string[],
  expected: string,
): boolean {
  return audience === expected ||
    (Array.isArray(audience) && audience.includes(expected));
}

function verificationFailure(
  cause: unknown,
): AuthenticationRequired | IdentityProviderFailure {
  if (
    cause instanceof TypeError ||
    cause instanceof joseErrors.JWKSTimeout ||
    (
      Predicate.isObject(cause) && "code" in cause &&
      cause["code"] === "ERR_JWKS_FETCH_FAILED"
    )
  ) {
    return new IdentityProviderFailure({
      message: cause instanceof joseErrors.JWKSTimeout
        ? "Cloudflare Access signing-key lookup timed out."
        : "Cloudflare Access signing keys could not be loaded.",
    });
  }
  return invalidToken(
    "The Cloudflare Access assertion is invalid or expired.",
  );
}

function invalidToken(message: string): AuthenticationRequired {
  return new AuthenticationRequired({message});
}

function requireAudience(value: string): string {
  const audience = value.trim();
  if (!/^[a-f0-9]{16,128}$/u.test(audience)) {
    throw new Error("The Cloudflare Access audience must be the application AUD tag.");
  }
  return audience;
}

function requireTeamDomain(value: string): string {
  const domain = value.trim().toLocaleLowerCase("en-US");
  if (!/^[a-z0-9-]+\.cloudflareaccess\.com$/u.test(domain)) {
    throw new Error(
      "The Cloudflare Access team domain must look like team.cloudflareaccess.com.",
    );
  }
  return domain;
}
