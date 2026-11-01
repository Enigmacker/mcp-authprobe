import type { HttpClient } from "../net/http.js";

/**
 * Dynamic Client Registration (RFC 7591) with cleanup (RFC 7592).
 *
 * Every redirect URI the scanner registers or sends lives under the reserved
 * ".invalid" top-level domain (RFC 2606), which can never resolve. Even if a
 * misconfigured server issued a redirect to one of them, nothing could ever
 * receive the code.
 */

export const SAFE_DOMAIN = "mcp-authprobe.invalid";
export const REGISTERED_REDIRECT = `https://client.${SAFE_DOMAIN}/callback`;
const CLIENT_NAME = "mcp-authprobe test client (safe to delete)";

export interface RegisteredClient {
  clientId: string;
  /** Present when the server registered a confidential client. In memory only. */
  clientSecret: string | null;
  redirectUris: string[];
  /** RFC 7592 management URI and token, used to delete the client. */
  registrationClientUri: string | null;
  registrationAccessToken: string | null;
}

export interface RegistrationOutcome {
  status: number;
  accepted: boolean;
  error: string | null;
  client: RegisteredClient | null;
}

export async function registerClient(
  http: HttpClient,
  registrationEndpoint: string,
  redirectUris: string[],
  extra: { clientName?: string; grantTypes?: string[] } = {},
): Promise<RegistrationOutcome> {
  const body = {
    client_name: extra.clientName ?? CLIENT_NAME,
    redirect_uris: redirectUris,
    grant_types: extra.grantTypes ?? ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none",
  };
  const res = await http.request({
    url: registrationEndpoint,
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
  });

  let json: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(res.body);
    if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) json = parsed as Record<string, unknown>;
  } catch {
    /* non-JSON answer */
  }
  const clientId = json["client_id"];
  const accepted = res.status >= 200 && res.status < 300 && typeof clientId === "string";
  const error = typeof json["error"] === "string" ? (json["error"] as string) : null;
  if (!accepted) return { status: res.status, accepted: false, error, client: null };

  const uris = Array.isArray(json["redirect_uris"]) ? (json["redirect_uris"] as unknown[]).filter((u): u is string => typeof u === "string") : redirectUris;
  const secret = json["client_secret"];
  const rcu = json["registration_client_uri"];
  const rat = json["registration_access_token"];
  return {
    status: res.status,
    accepted: true,
    error: null,
    client: {
      clientId: clientId as string,
      clientSecret: typeof secret === "string" && secret !== "" ? secret : null,
      redirectUris: uris,
      registrationClientUri: typeof rcu === "string" ? rcu : null,
      registrationAccessToken: typeof rat === "string" ? rat : null,
    },
  };
}

/**
 * Delete a registered client. Returns true when the server confirmed deletion.
 * The management URI must share the registration endpoint's origin: a hostile
 * server must not be able to send the scanner elsewhere.
 */
export async function deleteClient(http: HttpClient, client: RegisteredClient, registrationEndpoint: string): Promise<boolean> {
  if (!client.registrationClientUri || !client.registrationAccessToken) return false;
  try {
    if (new URL(client.registrationClientUri).origin !== new URL(registrationEndpoint).origin) return false;
    const res = await http.request({
      url: client.registrationClientUri,
      method: "DELETE",
      headers: { authorization: `Bearer ${client.registrationAccessToken}` },
    });
    return res.status === 204 || res.status === 200;
  } catch {
    return false;
  }
}
