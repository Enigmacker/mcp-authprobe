/**
 * Library entry point. Everything exported here follows semantic versioning:
 * additions in minor versions, removals only in a major one. Anything
 * imported from a deeper path (mcp-authprobe/dist/...) carries no such promise.
 */
export { CATALOGUE, getCheck, LOGIN_CHECK_IDS } from "./checks/catalogue.js";
export { runAudienceCheck, jwtAudience, FOREIGN_RESOURCE } from "./checks/audience.js";
export type { AudienceCheckContext } from "./checks/audience.js";
export { runEndpointChecks, runMetadataCheck, announcedRateLimit } from "./checks/endpoint.js";
export type { EndpointCheckId, EndpointOptions, EndpointResult } from "./checks/endpoint.js";
export { makeFinding, summarize } from "./checks/finding.js";
export { runRedirectUriChecks } from "./checks/redirect-uris.js";
export type { RedirectCheckContext } from "./checks/redirect-uris.js";
export { runRefreshTokenChecks, runRefreshTokenSequence } from "./checks/refresh-tokens.js";
export type { GrantState, RefreshCheckContext, RefreshSequenceResult } from "./checks/refresh-tokens.js";
export { runThrottlingCheck } from "./checks/throttling.js";
export type { ThrottleCheckContext } from "./checks/throttling.js";
export { loadGrant, parseGrant, writeGrantFile } from "./credentials.js";
export type { LoadedGrant, Observation, TestGrant, TokenEndpointAuthMethod } from "./credentials.js";
export { discover, resourceMatches, scopesFor } from "./discovery.js";
export type { DiscoverOptions, DiscoveryResult, ProtectedResourceMetadata, AuthorizationServerMetadata } from "./discovery.js";
export { EXIT, exitCodeFor } from "./exit.js";
export type { ExitOptions } from "./exit.js";
export { beginLogin, completeLogin, login, LoginError, parseLoginState } from "./login.js";
export type { BeginLoginOptions, ClientConfig, CompleteLoginOptions, LoginOptions, LoginResult, LoginState } from "./login.js";
export { HttpClient, BlockedAddressError, InsecureTransportError, NetworkError, ScanInterruptedError } from "./net/http.js";
export type { HttpOptions } from "./net/http.js";
export { bearerCredential, detectEra, LEGACY_VERSION, MODERN_VERSION } from "./oauth/mcp-call.js";
export type { Credential, Dialect, Era, EraProbe } from "./oauth/mcp-call.js";
export { generateSecret, proofFor, verifyOwnership } from "./ownership.js";
export type { OwnershipResult } from "./ownership.js";
export { forgetSecrets, registerSecret, safeText } from "./redact.js";
export { REPORT_SCHEMA, toJson } from "./report/json.js";
export { toMarkdown } from "./report/markdown.js";
export { toSarif } from "./report/sarif.js";
export { toTable } from "./report/table.js";
export { runScan, scan, summarizeDiscovery } from "./scan.js";
export type { ScanEvent, ScanOptions, ScanResult } from "./scan.js";
export { readSecretFile, readSecretLine, SecretFileError, writeSecretFile } from "./secret-file.js";
export { parseSelection, resolveChecks, SelectionError } from "./selection.js";
export type { CheckSelector } from "./selection.js";
export { loadAccessTokenFile, loadBearerFile, StaticKeyError } from "./static-key.js";
export * from "./types.js";
export { TOOL_NAME, TOOL_VERSION } from "./version.js";
