/** AIOSchema v0.5.5 — Types */

export const SPEC_VERSION = "0.5.5";

export const SUPPORTED_VERSIONS: ReadonlySet<string> = new Set([
  "0.1","0.2","0.3","0.3.1","0.4","0.5","0.5.1","0.5.5"
]);

export const HASH_ALGORITHMS: ReadonlyMap<string, number> = new Map([
  ["sha256",64],["sha3-256",64],["sha384",96]
]);

export const HASH_REGEX = /^(sha256|sha3-256)-[0-9a-f]{64}$|^sha384-[0-9a-f]{96}$/;

export const CORE_HASH_FIELDS = [
  "asset_id","schema_version","creation_timestamp","hash_original","creator_id"
] as const;

export type MatchType = "exact" | "soft" | "none";

export interface CoreBlock {
  asset_id:             string;
  schema_version:       string;
  creation_timestamp:   string;
  hash_original:        string | string[];
  creator_id:           string;
  core_fingerprint:     string;
  signature?:           string;
  manifest_signature?:  string;
  anchor_reference?:    string;
  previous_version_anchor?: string;
  hash_schema_block?:   string;
}

export interface Manifest {
  core:       CoreBlock;
  extensions: Record<string, unknown>;
}

export interface AnchorRecord {
  asset_id:         string;
  core_fingerprint: string;
  timestamp:        string;
  [key: string]:    unknown;
}

export type AnchorResolver = (ref: string) => Promise<AnchorRecord | null>;

export interface VerificationResult {
  success:                  boolean;
  message:                  string;
  matchType:                MatchType;
  signatureVerified:        boolean;
  manifestSignatureVerified: boolean;
  anchorVerified:           boolean;
  warnings:                 string[];
}

export class AIOSchemaError extends Error {
  constructor(m: string) { super(m); this.name = "AIOSchemaError"; }
}
export class AnchorVerificationError extends AIOSchemaError {
  constructor(m: string) { super(m); this.name = "AnchorVerificationError"; }
}
export class ManifestValidationError extends AIOSchemaError {
  constructor(m: string) { super(m); this.name = "ManifestValidationError"; }
}

export interface GenerateOptions {
  schemaVersion?:         string;
  creatorId?:             string;
  algorithms?:            string[];
  anchorReference?:       string;
  previousVersionAnchor?: string;
  extensions?:            Record<string, unknown>;
  privateKey?:            Uint8Array;
}

export interface VerifyOptions {
  verifyAnchor?:    boolean;
  anchorResolver?:  AnchorResolver;
  publicKey?:       Uint8Array;
  softThreshold?:   number;
}
