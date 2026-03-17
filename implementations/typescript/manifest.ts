/** AIOSchema v0.5.5 — Manifest generation */
import { SPEC_VERSION, CORE_HASH_FIELDS, Manifest, GenerateOptions, AIOSchemaError } from "./types";
import { computeHash, canonicalJson, uuidV7, anonymousCreatorId, pHashV1 } from "./algorithms";

export function generateManifest(data: Uint8Array, opts: GenerateOptions = {}): Manifest {
  const algs = opts.algorithms ?? ["sha256"];
  for (const a of algs) { try { computeHash(new Uint8Array(0),a); } catch { throw new AIOSchemaError(`Unsupported algorithm: ${a}`); } }

  const hashOriginal = algs.length===1 ? computeHash(data,algs[0]) : algs.map(a=>computeHash(data,a));
  const creatorId = opts.creatorId ?? anonymousCreatorId();
  const coreForFp: Record<string,unknown> = {
    asset_id: uuidV7(),
    schema_version: opts.schemaVersion ?? SPEC_VERSION,
    creation_timestamp: new Date().toISOString().replace(/\.\d{3}Z$/,"Z"),
    hash_original: hashOriginal,
    creator_id: creatorId,
  };
  const fpAlg = algs[0].startsWith("sha384") ? "sha384" : "sha256";
  const cfp = computeHash(canonicalJson(coreForFp), fpAlg);
  const core: Record<string,unknown> = { ...coreForFp, core_fingerprint: cfp };
  if (opts.anchorReference) core.anchor_reference = opts.anchorReference;
  if (opts.previousVersionAnchor) core.previous_version_anchor = opts.previousVersionAnchor;
  return { core: core as any, extensions: { soft_binding: pHashV1(data), ...(opts.extensions??{}) } };
}

export function manifestToJson(m: Manifest, indent=2): string { return JSON.stringify(m,null,indent); }
export function manifestFromJson(s: string): Manifest {
  const o = JSON.parse(s);
  if (!o.core) throw new AIOSchemaError("Invalid manifest: missing core");
  return { core: o.core, extensions: o.extensions??{} };
}
export function canonicalManifestBytes(m: Manifest): Buffer { return canonicalJson(m); }
