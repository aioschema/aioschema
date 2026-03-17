/** AIOSchema v0.5.5 — Algorithms */
import * as C from "crypto";
import { HASH_ALGORITHMS } from "./types";

export function computeHash(data: Uint8Array, alg: string): string {
  if (!HASH_ALGORITHMS.has(alg)) throw new Error(`Unsupported algorithm: ${alg}`);
  return `${alg}-${C.createHash(alg === "sha3-256" ? "sha3-256" : alg).update(data).digest("hex")}`;
}

export function parseHash(s: string, f = "hash"): [string, string] {
  const i = s.indexOf("-"); if (i<0) throw new Error(`Bad hash in ${f}`);
  const alg = s.slice(0,i), hex = s.slice(i+1);
  if (!HASH_ALGORITHMS.has(alg)) throw new Error(`Unknown alg '${alg}' in ${f}`);
  if (hex.length !== HASH_ALGORITHMS.get(alg)! || !/^[0-9a-f]+$/.test(hex)) throw new Error(`Invalid digest in ${f}`);
  return [alg, hex];
}

export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a,"utf8"), bb = Buffer.from(b,"utf8");
  if (ba.length !== bb.length) return false;
  return C.timingSafeEqual(ba, bb);
}

export function sha256Hex(d: Uint8Array): string { return C.createHash("sha256").update(d).digest("hex"); }

export function uuidV7(): string {
  // RFC 9562 UUID v7: unix_ts_ms(48) | ver(4) | rand_a(12) | var(2) | rand_b(62)
  // Layout: [8hex ts_hi]-[4hex ts_lo]-[4hex ver+rand_a]-[4hex var+rand_b_hi]-[12hex rand_b_lo]
  const ms  = BigInt(Date.now());
  const hi  = Number((ms >> 16n) & 0xFFFFFFFFn);       // ts top 32 bits -> section 1
  const lo  = Number(ms & 0xFFFFn);                     // ts bottom 16 bits
  const r   = C.randomBytes(10);                        // 10 bytes = 20 hex for sections 3-5
  const s3  = (0x7000 | (lo & 0x0FFF)).toString(16).padStart(4, "0");  // ver=7 + rand_a
  const s4  = ((0x80 | (r[0] & 0x3F)).toString(16).padStart(2,"0")) + r[1].toString(16).padStart(2,"0");
  const s5  = Array.from(r.subarray(2,8)).map((b)=>b.toString(16).padStart(2,"0")).join("");
  return `${hi.toString(16).padStart(8,"0")}-${lo.toString(16).padStart(4,"0")}-${s3}-${s4}-${s5}`;
}

export function anonymousCreatorId(): string { return `ed25519-fp-${C.randomBytes(16).toString("hex")}`; }

export function canonicalJson(o: unknown): Buffer {
  const j = (v: unknown): string => {
    if (v===null||typeof v!=="object") return JSON.stringify(v);
    if (Array.isArray(v)) return "["+v.map(j).join(",")+"]";
    const s = Object.keys(v as object).sort();
    return "{"+s.map(k=>JSON.stringify(k)+":"+j((v as Record<string,unknown>)[k])).join(",")+"}";
  };
  return Buffer.from(j(o),"utf8");
}

export function pHashV1(d: Uint8Array): string { return `pHash-v1-${sha256Hex(d.subarray(0,64)).slice(0,16)}`; }
export function pHashSimilarity(a: string, b: string): number {
  const ha=a.replace("pHash-v1-",""), hb=b.replace("pHash-v1-","");
  if (ha.length!==hb.length) return 0;
  let same=0; for(let i=0;i<ha.length;i++) if(ha[i]===hb[i]) same++;
  return same/ha.length;
}

export const SOFT_BINDING_THRESHOLD_DEFAULT = 0.95;
export const SOFT_BINDING_THRESHOLD_MAX     = 0.99;
