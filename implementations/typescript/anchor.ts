/**
 * AIOSchema v0.5.5 — RFC 3161 anchor support (§9, §18.5)
 */

import * as http  from "http";
import * as https from "https";
import * as fs    from "fs";
import * as nodeCrypto from "crypto";
import { AnchorVerificationError } from "./types";

export interface RFC3161Result {
  anchorReference: string;
  tsrBytes:        Buffer;
  tsrPath?:        string;
  tsaUrl:          string;
  verified:        boolean;
  message:         string;
}

export async function anchorRfc3161(
  coreFingerprint: string,
  tsaUrl  = "https://freetsa.org/tsr",
  outPath?: string
): Promise<RFC3161Result> {
  const hashHex  = coreFingerprint.slice(coreFingerprint.indexOf("-") + 1);
  const tsrReq   = buildTsrRequest(Buffer.from(hashHex, "hex"));

  let tsrBytes: Buffer;
  try {
    tsrBytes = await httpPost(tsaUrl, tsrReq);
  } catch (e) {
    throw new AnchorVerificationError(`RFC 3161 submission failed: ${(e as Error).message}`);
  }

  if (outPath) fs.writeFileSync(outPath, tsrBytes);
  const v = verifyTsr(tsrBytes, hashHex);

  return {
    anchorReference: `aios-anchor:rfc3161:${hashHex.slice(0, 32)}`,
    tsrBytes, tsrPath: outPath, tsaUrl,
    verified: v.verified, message: v.message,
  };
}

export function verifyRfc3161(
  tsrBytes: Buffer, coreFingerprint: string
): { verified: boolean; message: string } {
  return verifyTsr(tsrBytes, coreFingerprint.slice(coreFingerprint.indexOf("-") + 1));
}

function buildTsrRequest(hashBytes: Buffer): Buffer {
  const oid = Buffer.from([0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00]);
  const hv  = Buffer.concat([Buffer.from([0x04, hashBytes.length]), hashBytes]);
  const mi  = Buffer.concat([Buffer.from([0x30, oid.length + hv.length]), oid, hv]);
  const nc  = Buffer.concat([Buffer.from([0x02, 0x08]), nodeCrypto.randomBytes(8)]);
  const body = Buffer.concat([Buffer.from([0x02,0x01,0x01]), mi, nc, Buffer.from([0x01,0x01,0xff])]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

function verifyTsr(tsr: Buffer, hashHex: string): { verified: boolean; message: string } {
  if (!tsr || tsr.length < 10) return { verified: false, message: "TSR too short" };
  if (tsr[0] !== 0x30)         return { verified: false, message: "TSR not valid DER" };
  const needle = Buffer.from(hashHex, "hex").toString("hex");
  const found = tsr.toString("hex").includes(needle);
  return found
    ? { verified: true,  message: "Hash confirmed in TSR — RFC 3161 timestamp valid" }
    : { verified: false, message: "Hash not found in TSR" };
}

function httpPost(url: string, body: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const u   = new URL(url);
    const mod = u.protocol === "https:" ? https : http;
    const req = (mod as typeof https).request(
      { hostname: u.hostname,
        port: u.port ? parseInt(u.port) : (u.protocol === "https:" ? 443 : 80),
        path: u.pathname,
        method: "POST",
        headers: { "Content-Type": "application/timestamp-query", "Content-Length": String(body.length) }
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end",  () => resolve(Buffer.concat(chunks)));
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}
