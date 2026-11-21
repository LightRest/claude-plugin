// SPDX-License-Identifier: Apache-2.0
/**
 * RFC 8785 JSON canonicalisation, ported line for line from the npm package
 * `canonicalize@3.0.0` (Apache-2.0), which the LightRest server uses for the
 * signed payload digest, the tool-call canonical form and the issuer proof.
 * Inlined because @lightrest/mcp has no dependencies. It must stay
 * byte-identical: server/mcp/jcs-parity.test.ts runs both over a corpus.
 */
export default function canonicalize(object, seen = new Set()) {
  if (typeof object === "number" && isNaN(object)) {
    throw new Error("NaN is not allowed");
  }

  if (typeof object === "number" && !isFinite(object)) {
    throw new Error("Infinity is not allowed");
  }

  if (object === null || typeof object !== "object") {
    return JSON.stringify(object);
  }

  if (typeof object.toJSON === "function") {
    if (seen.has(object)) {
      throw new Error("Circular reference detected");
    }
    seen.add(object);
    const result = canonicalize(object.toJSON(), seen);
    seen.delete(object);
    return result;
  }

  if (seen.has(object)) {
    throw new Error("Circular reference detected");
  }
  seen.add(object);

  let result;
  if (Array.isArray(object)) {
    const values = object.map((cv) => {
      const value = cv === undefined || typeof cv === "symbol" ? null : cv;
      return canonicalize(value, seen);
    });
    result = `[${values.join(",")}]`;
  } else {
    const parts = [];
    for (const key of Object.keys(object).sort()) {
      if (object[key] === undefined || typeof object[key] === "symbol") {
        continue;
      }
      parts.push(`${canonicalize(key)}:${canonicalize(object[key], seen)}`);
    }
    result = `{${parts.join(",")}}`;
  }

  seen.delete(object);
  return result;
}
