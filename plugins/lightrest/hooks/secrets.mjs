// SPDX-License-Identifier: Apache-2.0
/**
 * The action guard's secret check: does a tool call's input carry something
 * shaped like a credential?
 *
 * A call that waits for a person to authorise it is sent to LightRest whole,
 * and the reviewer reads it there. The proposed call is stored with the review
 * and a sealed record is kept for good, so a key that rode along would be kept
 * with it. The guard asks this first and, on a hit, sends nothing: the agent is
 * told which kind it found and removes the value (spec §4 step 1).
 *
 * Pure: no network, no file system, no process. The input is the parsed JSON of
 * a hook call, so it has no cycles. Like the rest of the guard this is a
 * seatbelt against honest mistakes, not a scanner: it knows the shapes below
 * and nothing else, and a value split across strings or encoded is not seen.
 * Design: docs/superpowers/specs/2026-10-21-action-guard-design.md §4.
 */

/**
 * The last resort: a value with no prefix of its own (`JWT_SECRET=<64 hex>`,
 * `RAILWAY_TOKEN=<uuid>`, `VC_ISSUER_ED25519_SEED=<base64>`) that only its name
 * gives away. The name holds one of these words, with `_` or `-` allowed inside
 * (`stripe-api-key`, `API_KEY`). The value is 16 or more characters of
 * `[A-Za-z0-9+/=_.-]` with a letter and a digit, so `secret_name:
 * "RESEND_API_KEY_MONITOR"` (no digit), `token_count = 12`, `password =
 * crypt(…)` and `"<your key here>"` are not one.
 *
 * Two kinds of name are not secrets although they hold the word. One that ends
 * in Id, Hash, Ref, Name, Type, Count or At (`"credentialId" = 'HOC-…'`,
 * `"tokenHash"`, `secret_id`) names a row, a digest or a label, not a secret.
 * And after a plain colon, a value made of capitalised words and followed by
 * `[ < = ; , ) } | &` or the end of a line is a type annotation
 * (`privateKey: Ed25519PrivateKeyHandle = …`), not a value.
 */
const SECRET_WORD =
  /SECRET|TOKEN|API[_-]?KEY|PASSWORD|PASSWD|PRIVATE[_-]?KEY|SIGNING[_-]?KEY|CREDENTIAL|SEED/i;
const VALUE_CHARS = "[A-Za-z0-9+/=_.-]";
const MIXED_VALUE = `(?=${VALUE_CHARS}*[A-Za-z])(?=${VALUE_CHARS}*[0-9])${VALUE_CHARS}{16,}`;
const NAMED = "value named as a secret";
/** In a string: the word and the rest of the name, `=` `:` `=>` or `:=` (quotes and spaces allowed), the value. */
const NAMED_SCAN = new RegExp(
  `(${SECRET_WORD.source})([A-Za-z0-9_-]{0,40})["']?\\s*(:=|=>|[=:])\\s*["']?(${MIXED_VALUE})`,
  "gi"
);
/** As an object entry: a key that holds the word, and a value that is all of it. */
const NAMED_ENTRY_VALUE = new RegExp(`^${MIXED_VALUE}$`);
/** `_id` and the like, in any case; and `Id`, `ID` and the like after a lower-case letter or digit (so `ANDROID` is not one). */
const SNAKE_SUFFIX = /[_-](?:id|hash|ref|name|type|count|at)$/;
const CAMEL_SUFFIX =
  /(?<=[a-z0-9])(?:Id|ID|Hash|HASH|Ref|REF|Name|NAME|Type|TYPE|Count|COUNT|At|AT)$/;
/** Capitalised words, acronyms and digits, and nothing else: `Ed25519PrivateKeyHandle`. A random token breaks it at its first lower-case letter after a digit. */
const TYPE_NAME = /^(?:[A-Z][a-z]+|[A-Z]|\d)+$/;
const TYPE_ENDS = /^[ \t]*(?:[[<=;,)}|&]|\r?\n|$)/;

/** Does this name end in Id, Hash, Ref, Name, Type, Count or At? */
function isIdentifierName(name) {
  return SNAKE_SUFFIX.test(name.toLowerCase()) || CAMEL_SUFFIX.test(name);
}

/** The rule for a string, with the two exceptions above: it has `.test` like a pattern. */
const namedValue = {
  test(text) {
    for (const m of text.matchAll(NAMED_SCAN)) {
      const [whole, word, tail, separator, value] = m;
      if (isIdentifierName(word + tail)) continue;
      if (
        separator === ":" &&
        TYPE_NAME.test(value) &&
        TYPE_ENDS.test(text.slice(m.index + whole.length))
      )
        continue;
      return true;
    }
    return false;
  },
};

/**
 * One entry per kind: the name the agent is shown ("This call carries a secret
 * (<kind>)"), and the pattern that finds it anywhere inside a string. The order
 * is the order they are tried in, so a string that fits two kinds is reported
 * as the first (`Bearer lr_agt_…` is an agent key; a GitHub token inside a URL
 * is a GitHub token). No pattern is anchored: a secret is still a secret in
 * `key=sk_live_…;`.
 *
 * The first eight kinds are the spec's list; the rest are the credentials this
 * stack's own guarded calls carry. Bodies have a minimum length so a
 * placeholder (`sk_test_placeholder`) or a prefix the app shows on screen
 * (`lr_agt_` and 7 characters) is not a key. Stripe's oldest keys have 24
 * characters after the prefix; LightRest's agent keys have 48. A short prefix
 * that also starts ordinary identifiers (`re_`, `lr_`, `npm_`) must not follow
 * a letter or digit. The last kind, a value named as a secret, only catches
 * what no other kind did.
 */
const RULES = [
  ["Stripe secret key", /sk_(?:live|test)_[A-Za-z0-9]{24,}/],
  ["Stripe restricted key", /rk_(?:live|test)_[A-Za-z0-9]{24,}/],
  // Svix and Resend sign webhooks with whsec_ and base64, so + / = count.
  ["Stripe webhook secret", /whsec_[A-Za-z0-9+/=]{24,}/],
  ["LightRest agent key", /lr_agt_[A-Za-z0-9]{32,}/],
  // After the word Bearer, skipping the whitespace, quotes and `||` that SQL
  // puts between them, comes a token that is either 20 letters (`-` and `_`
  // allowed, but then in both cases, so a lower-case SQL variable such as
  // `v_service_role_key_for_the_call` is not one) or has a digit or a dot
  // inside it: "uses Bearer authentication." in prose is neither, `<token>` and
  // `$TOKEN` are not token characters at all, and a name followed by `(` is a
  // function call. `'Bearer ' || v_key` is too short to count and
  // `BearerTokenV2Provider` has no break after the word. No `i` flag, because
  // it would make `[A-Z]` match a lower-case letter.
  [
    "bearer token",
    /\b(?:[Bb]earer|BEARER)(?=[\s'"])[\s'"|]*(?![A-Za-z0-9._~+/=-]*\()(?=[A-Za-z0-9_~+/=-]*(?:[0-9]|\.[A-Za-z0-9_~+/=-])|[A-Za-z]{20,}|(?=[A-Za-z_-]*[A-Z])(?=[A-Za-z_-]*[a-z])[A-Za-z_-]{20,})[A-Za-z0-9._~+/=-]{8,}/,
  ],
  // The header line alone is enough: RSA, EC, OPENSSH, ENCRYPTED, PGP's
  // "PRIVATE KEY BLOCK", and SSH2's four dashes and digit (RFC 4716), plus a
  // PuTTY key file and a JWK that carries its private `d` member. A public key
  // or a certificate is not private.
  [
    "private key",
    /-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}|PuTTY-User-Key-File-\d|^(?=[\s\S]*"kty")[\s\S]*"d"\s*:\s*"[A-Za-z0-9_-]{20,}"/,
  ],
  // Three base64url segments, the first a JSON header (`{"` is `eyJ`).
  ["JWT", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  // A user, a colon and at least one character of password before the `@`
  // (a raw `/` may be in it), or a `password=` parameter in the query.
  // `postgres://host:5432/db` has no `@` before its `?`, so it is not one, and
  // a placeholder parameter (`[YOUR-PASSWORD]`, `<password>`) is not either.
  [
    "database URL with a password",
    /postgres(?:ql)?:\/\/(?:[^\s:@/]*:[^\s@?#]+@|\S*[?&]password=[^\s&#<[{$])/i,
  ],
  ["GitHub token", /gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,}/],
  // Either re_<id>_<secret>, or a plain token with a digit in it, so that
  // `re_enrollment_requested_at` is a column name and not a key.
  [
    "Resend API key",
    /(?<![A-Za-z0-9])re_(?:[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}|(?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{20,})/,
  ],
  ["Supabase secret key", /sb_secret_[A-Za-z0-9_-]{20,}|sbp_[0-9a-f]{40}/],
  ["Anthropic API key", /sk-ant-[A-Za-z0-9_-]{20,}/],
  ["npm token", /(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36,}/],
  // The key a person makes at /app/settings: lr_ and 32 hex characters.
  ["LightRest API key", /(?<![A-Za-z0-9])lr_[0-9a-f]{32}/],
  // Base64 of `user:password`. "Basic functionality" is not one: the run must
  // have a digit, + / =, or a lower-case letter before an upper-case one.
  [
    "basic auth credentials",
    /\b[Bb]asic\s+(?=[A-Za-z0-9+/]*(?:[0-9+/=]|[a-z][A-Z]))[A-Za-z0-9+/]{12,}/,
  ],
  // The password in any URL's user information: redis://, amqp://, https://.
  // A database URL is caught above, a token inside it earlier still.
  [
    "URL with a password",
    /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s:@/]*:[^\s@/?#]+@/i,
  ],
  // PASSWORD 'x' in a role or user mapping, a quoted password in a comparison,
  // and password=x in a connection string (PGPASSWORD=x too). A column, a hash
  // column, a parameter ($1, :name), a function call and a placeholder
  // ([YOUR-PASSWORD], <password>) are not one: a bare value must follow
  // `password=` with no space, and may not begin with any of those marks.
  [
    "database password",
    /password\s+'[^'\s<[{$:%?@][^'\s]{3,}'|password\s*=\s*'[^'\s<[{$:%?@][^']{3,}'|password=[^\s'"&;$)<[{:%?@][^\s'"&;$)]{5,}/i,
  ],
  [NAMED, namedValue],
];

/** The kind of the first rule that fits this string, or null. */
function kindOf(text) {
  for (const [kind, pattern] of RULES) {
    if (pattern.test(text)) return kind;
  }
  return null;
}

/** Is this object a JWK with its private `d` member (`{kty, ..., d}`)? */
function isPrivateJwk(item) {
  return (
    typeof item.kty === "string" &&
    typeof item.d === "string" &&
    /^[A-Za-z0-9_-]{20,}$/.test(item.d)
  );
}

/**
 * The kind of the first secret-shaped string in a value, or null. Walks
 * strings in any nested object or array, an object's keys included (a key can
 * be a secret as easily as a value), in document order: a key before its
 * value, siblings left to right. An object that is a private JWK counts as a
 * private key before its members are read. Anything that is not a string, an
 * array or an object is skipped.
 *
 * A value named as a secret is the last resort: strings and object entries
 * that fit it are noted, and it is reported only if no string anywhere in the
 * value fits a more specific kind. (An object entry is a key that names a
 * secret beside a string value: the walk reads keys and values apart, so the
 * string rule cannot see the pair.)
 *
 * @param {unknown} value
 * @returns {string | null}
 */
export function findSecret(value) {
  let named = null;
  // Last in, first out: children go on in reverse so they come off in order.
  const pending = [value];
  while (pending.length > 0) {
    const item = pending.pop();
    if (typeof item === "string") {
      const kind = kindOf(item);
      if (kind === NAMED) named = NAMED;
      else if (kind !== null) return kind;
    } else if (item !== null && typeof item === "object") {
      if (!Array.isArray(item)) {
        if (isPrivateJwk(item)) return "private key";
        for (const [key, entry] of Object.entries(item)) {
          if (
            typeof entry === "string" &&
            SECRET_WORD.test(key) &&
            !isIdentifierName(key) &&
            NAMED_ENTRY_VALUE.test(entry)
          )
            named = NAMED;
        }
      }
      const children = Array.isArray(item) ? item : Object.entries(item).flat();
      for (let i = children.length - 1; i >= 0; i--) pending.push(children[i]);
    }
  }
  return named;
}
