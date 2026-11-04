// Splits a JavaScript file into blocks of consecutive top-level statements.
// Usage: node split.mjs <file> <max-bytes-per-block>
// Output (stdout): JSON {"blocks": [[byteStart, byteEnd], ...], "renames": [...], "neutral": [...]}
//   blocks:  byte ranges per block (end exclusive)
//   renames: byte ranges of all identifiers that Semgrep's JavaScript parser does not accept
//            as names (currently "as", e.g. `class as {}`), for renaming in the scan copy
//   neutral: byte ranges of "<!--" and "-->" in regex, string and template literals.
//            Semgrep's lexer takes them there for HTML-style comments (Annex B) and
//            skips the rest (PartialParsing, e.g. /^<!--/ in Markdown parsers)
// Exit 1 on invalid UTF-8 or if acorn can parse the file neither as a module nor as a script.
import { readFileSync } from "node:fs";
import { parse } from "acorn";

const [file, maxArg] = process.argv.slice(2);
const maxBytes = Number.parseInt(maxArg, 10);
// Decode strictly and keep the BOM: invalid UTF-8 (otherwise U+FFFD) or a removed BOM
// would shift all byte offsets relative to the original file.
const raw = readFileSync(file);
let src;
try {
  src = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(raw);
} catch {
  process.stderr.write(`${file} is not valid UTF-8\n`);
  process.exit(1);
}
// Invariant: the text must yield exactly the original bytes again, otherwise the computed
// offsets are not reliable
if (Buffer.byteLength(src, "utf8") !== raw.length) {
  process.stderr.write(`${file}: decoded text does not match the file length\n`);
  process.exit(1);
}

let ast = null, tokens = [];
for (const sourceType of ["module", "script"]) {
  tokens = [];
  try {
    ast = parse(src, { ecmaVersion: "latest", sourceType, allowHashBang: true,
                       allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true,
                       onToken: tokens });
    break;
  } catch {}
}
if (ast === null) {
  process.stderr.write(`acorn cannot parse ${file}\n`);
  process.exit(1);
}

// acorn returns UTF-16 indices, Semgrep counts bytes. The converter works incrementally
// and requires ascending positions; going backwards would shift every further result.
let lastIndex = 0, lastByte = 0;
const toByte = (index) => {
  if (index < lastIndex) throw new Error(`position ${index} before ${lastIndex}: not ascending`);
  lastByte += Buffer.byteLength(src.slice(lastIndex, index), "utf8");
  lastIndex = index;
  return lastByte;
};
const spans = ast.body.map((node) => [toByte(node.start), toByte(node.end)]);

// Collect identifiers Semgrep's parser fails on (convert sorted by position)
const PARSER_UNSAFE_NAMES = new Set(["as"]);
const unsafe = [];
const walk = (node) => {
  if (node === null || typeof node !== "object") return;
  if (Array.isArray(node)) { for (const child of node) walk(child); return; }
  if (node.type === "Identifier" && PARSER_UNSAFE_NAMES.has(node.name)) unsafe.push([node.start, node.end]);
  for (const key of Object.keys(node)) {
    if (key !== "type" && key !== "start" && key !== "end") walk(node[key]);
  }
};
walk(ast.body);
// The same identifier can appear several times in the tree (shorthand {as}: key and
// value share one node range); remove duplicate ranges, then convert in ascending order
const uniqueStarts = new Map(unsafe.map(([start, end]) => [start, end]));
const ordered = [...uniqueStarts].sort((a, b) => a[0] - b[0]);
lastIndex = 0; lastByte = 0;
const renames = ordered.map(([start, end]) => [toByte(start), toByte(end)]);

// "<!--" and "-->" in literals (not in comments, not as operators like a-->b)
const LITERAL_TOKENS = new Set(["regexp", "string", "template"]);
const markers = [];
for (const token of tokens) {
  if (!LITERAL_TOKENS.has(token.type.label)) continue;
  // One left-to-right pass without overlap: in "<!-->" only "<!--" is replaced, after that
  // the text contains no "-->" any more. Overlapping ranges could not be converted in order.
  for (const match of src.slice(token.start, token.end).matchAll(/<!--|-->/g)) {
    markers.push([token.start + match.index, token.start + match.index + match[0].length]);
  }
}
markers.sort((a, b) => a[0] - b[0]);
lastIndex = 0; lastByte = 0;
const neutral = markers.map(([start, end]) => [toByte(start), toByte(end)]);

const blocks = [];
for (const [start, end] of spans) {
  const current = blocks.at(-1);
  if (current !== undefined && end - current[0] <= maxBytes) {
    current[1] = end;
  } else {
    blocks.push([start, end]);
  }
}
process.stdout.write(JSON.stringify({ blocks, renames, neutral }));
