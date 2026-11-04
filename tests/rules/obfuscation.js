// Test cases for rules/obfuscation.yml (semgrep --test). Not executable code.

function a(k) {
  // ruleid: obf-dynamic-global-access
  return globalThis[k];
}
// ok: obf-dynamic-global-access
const f = window["fetch"];

// ruleid: obf-dynamic-code-exec
eval(payload);
// ruleid: obf-dynamic-code-exec
const g = new Function("return 1");
// ruleid: obf-dynamic-code-exec
setTimeout("doIt()", 10);
// ok: obf-dynamic-code-exec
setTimeout(() => doIt(), 10);

// ruleid: obf-dynamic-require-import
const m = require(name);
// ok: obf-dynamic-require-import
const n = require("path");

const url = atob("aHR0cHM6Ly9jb2xsZWN0b3IuaW52YWxpZA==");
// ruleid: obf-decode-into-call
fetch(url);
const fn = "hctef".split("").reverse().join("");
// ruleid: obf-decode-into-call, obf-dynamic-global-access
globalThis[fn]("https://collector.invalid");

// ruleid: obf-tool-signature
var _0x3f2a1b = ["x"];
