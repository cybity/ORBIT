import test from "node:test";
import assert from "node:assert/strict";
import { detectType, normalizeTarget, isIp, rootDomain } from "../assets/modules.js";
import { md5 } from "../assets/md5.js";
import { toJson, toMarkdown } from "../assets/report.js";

test("detects supported target types", () => {
  assert.equal(detectType("example.com"), "domain");
  assert.equal(detectType("example.com/path"), "url");
  assert.equal(detectType("https://example.com/path"), "url");
  assert.equal(detectType("1.1.1.1"), "ip");
  assert.equal(detectType("2606:4700:4700::1111"), "ip");
  assert.equal(detectType("analyst@example.com"), "email");
  assert.equal(detectType("@analyst"), "username");
  assert.equal(detectType("not a target"), "unknown");
});

test("normalizes targets and strips URL credentials", () => {
  assert.equal(normalizeTarget("example.com/path"), "https://example.com/path");
  assert.equal(normalizeTarget("https://user:pass@example.com/"), "https://example.com/");
  assert.equal(normalizeTarget("Analyst@Example.COM"), "analyst@example.com");
  assert.equal(normalizeTarget("[2606:4700:4700::1111]", "ip"), "2606:4700:4700::1111");
  assert.throws(() => normalizeTarget("ftp://example.com", "url"), /Only HTTP and HTTPS/);
});

test("handles IPs, public suffixes, and punycode", () => {
  assert.equal(isIp("192.0.2.1"), true);
  assert.equal(isIp("2606:4700:4700::1111"), true);
  assert.equal(isIp("example.com"), false);
  assert.equal(rootDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(rootDomain("a.b.example.github.io"), "example.github.io");
  assert.equal(normalizeTarget("bücher.de"), "xn--bcher-kva.de");
});

test("MD5 matches Node crypto", async () => {
  const { createHash } = await import("node:crypto");
  for (const value of ["", "test@example.com", "The quick brown fox jumps over the lazy dog"]) {
    assert.equal(md5(value), createHash("md5").update(value).digest("hex"));
  }
});

test("report exports are structured", () => {
  const report = {
    target: "example.com",
    type: "domain",
    typeLabel: "DOMAIN",
    generatedAt: "2026-10-27T00:00:00.000Z",
    durationMs: 1234,
    tool: { name: "ORBIT", version: "0.1.0", mode: "client-side" },
    meta: { rootDomain: "example.com" },
    findings: [],
    signals: [],
    errors: [],
    disclaimer: "Authorized use only.",
  };

  const markdown = toMarkdown(report);
  assert.match(markdown, /# ORBIT OSINT Report — example.com/);
  assert.match(markdown, /No attention or note-level signals/);
  assert.match(markdown, /Authorized use only\./);

  const parsed = JSON.parse(toJson(report));
  assert.equal(parsed.target, "example.com");
  assert.equal(parsed.findings.length, 0);
});
