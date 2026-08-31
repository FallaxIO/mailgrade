// Loads the built package the way a consumer would, on whichever runtime runs
// this file. The zero-dependency claim is only worth something if the output
// actually imports outside Node.
import { gradeDomain } from "../dist/index.js";
import { analyzeHeaders } from "../dist/headers/index.js";
import { buildDmarcRecord, DEFAULT_OPTIONS } from "../dist/dmarc/index.js";
import { resolveDomain } from "../dist/doh.js";

function check(label, actual, expected) {
  if (actual !== expected) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

check(
  "gradeDomain",
  gradeDomain({
    domain: "acme.com",
    txt: ["v=spf1 -all"],
    dmarc: ["v=DMARC1; p=reject; rua=mailto:d@acme.com"],
  }).verdict,
  "protected",
);

check(
  "buildDmarcRecord",
  buildDmarcRecord({ ...DEFAULT_OPTIONS, domain: "acme.com", policy: "reject" }),
  "v=DMARC1; p=reject",
);

check("analyzeHeaders", analyzeHeaders("From: a@b.com\n").verdict, "inconclusive");
check("resolveDomain", typeof resolveDomain, "function");

console.log("smoke ok");
