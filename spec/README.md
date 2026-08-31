# Conformance corpus

Every file here is a language-neutral contract for the rules in this library.
A case is an input and a projection of the result: stable ids, statuses and
verdicts, and no English. The prose the library produces is a convenience and
is deliberately not asserted, so it can be reworded or translated without
breaking a port.

This exists so a port to another language is a weekend rather than a rewrite.
`FallaxIO/mailgrade` is the TypeScript implementation; a port reads these same
files, writes one adapter that maps a `target` to its own function, and is
finished when all of them pass.

## Shape

```json
{
  "cases": [
    {
      "target": "analyzeSpf",
      "name": "passes -all",
      "input": { "txt": ["v=spf1 include:_spf.google.com -all"] },
      "expect": { "id": "spf-hardfail", "status": "pass", "allQualifier": "-" }
    }
  ]
}
```

- `target` names the function under test. The adapter maps it to a projection.
- `input` is the argument set, by name.
- `expect` is a partial match. Only the keys present are asserted, so a
  projection may return more than a case pins.

## Rules

- Assert on ids, never on sentences.
- Where `input` carries `options`, it is a partial set of DMARC options merged
  over the defaults (`p=none`, relaxed alignment, `pct=100`, `ri=86400`,
  `fo=0`, subdomains inheriting).
- `expect.hasNote` asks whether one id is present rather than pinning the whole
  list, for cases where the rest is incidental.
- `spf-eval.json` cases carry a `zone`: a map from DNS name to its records
  (`TXT`, `A`, `AAAA`, `MX`, `PTR`), with the string `"TEMPERROR"` standing
  for a lookup that fails. A port evaluates against that zone and never
  touches real DNS.

## Files

| File | Covers |
| --- | --- |
| `domain.json` | registrable domains, relaxed alignment, input coercion |
| `spf.json` | SPF grading |
| `dkim.json` | DKIM key detection and grading |
| `dmarc-lookup.json` | grading a published DMARC record |
| `dmarc-record.json` | building, parsing, reviewing and rolling out a record |
| `grade.json` | the whole-domain verdict and its recommendations |
| `spf-eval.json` | RFC 7208 evaluation: mechanisms, macros, limits, exp= |
| `headers.json` | header parsing, authentication results, impersonation |

The reference adapter is `test/spec.test.ts`, about 120 lines.
