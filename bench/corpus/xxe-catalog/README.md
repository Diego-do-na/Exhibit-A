# Case: XXE in a catalog importer (external entity reads a local file)

XML external entity (XXE) case for Exhibit A. It is proven through the
existing ``canary_read`` effect: the vulnerable app resolves an external
entity to a local file, and the proof is that the app itself opened the
planted canary, reached through the entry point from the test.

## Vulnerability

`parse_catalog` builds an `xml.sax` parser, turns on external general
entities, and installs a handler that opens the entity's system identifier
with `open`. A catalog document that declares `<!ENTITY extra SYSTEM
"…/outside/canary.txt">` makes the parse read the canary.

- **Entry point:** `App.handle_request`
- **Sink:** `CatalogHandler.resolveEntity` → `open`; `xml.sax.make_parser.parse`
- **Observed effect:** `canary_read`
- **CWE:** CWE-611 Improper Restriction of XML External Entity Reference

## Real-world analog and originality

This models the XXE class. The real public CVE is **CVE-2018-1999002**
(Jenkins, XXE in the XmlFile reader / Stapler) / the broader class of
CVE-2014-3529-style entity expansion into local files. **CVE-2018-1000164**
is another widely cited Python XML XXE analog (xml2rfc). The CVE numbers
were confirmed via public records; the app in this case is original
synthetic code, not Jenkins.

**No third-party code is vendored.** The trees are original code written
for this case during the hackathon build period.

## Trees

| Tree | Behaviour |
|---|---|
| `vulnerable/` | sax parser with external entities and a resolver that opens the system id |
| `fixed/` | `xml.etree.ElementTree.fromstring` (no entity resolution) |
| `fixed_incomplete/` | refuses system ids that contain `file:`, but a raw path still opens |

## Running it

```bash
PYTHONPATH=src ~/Desktop/Proyects/Exhibit-A/.venv/bin/python -m pytest tests/test_case_mapped_classes.py
```

The sandbox that runs untrusted tests is **isolated and resource-limited**,
never "100% safe".

## Recordings

This case has no `recordings/` yet. It is registered in
`bench/record_meta.py::CASES` and `bench/baseline.py::TARGETS`; both treat
missing recordings as unmeasured until the owner records a Meta-model run.
