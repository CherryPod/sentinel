# Vendored dependencies

## lit.js
- Source: `lit` 3.3.3
- Built with: `npx esbuild scripts/lit-entry.js --bundle --format=esm --minify --outfile=ui/vendor/lit.js`
- SHA-256: `f0741a86308a5eb507eee175fc316efb753f84fca1202afa11db20ccec6bb388`
- Exports: `LitElement`, `html`, `css`, `nothing`
- Rebuild only via the command above; commit the diff and update this hash.
  The committed file IS the audit unit — review the diff on every version bump.
