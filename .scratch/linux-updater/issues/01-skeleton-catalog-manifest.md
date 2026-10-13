# 01 — Project skeleton, catalog, manifest client

Status: done

Build the offline-testable core: package layout, PID catalog, manifest
fetch/parse.

- Python package `schuberth_dfu` + console script `schuberth-dfu`.
- `catalog.py`: load `docs/analysis/pid-catalog.csv` (vendor it into the
  package), expose `product_for_pid(pid)`.
- `manifest.py`: fetch `Firmware`/`Revisions` from
  `https://firmware.sena.com/senabluetoothmanager/`, parse
  `PRODUCT:version[:Lang]:file` + `PRODUCT:<n>` trailer lines, expose
  `latest(product) -> (version, filename)`.
- CLI subcommands `detect` (stub) and `check <product>`.
- Unit tests against a fixture copy of the live manifest.

## Comments

- 2026-10-13: implemented in `schuberth_dfu/` (catalog.py, manifest.py, cli.py).
  189-entry catalog incl. derived SC2V2=0x3217. Verified live: `check SC2` →
  v1.5 / SC2-v1.5-build0.img. Tests: tests/test_catalog.py, tests/test_manifest.py.
