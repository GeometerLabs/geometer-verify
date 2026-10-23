# Contributing

Thank you for looking. Issues are welcome: bug reports, a pack or bundle the verifier handles wrongly, unclear documentation, a schema question.

## Pull requests

Outside pull requests are read and reviewed. This repository is exported from Geometer's main source tree, so a change that is accepted may be reimplemented there rather than merged as written; the exported repository is then updated with the result. Small fixes (typos, documentation, a failing edge case with a test) are the easiest to accept. For anything larger, please open an issue first so we can say whether it fits.

## Licence

By submitting a contribution you agree that it is licensed under the Apache License, Version 2.0 (see LICENSE), and that you have the right to submit it. We do not ask for a separate contributor agreement.

## Before you submit

```
cargo fmt --check
cargo build --locked
cargo test --locked
cargo run -q -p contractgen -- --check
(cd contracts/ts && npm test)
(cd contracts/python && python3 -m unittest discover -s tests)
```

If you change `contracts/schemas/core.toml`, run `cargo run -p contractgen` and commit the regenerated files; the TypeScript and Python tests must pass with the shared vectors. See docs/contracts.md for the compatibility rules.

Security problems: do not open an issue; see SECURITY.md.
