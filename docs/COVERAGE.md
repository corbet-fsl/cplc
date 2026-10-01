# Coverage gate

CI uses cargo-llvm-cov on nightly for upstream Rust branch instrumentation.
Stable Rust remains the compiler for formatting, Clippy, native and wasm checks.
The gate requires exactly 100% of emitted production source lines and branches,
with a complete matching LLVM JSON file inventory and no absent measurements. There are no
production-code exclusions. Test harness and fixture files are excluded because
they are validation inputs rather than shipped behavior. A failed gate is an
open test gap, never evidence of complete coverage.

Dependencies are resolved once per CI run and the resulting Cargo.lock artifact
is reused by every job. CI refreshes within the declared ranges;
Dependabot proposes lockfile updates for review and merging after full CI.
The checked-in lock and per-run artifacts retain exact reproducible resolutions.

The source gate reuses the shared policy-track LCOV/JSON inventory validator.
LCOV, JSON and annotated text come from the same instrumented execution.
Every source-line location and hit/miss is cross-checked against annotated text;
JSON alone cannot prove this inventory when generic summaries differ. Every emitted production
source line and branch must execute; JSON and annotated instantiations remain
diagnostics. Source coverage does not claim each generic instantiation. No
production exclusion is configured. Private boundary vectors call actual
validation and the real crbk evaluator; they do not construct checked authority
capabilities or substitute an admitting evaluator.
