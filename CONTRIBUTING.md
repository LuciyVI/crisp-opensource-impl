# Contributing

## Scope

Contributions are welcome for protocol core, tests, build system, docs, and CI.

## Development flow

1. Create a feature branch.
2. Keep commits focused and reviewable.
3. Add or update tests for behavior changes.
4. Run local checks before opening a PR.

## Local checks

```bash
cmake -S . -B build -DCRISP_BUILD_TESTS=ON -DCRISP_BUILD_TOOLS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Optional checks:

- `-DCRISP_ENABLE_ASAN=ON`
- `-DCRISP_ENABLE_UBSAN=ON`
- `-DCRISP_ENABLE_TSAN=ON` (separate run, not combined with ASAN/UBSAN)
- `-DCRISP_ENABLE_CLANG_TIDY=ON`

## Coding rules

- C11 for C files, C++20 for C++ files.
- Keep public APIs in `crisp-core/include` backward-compatible when possible.
- Validate all external input sizes and ranges.
- Do not add cryptography implementations from scratch; use backend interface.

## Pull request checklist

- [ ] Compiles with gcc and clang.
- [ ] Tests pass.
- [ ] New functionality has tests.
- [ ] Public API/documentation updated when needed.
