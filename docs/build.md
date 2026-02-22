# Build guide

## Requirements

- CMake 3.20+
- C compiler with C11 support
- C++ compiler with C++20 support
- Git (for fetching Catch2 when tests are enabled)

## Configure

```bash
cmake -S . -B build \
  -DCRISP_BUILD_TESTS=ON \
  -DCRISP_BUILD_TOOLS=ON \
  -DCRISP_WERROR=ON
```

## Build

```bash
cmake --build build --parallel
```

## Run tests

```bash
ctest --test-dir build --output-on-failure
```

## Sanitizers

Enable one of these modes at configure time:

- AddressSanitizer: `-DCRISP_ENABLE_ASAN=ON`
- UndefinedBehaviorSanitizer: `-DCRISP_ENABLE_UBSAN=ON`
- ThreadSanitizer: `-DCRISP_ENABLE_TSAN=ON`

`CRISP_ENABLE_TSAN` is intentionally incompatible with ASAN/UBSAN in this setup.

## clang-tidy (optional)

```bash
cmake -S . -B build -DCRISP_ENABLE_CLANG_TIDY=ON
```
