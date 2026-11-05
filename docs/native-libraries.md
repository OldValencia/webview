# Building the native libraries

Run **Build native libraries** from the Actions tab after committing the changes you want to build. The workflow is manual; pushing does not publish a release or start this particular workflow. Every job checks out the same selected commit, and final verification rejects a bundle containing metadata from another commit.

The combined artifact is named `spark-webview-natives`. Its layout is:

```text
natives/
  x86/windows_nt/webview.dll
  x86_64/windows_nt/webview.dll
  aarch64/windows_nt/webview.dll
  x86_64/macos/libwebview.dylib
  aarch64/macos/libwebview.dylib
  x86_64/linux/gnu/libwebview.so
  aarch64/linux/gnu/libwebview.so
metadata/<target>.json
SHA256SUMS
```

The two macOS resources contain the same universal library with both x86_64 and arm64 slices. ARM64 resources use `aarch64`; `arm` denotes 32-bit ARM and must not be used for an ARM64 DLL. When copying into Java resources, retain everything below `natives/` under the wrapper's resource prefix. Existing musl, Linux x86 and ARM32 resources are not rebuilt by this workflow and must not be represented as updated artifacts.

## Build and compatibility choices

- Windows uses the Windows 2022 runner and separate x64, Win32 and ARM64 builds. The MSVC runtime is linked statically so the wrapper does not add a Visual C++ Redistributable prerequisite. WebView2 Runtime remains required. Functional tests use disposable profiles; the official Evergreen bootstrapper installs the Runtime on the ephemeral runner if necessary.
- macOS uses the macOS 15 runner, a universal build, and an explicit macOS 11.0 deployment target. Tests and the dynamic-load check execute on the runner's native architecture, not both slices. Header validation requires both slices before staging either resource.
- GNU/Linux uses Ubuntu 24.04 x64 and ARM64 runners and explicitly selects GTK 3/WebKitGTK 4.1. These are dynamically linked system dependencies, not a bundled browser. Compatibility with older glibc/libstdc++ or arbitrary distributions is not guaranteed. There is no Alpine/musl build in this matrix.
- All outputs are Release builds. Static libraries, documentation, examples, amalgamation, general CPack packaging and formatting jobs are omitted from this binary workflow. The existing upstream workflows remain available for those checks.

Pinned OS labels avoid silently changing the distribution/SDK baseline when a `latest` alias moves; hosted images and installed package versions can still change. This workflow provides source commit identification and file checksums, not bit-for-bit reproducible builds or a guarantee of compatibility with all historical library resources.

## Checks before upload

Native C++ tests run on Windows x64/x86, macOS's host architecture and both Linux architectures (with a virtual display and a D-Bus session). Windows ARM64 is cross-compiled and structurally validated; its runtime behavior needs an ARM64 Windows machine. The shared library is also loaded with the Python standard library on executable host targets, and every expected C export plus the C API version is checked. These checks do not replace application-level tests such as Spark's draft/streaming and crash-recovery suite.

`scripts/native/package.py` verifies PE, ELF or Mach-O headers against the expected architecture before copying a binary. The final job requires all seven paths, checks each SHA-256 against its per-target manifest, rejects unexpected/missing files and writes `SHA256SUMS`. Upload steps fail if no files are found. A missing or failed matrix build therefore cannot produce an apparently complete final bundle.

The packaging helper uses only Python's standard library. Its error-path tests can run without a compiler or browser:

```sh
python -m unittest discover -s scripts/native -p 'test_*.py' -v
```

For a local native build, configure with `WEBVIEW_BUILD_TESTS=ON`, build Release, then run:

```sh
ctest --test-dir build -C Release --output-on-failure --no-tests=error
```

The Windows stability tests cover dispatch failure with a full real message queue, immediate browser-call errors after controller Close and termination from a foreign thread. The C API is unchanged. Script/navigation submission errors are not the same as asynchronous execution or network failures.

## References

- [Hosted runner platforms and labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [WebView2 Runtime detection and distribution](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution)
- [Artifact upload options and missing-file behavior](https://github.com/actions/upload-artifact/tree/v4)

## Follow-up work

Keep changes to initialization-script completion lifetime, COM ownership and cross-platform embedding separate from this release preparation. They need focused tests and can affect callback ownership or embedding behavior. Updating a binary does not repair outdated JNA declarations or unsafe DLL extraction in a consumer wrapper; Spark maintains its own adapter, while `webview_java` needs its own corresponding Java changes.
