# Changelog

## v1.0.3

- Adds post-reboot verification using `sysctl -n machdep.cpu.brand_string`.
- Documents the expected normalized output.
- Adds troubleshooting checks when the unwanted prefix remains.

## v1.0.2

- Clarifies that `<empty Data>` means the field must be left blank.
- Warns not to type the literal text `<empty Data>` into OpenCore Configurator.
- Shows the equivalent empty plist Data representation.

## v1.0.1

- Prints the complete OpenCore `Kernel -> Patch` dictionary in field order.
- Shows `Mask` and `ReplaceMask` explicitly as `<empty Data>` when empty.
- Adds a clear manual-install instruction before the dictionary.
- Updates `patch-values.txt` to use the same full dictionary format.

## v1.0.0

- Detects `_cpuid_set_info` or `_cpuid_set_generic_info` dynamically.
- Parses modern Boot Kernel Collections and standalone x86_64 kernels.
- Verifies CPUID leaves `0x80000002`, `0x80000003`, and `0x80000004`.
- Recognizes the compiled leading-space-removal loop.
- Decodes and adjusts the actual stack-relative `LEA` displacement.
- Derives the number of skipped bytes from the current CPU brand.
- Generates kernel-scoped, Darwin-version-scoped OpenCore patch values.
- Offers `/Volumes/EFI/EFI/OC/config.plist` as the interactive default.
- Detects applicable existing patches and exact duplicates.
- Makes a timestamped backup and runs `plutil -lint` before replacement.
- Includes a self-test based on the confirmed macOS `25F80` patch.
