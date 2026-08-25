# CPUID Brand Patch Generator v1.1.1

This tool generalizes the working macOS `25F80` patch. It analyzes the
currently installed **x86_64** kernel instead of using fixed addresses or fixed
stack offsets.

## What it supports

It can adapt to different Intel/AMD-compatible CPUs and different x86_64 XNU
builds when all of these conditions are true:

1. The kernel exposes `_cpuid_set_info` or `_cpuid_set_generic_info`.
2. The compiled function still contains a recognizable implementation of:
   - CPUID leaves `0x80000002` through `0x80000004`;
   - the leading-space-removal loop;
   - a stack-relative `LEA` that initializes the brand-copy pointer.
3. The desired normalized beginning, such as `Intel` or `AMD`, is already a
   substring of the hardware CPU brand.

The script **removes a prefix**. It does not invent or inject arbitrary brand
text.

It fails without generating or installing a patch when the kernel layout is
not recognized. This is intentional.

## Default interactive use

```bash
chmod +x generate-cpuid-brand-patch.py
./generate-cpuid-brand-patch.py
```

It asks:

```text
OpenCore config.plist path [/Volumes/EFI/EFI/OC/config.plist]
(press Enter for the default, or type - to skip modification):
```

After analysis it prints every field of the OpenCore patch dictionary in the
same order normally entered under `Kernel -> Patch`, including `Mask`,
`ReplaceMask`, and empty Data values. It also prints:

```text
If you want to add this patch dictionary manually, add it under Kernel -> Patch:
```

It then asks before modifying the configuration.

When a CPUID brand patch applicable to the current Darwin kernel is already
present, it prints the existing entry and exits without changing anything.

## Non-interactive examples

Generate only:

```bash
./generate-cpuid-brand-patch.py --no-config
```

Use a specific configuration and install after successful analysis:

```bash
./generate-cpuid-brand-patch.py   --config /Volumes/EFI/EFI/OC/config.plist   --yes
```

Specify where the resulting brand should begin:

```bash
./generate-cpuid-brand-patch.py --target Intel
```

When the running brand is already normalized by an existing patch but you need
to regenerate manually:

```bash
./generate-cpuid-brand-patch.py   --ignore-existing   --skip 9   --target Intel   --no-config
```

Use a different kernel collection or standalone kernel:

```bash
./generate-cpuid-brand-patch.py   --kernel-collection /path/to/kernel-or-kernel-collection
```


### Meaning of `<empty Data>`

When the generated patch output shows:

```text
Mask:        <empty Data>
ReplaceMask: <empty Data>
```

`<empty Data>` literally means that the corresponding field must be left
empty. Do not type the text `<empty Data>` into OpenCore Configurator.

In OpenCore Configurator, create the field as Data and leave its value blank.
In a plist editor, it should be represented as an empty Data value:

```xml
<data></data>
```

or equivalently:

```xml
<data/>
```


## After macOS or kernel updates

macOS updates can change the compiled `_cpuid_set_info` / `_cpuid_set_generic_info`
instruction layout. In that case an old `Kernel -> Patch` entry may remain in
`config.plist`, but it may no longer match the new kernel bytes.

After every system/kernel update, boot once and check:

```bash
sysctl -n machdep.cpu.brand_string
```

If the unwanted prefix is back, run the generator again. When the runtime brand
still has a prefix, the script will:

- print all existing CPUID brand patches found in `config.plist`;
- treat those old patches as stale or not applicable to the current boot;
- generate a new patch from the current kernel;
- print the old and new patch dictionaries;
- ask before modifying `config.plist`;
- remove the old generated CPUID brand patch entries and add the new one;
- write `config-change-log.txt` beside the generated analysis files.

Use `--keep-existing` only when you deliberately want to append the new patch
without removing old CPUID brand patches.

## revcpuname check

The script also scans:

```text
NVRAM -> Add -> revcpuname
```

If a `revcpuname` value exists and contains the same kind of unwanted prefix,
the script prints the old and normalized value and asks whether to update it.
With `--yes`, prefixed `revcpuname` values are updated automatically. Use
`--no-revcpuname` to skip this check.

## Safety behavior

Before writing `config.plist`, the script:

- checks for an applicable existing CPUID brand patch;
- checks again for an exact `Find`/`Replace` duplicate;
- creates a timestamped backup beside `config.plist`;
- writes through a temporary file;
- validates the temporary plist with `plutil -lint`;
- replaces the original only after validation succeeds.

Every generated patch is restricted to the current Darwin kernel using exact
`MinKernel` and `MaxKernel` values. Its `Find` pattern is derived from the
current kernel, and its `Base` is the detected CPUID function symbol.

Still keep a bootable fallback EFI and run the `ocvalidate` binary from the
same OpenCore release before rebooting.


## Verify after reboot

After adding the patch, validating the configuration, and rebooting through
OpenCore, verify the kernel CPU brand string with:

```bash
sysctl -n machdep.cpu.brand_string
```

The output should begin with the intended normalized CPU vendor string, for
example:

```text
Intel(R) Core(TM) i7-11700K @ 3.60GHz
```

If the unwanted prefix is still present, the patch was not applied. Recheck
that:

- the edited `config.plist` is the one used by the active OpenCore EFI;
- the patch is enabled under `Kernel -> Patch`;
- `MinKernel` and `MaxKernel` match the running Darwin kernel;
- the generated `Find` and `Replace` Data values were entered correctly.

## Generated files

A successful analysis creates a Desktop folder containing:

- `Kernel-Patch-entry.plist`
- `patch-values.txt`
- `analysis.json`

## Built-in test

The self-test includes the exact working `25F80` instruction transformation:

```text
LEA displacement -0xB1 -> -0xA8
```

Run:

```bash
./generate-cpuid-brand-patch.py --self-test
```

## Important limitation

No binary-patch generator can guarantee support for every future or historical
kernel. Apple may remove symbols, substantially rewrite the function, or use a
different CPU-information implementation. This generator deliberately refuses
to guess in those cases.
