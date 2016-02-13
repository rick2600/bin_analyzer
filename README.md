# BinAnalyzer
Toy project for static analysis of ELF binaries

## Help
```
usage: bin_analyzer.py [-h] [-l] [-v VERBOSE] [-m [MODS]] [-x] [--no-color]
                       [-o OUT_DIR]
                       file

bin_analyzer: static analysis of ELF binaries

positional arguments:
  file                  standalone binary or directory of binaries

optional arguments:
  -h, --help            show this help message and exit
  -l, --list            list modules
  -v VERBOSE, --verbose VERBOSE
                        control verbosity (1-3)
  -m [MODS], --mods [MODS]
                        run only this list of modules (sep by comma) <default:
                        all>
  -x, --exclude         do not run this list of modules (used with -m)
  --no-color            disable coloring
  -o OUT_DIR, --out-dir OUT_DIR
                        directory to save output
```

## Modules
```
[*] Modules availables
    checksec             - analyze security mitigations
    compiler             - try to identify compiler information from the elf sections
    dangerous            - find use of dangerous functions
    finddeps             - find dependencies of a binary
    sha1sum              - compute and check SHA1 message digest
    strings              - look for interesting strings
    tagger               - try to identify the purpose of binary and tag it
    topfuncref           - list top 10 functions referenced
```

## Example
![example](samples/example00.png)
