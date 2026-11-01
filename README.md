# pa-permission-drift-detector
Compares current permission settings against a baseline or golden configuration to identify deviations or 'permission drift' over time. Useful for maintaining consistent security posture. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-drift-detector`

## Usage
`python3 main.py --baseline [path] --target [directory] [params]`

## Parameters
- `-h`: Show help message and exit
- `--baseline`: Path to the baseline JSON configuration file. The baseline maps each relative file path to its expected permissions as an octal string, for example "644".
- `--target`: Path to the target directory to analyze.
- `--exclude`: Path to a file containing exclusion patterns (e.g., .gitignore style), one pattern per line.
- `--output`: Path to the output file to save the report (JSON format).

## Behavior notes
- Any discrepancy exits 1, including a file whose permissions differ from the baseline, a file present in the target but absent from the baseline, and a baseline entry whose file no longer exists in the target. A deleted file is drift: it is reported with actual permissions "missing". An empty target directory against a non empty baseline therefore reports drift for every baseline entry and exits 1, never a clean result.
- Earlier versions accepted a `--strict` flag. It changed nothing except one log line, because every discrepancy already exits 1, so the flag has been removed.
- The `--output` path may not be the baseline file or the exclusion file: when the resolved output path equals either input, the run refuses and exits 1 before writing anything.

## License
Copyright (c) ShadowStrikeHQ
