# pa-permission-drift-detector
Compares current permission settings against a baseline or golden configuration to identify deviations or 'permission drift' over time. Useful for maintaining consistent security posture. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-drift-detector`

## Usage
`./pa-permission-drift-detector [params]`

## Parameters
- `-h`: Show help message and exit
- `--baseline`: Path to the baseline JSON configuration file.
- `--target`: Path to the target directory to analyze.
- `--exclude`: No description provided
- `--output`: No description provided
- `--strict`: Enable strict mode: exit immediately if a discrepancy is found.

## License
Copyright (c) ShadowStrikeHQ
