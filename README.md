# Nmap to Excel Parser

Convert Nmap scan output into a structured Excel workbook.

This tool parses Nmap XML files and creates an `.xlsx` workbook with host inventory, open ports, service details, port matrices, scan metadata, source file hashes, and raw Nmap text. It is useful for penetration testing reports, vulnerability assessment evidence, asset inventory, and general scan review workflows.

## Features

- Parses one or more Nmap XML files from a directory
- Uses Nmap XML as the authoritative source for structured data
- Includes raw `.nmap` and `.gnmap` text for traceability
- Generates a formatted Excel workbook with frozen headers and filters
- Records source file sizes, modification times, and SHA-256 hashes
- Supports IPv4 and IPv6 address sorting
- Works with standard Nmap `-oA`, `-oX`, `.nmap`, and `.gnmap` outputs

## Workbook Sheets

The generated workbook includes:

| Sheet | Description |
| --- | --- |
| `Summary` | High-level workbook and scan totals |
| `Hosts` | One row per discovered host |
| `Open Ports` | One row per parsed port/service |
| `Port Matrix` | Host-by-port view for quick comparison |
| `Service Counts` | Unique port/service combinations and affected hosts |
| `Extra Port States` | Closed, filtered, and other aggregate port states from Nmap |
| `Scan Metadata` | Nmap command, version, scan info, and run statistics |
| `Source Files` | File inventory with hashes for traceability |
| `Raw Nmap Text` | Line-by-line `.nmap` and `.gnmap` content |

## Requirements

- Python 3.9 or newer
- `openpyxl`

Install the dependency:

```bash
python3 -m pip install openpyxl
```

## Usage

Place `nmap_parser.py` in a directory containing Nmap output files, then run:

```bash
python3 nmap_parser.py
```

By default, the script reads from the current directory and writes:

```text
parsed_nmap_results.xlsx
```

You can also specify an input directory and output file:

```bash
python3 nmap_parser.py --input-dir /path/to/nmap-results --output report.xlsx
```

If the output path is relative, it is created inside the input directory.

## Example Nmap Workflow

Run Nmap with XML output:

```bash
nmap -sV -p- -oA scan_results 192.168.1.0/24
```

This creates:

```text
scan_results.xml
scan_results.nmap
scan_results.gnmap
```

Then generate the Excel workbook:

```bash
python3 nmap_parser.py --input-dir . --output scan_results.xlsx
```

## Input Files

The script looks for these files in the input directory:

- `*.xml`: parsed as structured Nmap XML
- `*.nmap`: included in the raw text sheet
- `*.gnmap`: included in the raw text sheet
- `*.txt`: included in the source file inventory

At least one valid Nmap XML file is required.

## Notes

- The script does not run Nmap. It only parses existing scan output.
- Service and product details depend on the Nmap scan options used. For richer output, run Nmap with service detection such as `-sV`.
- The workbook may contain sensitive network information. Review it before sharing.
- Only scan networks and systems where you have authorization.

## Development

Clone the repository, install dependencies, and run the parser against a directory of sample Nmap outputs:

```bash
git clone https://github.com/your-username/nmap-parser.git
cd nmap-parser
python3 -m pip install openpyxl
python3 nmap_parser.py --input-dir samples --output sample_report.xlsx
```

## Contributing

Contributions are welcome. Useful improvements include:

- Additional workbook sheets or summaries
- Support for recursive input directories
- Automated tests with sample Nmap XML files
- Packaging for PyPI
- Better handling of NSE script output

Please open an issue or pull request with a clear description of the change.

## License

Add a license file before publishing. The MIT License is a common choice for small open-source utilities, but choose the license that matches how you want others to use and redistribute the project.
