#!/usr/bin/env python3
"""
Parse Nmap output files into an Excel workbook.

The script uses Nmap XML as the authoritative source, then also records source
file hashes and raw .nmap/.gnmap text for traceability.

Usage:
    python3 parse_nmap_to_excel.py
    python3 parse_nmap_to_excel.py --input-dir /path/to/scans --output results.xlsx
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
except ImportError as exc:
    raise SystemExit("Missing dependency: install openpyxl with `python3 -m pip install openpyxl`.") from exc


def epoch_to_local(value: str | None) -> str:
    if not value:
        return ""
    try:
        return datetime.fromtimestamp(int(value)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return ""


def ip_sort_key(ip: str) -> tuple[int, Any]:
    try:
        parsed = ipaddress.ip_address(ip)
        return parsed.version, int(parsed)
    except ValueError:
        return 99, ip


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def service_summary(service: ET.Element | None) -> str:
    if service is None:
        return ""
    parts = [
        service.attrib.get("product", ""),
        service.attrib.get("version", ""),
        service.attrib.get("extrainfo", ""),
    ]
    return " ".join(part for part in parts if part).strip()


def script_output(parent: ET.Element | None) -> str:
    if parent is None:
        return ""
    scripts = []
    for script in parent.findall("script"):
        script_id = script.attrib.get("id", "")
        output = script.attrib.get("output", "")
        if script_id or output:
            scripts.append(f"{script_id}: {output}".strip(": "))
    return "\n".join(scripts)


def find_nmap_xml_files(input_dir: Path) -> list[Path]:
    xml_files = []
    for path in sorted(input_dir.glob("*.xml")):
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError:
            continue
        if root.tag == "nmaprun":
            xml_files.append(path)
    return xml_files


def parse_xml_files(xml_files: list[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    hosts: list[dict[str, Any]] = []
    ports: list[dict[str, Any]] = []
    scan_rows: list[dict[str, Any]] = []
    extra_rows: list[dict[str, Any]] = []

    for xml_file in xml_files:
        root = ET.parse(xml_file).getroot()

        scan_rows.append(
            {
                "Source File": xml_file.name,
                "Nmap Version": root.attrib.get("version", ""),
                "Scanner": root.attrib.get("scanner", ""),
                "Command": root.attrib.get("args", ""),
                "Started": root.attrib.get("startstr", "") or epoch_to_local(root.attrib.get("start")),
                "XML Output Version": root.attrib.get("xmloutputversion", ""),
            }
        )

        runstats = root.find("runstats")
        if runstats is not None:
            finished = runstats.find("finished")
            host_stats = runstats.find("hosts")
            scan_rows.append(
                {
                    "Source File": xml_file.name,
                    "Nmap Version": "",
                    "Scanner": "runstats",
                    "Command": finished.attrib.get("summary", "") if finished is not None else "",
                    "Started": finished.attrib.get("timestr", "") if finished is not None else "",
                    "XML Output Version": (
                        f"up={host_stats.attrib.get('up', '')}; "
                        f"down={host_stats.attrib.get('down', '')}; "
                        f"total={host_stats.attrib.get('total', '')}"
                    )
                    if host_stats is not None
                    else "",
                }
            )

        for scaninfo in root.findall("scaninfo"):
            scan_rows.append(
                {
                    "Source File": xml_file.name,
                    "Nmap Version": "",
                    "Scanner": "scaninfo",
                    "Command": (
                        f"type={scaninfo.attrib.get('type', '')}; "
                        f"protocol={scaninfo.attrib.get('protocol', '')}; "
                        f"numservices={scaninfo.attrib.get('numservices', '')}; "
                        f"services={scaninfo.attrib.get('services', '')}"
                    ),
                    "Started": "",
                    "XML Output Version": "",
                }
            )

        for host in root.findall("host"):
            status = host.find("status")
            addresses = {addr.attrib.get("addrtype", ""): addr.attrib for addr in host.findall("address")}
            ip = addresses.get("ipv4", {}).get("addr", "") or addresses.get("ipv6", {}).get("addr", "")
            mac = addresses.get("mac", {}).get("addr", "")
            vendor = addresses.get("mac", {}).get("vendor", "")
            hostnames = [
                hostname.attrib.get("name", "")
                for hostname in host.findall("./hostnames/hostname")
                if hostname.attrib.get("name")
            ]
            times = host.find("times")
            host_ports = []
            service_names = []

            for extraports in host.findall("./ports/extraports"):
                extra_rows.append(
                    {
                        "Source File": xml_file.name,
                        "IP Address": ip,
                        "State": extraports.attrib.get("state", ""),
                        "Count": extraports.attrib.get("count", ""),
                        "Reasons": "; ".join(
                            f"{reason.attrib.get('reason', '')} ({reason.attrib.get('count', '')})"
                            for reason in extraports.findall("extrareasons")
                        ),
                        "Port Ranges": "; ".join(
                            reason.attrib.get("ports", "")
                            for reason in extraports.findall("extrareasons")
                            if reason.attrib.get("ports")
                        ),
                    }
                )

            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                portid = port.attrib.get("portid", "")
                proto = port.attrib.get("protocol", "")
                state_name = state.attrib.get("state", "") if state is not None else ""
                service_name = service.attrib.get("name", "") if service is not None else ""
                product_version = service_summary(service)
                cpes = [cpe.text or "" for cpe in service.findall("cpe")] if service is not None else []

                service_names.append(service_name or "unknown")
                display_service = service_name or "unknown"
                if product_version:
                    display_service = f"{display_service} ({product_version})"
                host_ports.append(f"{portid}/{proto} {display_service}")

                ports.append(
                    {
                        "Source File": xml_file.name,
                        "IP Address": ip,
                        "Hostname": ", ".join(hostnames),
                        "MAC Address": mac,
                        "Vendor": vendor,
                        "Protocol": proto,
                        "Port": int(portid) if portid.isdigit() else portid,
                        "State": state_name,
                        "State Reason": state.attrib.get("reason", "") if state is not None else "",
                        "Reason TTL": state.attrib.get("reason_ttl", "") if state is not None else "",
                        "Service": service_name,
                        "Product": service.attrib.get("product", "") if service is not None else "",
                        "Version": service.attrib.get("version", "") if service is not None else "",
                        "Extra Info": service.attrib.get("extrainfo", "") if service is not None else "",
                        "OS Type": service.attrib.get("ostype", "") if service is not None else "",
                        "Method": service.attrib.get("method", "") if service is not None else "",
                        "Confidence": service.attrib.get("conf", "") if service is not None else "",
                        "CPE": "; ".join(cpes),
                        "Scripts": script_output(port),
                    }
                )

            extraport_counts = Counter()
            for extra in extra_rows:
                if extra["Source File"] == xml_file.name and extra["IP Address"] == ip:
                    try:
                        extraport_counts[extra["State"]] += int(extra["Count"])
                    except (TypeError, ValueError):
                        pass

            hosts.append(
                {
                    "Source File": xml_file.name,
                    "IP Address": ip,
                    "Hostname": ", ".join(hostnames),
                    "Status": status.attrib.get("state", "") if status is not None else "",
                    "Status Reason": status.attrib.get("reason", "") if status is not None else "",
                    "MAC Address": mac,
                    "Vendor": vendor,
                    "Open Ports": len(host.findall("./ports/port")),
                    "Closed Ports": extraport_counts.get("closed", 0),
                    "Filtered Ports": extraport_counts.get("filtered", 0),
                    "Services": ", ".join(sorted(set(name for name in service_names if name))),
                    "Port List": "; ".join(host_ports),
                    "Host Scripts": script_output(host.find("hostscript")),
                    "Start Time": epoch_to_local(host.attrib.get("starttime")),
                    "End Time": epoch_to_local(host.attrib.get("endtime")),
                    "SRTT": times.attrib.get("srtt", "") if times is not None else "",
                    "RTTVAR": times.attrib.get("rttvar", "") if times is not None else "",
                    "Timeout": times.attrib.get("to", "") if times is not None else "",
                }
            )

    hosts.sort(key=lambda row: ip_sort_key(row["IP Address"]))
    ports.sort(
        key=lambda row: (
            ip_sort_key(row["IP Address"]),
            row["Protocol"],
            int(row["Port"]) if isinstance(row["Port"], int) else row["Port"],
        )
    )
    return hosts, ports, scan_rows, extra_rows


def source_file_rows(input_dir: Path) -> list[dict[str, Any]]:
    candidates = []
    for pattern in ("*.xml", "*.nmap", "*.gnmap", "*.txt"):
        candidates.extend(input_dir.glob(pattern))

    rows = []
    for path in sorted(set(candidates)):
        role = {
            ".xml": "Nmap XML",
            ".nmap": "Nmap text",
            ".gnmap": "Nmap grepable",
        }.get(path.suffix, "Evidence text")
        rows.append(
            {
                "File": path.name,
                "Role": role,
                "Size Bytes": path.stat().st_size,
                "Modified": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "SHA256": sha256(path),
            }
        )
    return rows


def raw_text_rows(input_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(list(input_dir.glob("*.nmap")) + list(input_dir.glob("*.gnmap"))):
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for idx, line in enumerate(handle, start=1):
                rows.append({"File": path.name, "Line": idx, "Text": line.rstrip("\n")})
    return rows


def service_count_rows(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], set[str]] = defaultdict(set)
    for row in ports:
        product_version = " ".join(part for part in [row["Product"], row["Version"], row["Extra Info"]] if part).strip()
        key = (row["Protocol"], row["Port"], row["State"], row["Service"], product_version)
        grouped[key].add(row["IP Address"])

    rows = []
    for (proto, port, state, service, product_version), hosts in sorted(
        grouped.items(),
        key=lambda item: (item[0][0], int(item[0][1]) if isinstance(item[0][1], int) else item[0][1], item[0][3]),
    ):
        rows.append(
            {
                "Protocol": proto,
                "Port": port,
                "State": state,
                "Service": service,
                "Product/Version": product_version,
                "Host Count": len(hosts),
                "Hosts": ", ".join(sorted(hosts, key=ip_sort_key)),
            }
        )
    return rows


def port_matrix_rows(hosts: list[dict[str, Any]], ports: list[dict[str, Any]]) -> tuple[list[str], list[list[Any]]]:
    port_keys = sorted(
        {(row["Protocol"], row["Port"]) for row in ports},
        key=lambda item: (item[0], int(item[1]) if isinstance(item[1], int) else item[1]),
    )
    headers = ["IP Address", "Hostname"] + [f"{port}/{proto}" for proto, port in port_keys]
    by_host_port = {}

    for row in ports:
        product_version = " ".join(part for part in [row["Product"], row["Version"], row["Extra Info"]] if part).strip()
        value = row["Service"] or "unknown"
        if product_version:
            value = f"{value} ({product_version})"
        by_host_port[(row["IP Address"], row["Protocol"], row["Port"])] = value

    rows = []
    for host in hosts:
        rows.append(
            [host["IP Address"], host["Hostname"]]
            + [by_host_port.get((host["IP Address"], proto, port), "") for proto, port in port_keys]
        )
    return headers, rows


def add_table_sheet(
    wb: Workbook,
    title: str,
    headers: list[str],
    rows: list[dict[str, Any]] | list[list[Any]],
    wrap_columns: set[str] | None = None,
) -> None:
    wrap_columns = wrap_columns or set()
    ws = wb.create_sheet(title)
    ws.append(headers)

    if rows and isinstance(rows[0], dict):
        for row in rows:  # type: ignore[index]
            ws.append([row.get(header, "") for header in headers])  # type: ignore[union-attr]
    else:
        for row in rows:  # type: ignore[assignment]
            ws.append(row)

    header_fill = PatternFill("solid", fgColor="1F4E78")
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill
        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)

    ws.freeze_panes = "A2"
    if ws.max_row >= 1 and ws.max_column >= 1:
        ws.auto_filter.ref = ws.dimensions

    for col_idx, header in enumerate(headers, start=1):
        letter = get_column_letter(col_idx)
        max_len = len(str(header))
        for cell in ws[letter]:
            max_len = max(max_len, min(len(str(cell.value or "")), 80))
            if header in wrap_columns:
                cell.alignment = Alignment(vertical="top", wrap_text=True)
        ws.column_dimensions[letter].width = min(max(max_len + 2, 10), 60)


def add_summary_sheet(wb: Workbook, hosts: list[dict[str, Any]], ports: list[dict[str, Any]], xml_files: list[Path], output: Path) -> None:
    ws = wb.create_sheet("Summary", 0)
    rows = [
        ("Workbook Created", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Nmap XML Parsed", ", ".join(path.name for path in xml_files)),
        ("Hosts", len({row["IP Address"] for row in hosts})),
        ("Open Services", len([row for row in ports if row["State"] == "open"])),
        ("Unique Open Ports", len({(row["Protocol"], row["Port"]) for row in ports})),
        ("Output File", output.name),
    ]
    for row in rows:
        ws.append(row)
    ws.column_dimensions["A"].width = 24
    ws.column_dimensions["B"].width = 80
    for cell in ws["A"]:
        cell.font = Font(bold=True)


def build_workbook(input_dir: Path, output: Path) -> None:
    xml_files = find_nmap_xml_files(input_dir)
    if not xml_files:
        raise SystemExit(f"No Nmap XML files found in {input_dir}")

    hosts, ports, scan_rows, extra_rows = parse_xml_files(xml_files)

    wb = Workbook()
    wb.remove(wb.active)
    add_summary_sheet(wb, hosts, ports, xml_files, output)
    add_table_sheet(
        wb,
        "Hosts",
        [
            "Source File",
            "IP Address",
            "Hostname",
            "Status",
            "Status Reason",
            "MAC Address",
            "Vendor",
            "Open Ports",
            "Closed Ports",
            "Filtered Ports",
            "Services",
            "Port List",
            "Host Scripts",
            "Start Time",
            "End Time",
            "SRTT",
            "RTTVAR",
            "Timeout",
        ],
        hosts,
        wrap_columns={"Port List", "Host Scripts"},
    )
    add_table_sheet(
        wb,
        "Open Ports",
        [
            "Source File",
            "IP Address",
            "Hostname",
            "MAC Address",
            "Vendor",
            "Protocol",
            "Port",
            "State",
            "State Reason",
            "Reason TTL",
            "Service",
            "Product",
            "Version",
            "Extra Info",
            "OS Type",
            "Method",
            "Confidence",
            "CPE",
            "Scripts",
        ],
        ports,
        wrap_columns={"CPE", "Scripts"},
    )
    matrix_headers, matrix = port_matrix_rows(hosts, ports)
    add_table_sheet(wb, "Port Matrix", matrix_headers, matrix)
    add_table_sheet(
        wb,
        "Service Counts",
        ["Protocol", "Port", "State", "Service", "Product/Version", "Host Count", "Hosts"],
        service_count_rows(ports),
        wrap_columns={"Hosts"},
    )
    add_table_sheet(
        wb,
        "Extra Port States",
        ["Source File", "IP Address", "State", "Count", "Reasons", "Port Ranges"],
        extra_rows,
        wrap_columns={"Port Ranges"},
    )
    add_table_sheet(
        wb,
        "Scan Metadata",
        ["Source File", "Nmap Version", "Scanner", "Command", "Started", "XML Output Version"],
        scan_rows,
        wrap_columns={"Command"},
    )
    add_table_sheet(wb, "Source Files", ["File", "Role", "Size Bytes", "Modified", "SHA256"], source_file_rows(input_dir))
    add_table_sheet(wb, "Raw Nmap Text", ["File", "Line", "Text"], raw_text_rows(input_dir), wrap_columns={"Text"})

    output.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output)

    check = load_workbook(output, read_only=True, data_only=True)
    check.close()

    print(f"Created: {output}")
    print(f"Hosts: {len(hosts)}")
    print(f"Open port rows: {len(ports)}")
    print(f"Unique open ports: {len({(row['Protocol'], row['Port']) for row in ports})}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse Nmap XML/text outputs into an Excel workbook.")
    parser.add_argument("--input-dir", default=".", type=Path, help="Directory containing .xml/.nmap/.gnmap files.")
    parser.add_argument("--output", default="parsed_nmap_results.xlsx", type=Path, help="Output .xlsx file.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_dir = args.input_dir.expanduser().resolve()
    output = args.output.expanduser()
    if not output.is_absolute():
        output = input_dir / output
    build_workbook(input_dir, output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
