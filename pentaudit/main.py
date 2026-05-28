"""
main.py — Command-Line Interface (CLI) Entry Point for PentAudit
=================================================================

WHY THIS FILE EXISTS:
This is the "brain" or the controller of the entire tool. When the user 
runs the tool from the terminal, this is the file that gets executed. It:
1. Parses terminal arguments (like target, output, domain).
2. Sets up and coordinates the Discovery scanner, Access auditor, and Report generator.
3. Provides a clean flow, timing operations and displaying terminal results.
"""

import argparse
import sys
import os
import json
from datetime import datetime



# Import our custom modules
from pentaudit.config import DEMO_MODE
from pentaudit.utils import (
    print_banner, print_phase, print_success, print_warning,
    print_info, print_error, timer_start, timer_end, display_results_table,
    console
)
from pentaudit.discovery import DiscoveryScanner
from pentaudit.auditor import SecurityAuditor
from pentaudit.reporter import ReportGenerator


def parse_arguments():
    """Parse and return command-line arguments."""
    parser = argparse.ArgumentParser(
        description="PentAudit — Autonomous Pentest Platform & AI Security Tool Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a live scan on a target subnet and generate report:
  python -m pentaudit.main --target 10.0.5.0/24 --output audit_report.html

  # Run in demo mode for portfolio showcase (no real scanning required):
  python -m pentaudit.main --demo --output demo_report.html

  # Perform discovery only (no active security auditing):
  python -m pentaudit.main --target 10.0.5.50 --discover-only

  # Re-generate report from previous scan results JSON:
  python -m pentaudit.main --from-results scan_data.json --output report.html
"""
    )

    parser.add_argument(
        "-t", "--target",
        help="Target IP address, range (e.g., 10.0.5.0/24), or host to scan"
    )
    
    parser.add_argument(
        "-d", "--domain",
        help="Internal domain name (e.g., corp.internal) for DNS checks"
    )

    parser.add_argument(
        "-o", "--output",
        default="report.html",
        help="Path to save the HTML report (default: report.html)"
    )

    parser.add_argument(
        "--discover-only",
        action="store_true",
        help="Run discovery phase only (do not perform active security audits)"
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with simulated findings (great for GitHub showcase)"
    )

    parser.add_argument(
        "--from-results",
        help="Re-generate HTML report from a previously saved JSON scan results file"
    )

    return parser.parse_args()


def run_from_results(json_path, output_path):
    """Load scan results from a JSON file and re-generate the HTML report."""
    print_phase("RE-GENERATING REPORT FROM JSON RESULTS")
    print_info(f"Loading results file: {json_path}")

    if not os.path.exists(json_path):
        print_error(f"JSON results file not found at: {json_path}")
        sys.exit(1)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        findings = data.get("findings", [])
        platforms = data.get("platforms", [])
        scan_metadata = {
            "target": data.get("target", "N/A"),
            "mode": data.get("scan_mode", "loaded_results"),
            "date": data.get("date", datetime.now().strftime("%B %d, %Y"))
        }

        print_success(f"Successfully loaded {len(platforms)} platform(s) and {len(findings)} finding(s)")
        
        reporter = ReportGenerator(findings, platforms, scan_metadata)
        reporter.generate(output_path)
        
        print_success("Report re-generation complete!")
    except Exception as e:
        print_error(f"Failed to process results file: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point."""
    print_banner()
    args = parse_arguments()

    # Case 1: Re-generating report from JSON file
    if args.from_results:
        run_from_results(args.from_results, args.output)
        sys.exit(0)

    # Case 2: Standard scanning / Demo
    target = args.target
    demo_mode = args.demo

    # Help user if they run the tool without arguments
    if not target and not demo_mode:
        print_warning("No scanning target specified!")
        print_info("To showcase the tool's capabilities, we will run in [bold]DEMO MODE[/bold].")
        print_info("To scan a real network instead, use: [bold]python -m pentaudit.main --target <IP/range>[/bold]\n")
        demo_mode = True
        target = "10.0.5.0/24"  # Default simulated target

    start_time = timer_start()

    # 1. Discovery Phase
    scanner = DiscoveryScanner(target=target, domain=args.domain, demo_mode=demo_mode)
    discovered_platforms = scanner.run()

    # Format discovered platforms for the terminal table display
    terminal_table_data = []
    for platform in discovered_platforms:
        terminal_table_data.append({
            "host": platform["host"],
            "port": platform["port"],
            "platform": platform["platform"],
            "confidence": platform["confidence"],
            "url": platform["url"]
        })
    
    if terminal_table_data:
        console.print("\n")
        display_results_table(terminal_table_data, title="Discovered Asset Inventory")

    # If the user only wants discovery, we generate a basic report or stop here
    if args.discover_only:
        print_success("Discovery phase finished (--discover-only specified). Skipping audit.")
        
        # Save a discovery-only report
        scan_metadata = {
            "target": target,
            "mode": "discovery_only",
            "date": datetime.now().strftime("%B %d, %Y")
        }
        reporter = ReportGenerator(findings=[], platforms=discovered_platforms, scan_metadata=scan_metadata)
        reporter.generate(args.output)
        
        elapsed = timer_end(start_time)
        print_success(f"Finished in {elapsed}s.")
        sys.exit(0)

    # 2. Auditing Phase
    auditor = SecurityAuditor(discovered_platforms, demo_mode=demo_mode)
    findings = auditor.run_all_checks()

    # Format findings for terminal display
    if findings:
        console.print("\n")
        findings_table_data = []
        for finding in findings:
            findings_table_data.append({
                "check_id": finding["check_id"],
                "platform": finding["platform_name"],
                "host": finding["platform_host"],
                "risk_level": finding["risk_level"],
                "title": finding["title"]
            })
        display_results_table(findings_table_data, title="Identified Vulnerabilities & Risks")

    # 3. Reporting Phase
    scan_metadata = {
        "target": target,
        "mode": "demo" if demo_mode else "active_scan",
        "date": datetime.now().strftime("%B %d, %Y")
    }
    reporter = ReportGenerator(findings, discovered_platforms, scan_metadata)
    reporter.generate(args.output)

    # 4. Final summary
    total_elapsed = timer_end(start_time)
    print_phase("AUDIT SUMMARY")
    print_success(f"Total execution time: {total_elapsed} seconds")
    print_success(f"Assets discovered: {len(discovered_platforms)}")
    print_warning(f"Vulnerabilities found: {len(findings)}")
    print_info(f"HTML report generated: [bold]{args.output}[/bold]")
    print_info(f"JSON results generated: [bold]{args.output.replace('.html', '.json')}[/bold]")
    
    if demo_mode:
        print_info("\n💡 [bold cyan]Showcase Tip:[/bold cyan] Open the HTML report in your browser to view the premium dark-themed layout, risk charts, and MITRE ATT&CK maps.")


if __name__ == "__main__":
    main()
