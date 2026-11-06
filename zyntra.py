#!/usr/bin/env python3

import argparse
from core.dispatcher import dispatch_command
from core.exporter import export_assessment
from modules.recon.network import parse_ports

VERSION = "0.1.0"


def show_banner():
    print(r"""
 ________  ___    ___ ________   _________  ________  ________
|\_____  \|\  \  /  /|\   ___  \|\___   ___\\   __  \|\   __  \
 \|___/  /\ \  \/  / | \  \\ \  \|___ \  \_\ \  \|\  \ \  \|\  \
     /  / /\ \    / / \ \  \\ \  \   \ \  \ \ \   _  _\ \   __  \
    /  /_/__\ /  / /   \ \  \\ \  \   \ \  \ \ \  \\  \\ \  \ \  \
   |\________\\__/ /     \ \__\\ \__\   \ \__\ \ \__\\ _\\ \__\ \__\
    \|_______|\|__|       \|__| \|__|    \|__|  \|__|\|__|\|__|\|__|
""")
    print(" Security Assessment & Intelligence Framework")
    print(f" Version {VERSION}\n")


def main():
    parser = argparse.ArgumentParser(
        prog="zyntra",
        description="ZYNTRA Security Assessment & Intelligence Framework"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"ZYNTRA {VERSION}"
    )


    modules = parser.add_mutually_exclusive_group()

    modules.add_argument(
        "-r",
        "--recon",
        action="store_true",
        help="Run reconnaissance"
    )

    modules.add_argument(
        "-e",
        "--enumeration",
        action="store_true",
        help="Run enumeration"
    )

    modules.add_argument(
        "-w",
        "--web",
        action="store_true",
        help="Run web security assessment"
    )

    modules.add_argument(
        "--export",
        metavar="ASSESSMENT_ID",
        help="Export one assessment by ID"
    )

    parser.add_argument(
        "-t",
        "--target",
        help="Target for the selected operation"
    )
    parser.add_argument(
        "--ports",
        help="Explicit TCP ports or ranges to scan (e.g. 22,80,443 or 1-1024)"
    )

    parser.add_argument(
        "--confirm-full-scan",
        action="store_true",
        help="Confirm an intentional full TCP port scan"
    )

    parser.add_argument(
        "--destination",
        help="Existing directory where the assessment will be exported"
    )

    args = parser.parse_args()

    if args.export and not args.destination:
        parser.error("--destination is required with --export")

    if args.destination and not args.export:
        parser.error("--destination requires --export")

    if args.export and (args.target or args.ports or args.confirm_full_scan):
        parser.error("--export cannot be combined with assessment options")

    if (args.recon or args.enumeration or args.web) and not args.target:
        parser.error("A target is required. Use -t/--target.")

    show_banner()

    if args.export:
        try:
            result = export_assessment(args.export, args.destination)

            if result["status"] == "skipped":
                print(f"[*] Export skipped: {result['reason']}")
                print(f"[*] Existing destination: {result['path']}")
            else:
                print(f"[+] Assessment exported: {args.export}")
                print(f"[+] Results: {result['path']}")
                print(f"[+] Results SHA-256: {result['sha256']}")

                if result.get("report_path"):
                    print(f"[+] HTML report: {result['report_path']}")

                if result.get("report_sha256"):
                    print(f"[+] Report SHA-256: {result['report_sha256']}")

        except (ValueError, FileNotFoundError, OSError) as error:
            parser.error(str(error))

    elif args.recon:
        try:
            ports = None

            if args.ports:
                ports = parse_ports(
                    args.ports,
                    confirm_full_scan=args.confirm_full_scan
                )
            elif args.confirm_full_scan:
                parser.error("--confirm-full-scan requires --ports")

            dispatch_command("recon", args.target, ports=ports)

        except ValueError as error:
            parser.error(str(error))

    elif args.enumeration:
        if args.ports or args.confirm_full_scan:
            parser.error("--ports is only supported with reconnaissance")

        dispatch_command("enumeration", args.target)

    elif args.web:
        if args.ports or args.confirm_full_scan:
            parser.error("--ports is only supported with reconnaissance")

        dispatch_command("web", args.target)

    else:
        if args.ports or args.confirm_full_scan:
            parser.error("--ports requires -r/--recon")

        print("[*] No module selected.")

if __name__ == "__main__":
    main()
