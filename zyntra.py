#!/usr/bin/env python3

import argparse
from core.dispatcher import dispatch_command


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


    parser.add_argument(
        "-r",
        "--recon",
        action="store_true",
        help="Run reconnaissance"
    )

    parser.add_argument(
        "-e",
        "--enumeration",
        action="store_true",
        help="Run enumeration"
    )


    parser.add_argument(
        "-t",
        "--target",
        help="Target for the selected operation"
    )

    args = parser.parse_args()

    show_banner()

    if args.recon:
        dispatch_command("recon", args.target)

    elif args.enumeration:
        dispatch_command("enumeration", args.target)

    else:
        print("[*] No module selected.")

if __name__ == "__main__":
    main()
