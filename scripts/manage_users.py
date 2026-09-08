from __future__ import annotations

import argparse
from getpass import getpass
from pathlib import Path

from backend.security import SecurityManager


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a ShadowNet user")
    parser.add_argument("username")
    parser.add_argument("--role", choices=("viewer", "operator", "admin"), default="operator")
    parser.add_argument("--database", type=Path, default=Path("data/shadownet.db"))
    args = parser.parse_args()
    password = getpass("Password (minimum 10 characters): ")
    SecurityManager(args.database).create_user(args.username, password, args.role)
    print(f"Created {args.role} user {args.username}")


if __name__ == "__main__":
    main()
