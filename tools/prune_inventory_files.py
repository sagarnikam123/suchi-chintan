#!/usr/bin/env python3
"""
Prune Older Inventory Files Tool

Iterates over service folders within specified account/output directories,
identifies the latest file(s) in each folder, keeps only the latest, and deletes older files.

Features:
- Accepts -p/--profile or -a/--account (just like inventory scripts).
- Accepts multiple accounts/profiles or direct paths.
- Defaults to scanning all account folders under output/ if no target specified.
- Keeps the newest N file(s) (default: 1) based on modification time.
- Supports filtering by service (-s/--service).
- Handles empty folders gracefully without errors.
- Leaves single-file folders untouched.
- Supports --dry-run to preview actions safely before deleting.

Usage:
    # 1. Prune by AWS profile name
    python tools/prune_inventory_files.py -p 123456789012_AdministratorAccess

    # 2. Prune by Account ID or Account Name/Alias
    python tools/prune_inventory_files.py -a 123456789012
    python tools/prune_inventory_files.py -a "Dev-Engineering"

    # 3. Dry-run preview
    python tools/prune_inventory_files.py -p 123456789012_AdministratorAccess --dry-run

    # 4. Prune a specific service only
    python tools/prune_inventory_files.py -a 123456789012 -s ec2,s3

    # 5. Keep top 2 latest files
    python tools/prune_inventory_files.py -a 123456789012 --keep 2

    # 6. Prune all accounts in output/
    python tools/prune_inventory_files.py --dry-run
"""

import sys
import re
import argparse
from pathlib import Path
from typing import List, Dict, Any, Set

ROOT_DIR = Path(__file__).parent.parent
OUTPUT_DIR = ROOT_DIR / "output"

# Make common utilities importable
sys.path.insert(0, str(ROOT_DIR))

try:
    from common import get_accounts, create_session_with_identity
except ImportError:
    get_accounts = None
    create_session_with_identity = None


def format_bytes(size: int) -> str:
    """Format file size into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}" if unit != 'B' else f"{size} B"
        size /= 1024.0
    return f"{size:.1f} TB"


def resolve_target_directories(
    account_arg: str = None,
    profile_arg: str = None,
    paths_arg: List[str] = None,
    service_arg: str = None
) -> List[Path]:
    """Resolve target service directories based on -p, -a, or path inputs."""
    account_ids: Set[str] = set()
    explicit_folders: List[Path] = []

    # 1. Handle -p / --profile
    if profile_arg:
        # Check if profile_arg is directly a 12-digit account ID
        if re.match(r'^\d{12}$', profile_arg):
            account_ids.add(profile_arg)
        else:
            # Try to extract account ID from profile name if it starts with 12 digits
            match = re.match(r'^(\d{12})', profile_arg)
            if match:
                account_ids.add(match.group(1))
            else:
                # Try STS lookup or accounts.yaml lookup
                resolved = False
                if get_accounts:
                    try:
                        matched_accts = [a for a in get_accounts() if a.get("profile") == profile_arg]
                        if matched_accts:
                            account_ids.add(matched_accts[0]["account_id"])
                            resolved = True
                    except Exception:
                        pass

                if not resolved and create_session_with_identity:
                    try:
                        _, acct_id, _ = create_session_with_identity(profile_arg)
                        if acct_id:
                            account_ids.add(acct_id)
                            resolved = True
                    except Exception:
                        pass

                if not resolved:
                    # Fallback to direct folder matching profile name
                    prof_dir = OUTPUT_DIR / profile_arg
                    if prof_dir.exists():
                        explicit_folders.append(prof_dir)
                    else:
                        print(f"❌ Error: Could not resolve Account ID for profile '{profile_arg}'", file=sys.stderr)
                        sys.exit(1)

    # 2. Handle -a / --account
    if account_arg:
        if re.match(r'^\d{12}$', account_arg):
            account_ids.add(account_arg)
        elif get_accounts:
            try:
                matched = get_accounts(account_arg)
                for acct in matched:
                    account_ids.add(acct["account_id"])
            except Exception as e:
                print(f"❌ Error resolving account '{account_arg}': {e}", file=sys.stderr)
                sys.exit(1)
        else:
            account_ids.add(account_arg)

    # 3. Handle explicit paths
    if paths_arg:
        for p in paths_arg:
            target_path = Path(p).resolve()
            if target_path.exists():
                # If path is an account ID under output/
                if target_path.parent == OUTPUT_DIR and re.match(r'^\d{12}$', target_path.name):
                    account_ids.add(target_path.name)
                else:
                    explicit_folders.append(target_path)
            else:
                print(f"⚠️  Warning: Path does not exist: {target_path}", file=sys.stderr)

    # 4. If no -p, -a, or paths provided, target all account folders under output/
    if not account_ids and not explicit_folders:
        if OUTPUT_DIR.exists():
            for entry in OUTPUT_DIR.iterdir():
                if entry.is_dir() and re.match(r'^\d{12}$', entry.name):
                    account_ids.add(entry.name)

    # Resolve account IDs to output folders
    for acct_id in sorted(account_ids):
        acct_dir = OUTPUT_DIR / acct_id
        if acct_dir.exists() and acct_dir.is_dir():
            explicit_folders.append(acct_dir)
        else:
            print(f"⚠️  Warning: No inventory output found for account {acct_id} at {acct_dir}", file=sys.stderr)

    # Services filter
    selected_services = set(service_arg.split(",")) if service_arg else None

    # Collect all service subdirectories
    target_service_folders = []
    for base in explicit_folders:
        subdirs = [d for d in base.iterdir() if d.is_dir() and not d.name.startswith(('.', '_'))]
        if subdirs:
            for sub in sorted(subdirs):
                if selected_services is None or sub.name in selected_services:
                    target_service_folders.append(sub)
        else:
            # Leaf folder
            if selected_services is None or base.name in selected_services:
                target_service_folders.append(base)

    return target_service_folders


def process_folder(folder: Path, keep_count: int, dry_run: bool) -> Dict[str, Any]:
    """Process a single directory, keeping only the newest `keep_count` files."""
    files = [f for f in folder.iterdir() if f.is_file() and not f.name.startswith('.')]
    
    result = {
        "folder": str(folder),
        "total_files": len(files),
        "kept": [],
        "deleted": [],
        "bytes_freed": 0,
    }

    if not files:
        return result

    # Sort files by modification time (newest first)
    files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

    kept_files = files[:keep_count]
    deleted_files = files[keep_count:]

    result["kept"] = [f.name for f in kept_files]

    for f in deleted_files:
        try:
            file_size = f.stat().st_size
            if not dry_run:
                f.unlink()
            result["deleted"].append(f.name)
            result["bytes_freed"] += file_size
        except Exception as e:
            print(f"  ❌ Error deleting {f.name}: {e}", file=sys.stderr)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Prune older inventory files in output directories, keeping only the latest."
    )
    parser.add_argument(
        "-p", "--profile",
        help="AWS profile name or Account ID to target.",
        default=None,
    )
    parser.add_argument(
        "-a", "--account",
        help="Account ID, Name, or Alias from accounts.yaml.",
        default=None,
    )
    parser.add_argument(
        "-s", "--service",
        help="Filter to specific service(s), comma-separated (e.g. ec2,s3,rds).",
        default=None,
    )
    parser.add_argument(
        "-k", "--keep",
        type=int,
        default=1,
        help="Number of latest files to keep per directory (default: 1).",
    )
    parser.add_argument(
        "-d", "--dry-run",
        action="store_true",
        help="Simulate actions without deleting any files.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional direct path(s) to account or service directory.",
        default=None,
    )
    args = parser.parse_args()

    if args.keep < 1:
        print("❌ Error: --keep must be at least 1", file=sys.stderr)
        sys.exit(1)

    target_folders = resolve_target_directories(
        account_arg=args.account,
        profile_arg=args.profile,
        paths_arg=args.paths,
        service_arg=args.service,
    )

    # Remove duplicates while preserving order
    seen = set()
    unique_folders = []
    for f in target_folders:
        if str(f) not in seen:
            seen.add(str(f))
            unique_folders.append(f)

    if not unique_folders:
        print("ℹ️  No folders found to process.")
        return

    action_label = "[DRY-RUN] Would delete" if args.dry_run else "Deleted"
    print("=" * 75)
    print(f"  🧹 Inventory File Pruner ({'DRY-RUN MODE' if args.dry_run else 'LIVE RUN'})")
    if args.profile:
        print(f"  Target Profile        : {args.profile}")
    if args.account:
        print(f"  Target Account        : {args.account}")
    if args.service:
        print(f"  Target Service(s)     : {args.service}")
    print(f"  Keep count per folder : {args.keep}")
    print(f"  Folders to evaluate   : {len(unique_folders)}")
    print("=" * 75)

    total_kept = 0
    total_deleted = 0
    total_freed = 0
    folders_with_deletions = 0
    empty_folders = 0

    for folder in unique_folders:
        res = process_folder(folder, args.keep, args.dry_run)
        total_files = res["total_files"]
        kept = res["kept"]
        deleted = res["deleted"]
        bytes_freed = res["bytes_freed"]

        total_kept += len(kept)
        total_deleted += len(deleted)
        total_freed += bytes_freed

        if total_files == 0:
            empty_folders += 1
            continue

        if deleted:
            folders_with_deletions += 1
            # Display relative path from output/ for clarity
            try:
                rel_path = folder.relative_to(OUTPUT_DIR)
            except ValueError:
                rel_path = folder
            print(f"\n📁 {rel_path} ({total_files} files -> keeping {len(kept)}, {action_label.lower()} {len(deleted)}):")
            print(f"   ✅ Kept: {', '.join(kept)}")
            for d in deleted:
                print(f"   🗑️  {action_label}: {d}")

    print("\n" + "=" * 75)
    print("  📊 SUMMARY")
    print("=" * 75)
    print(f"  Total folders checked   : {len(unique_folders)} ({empty_folders} empty)")
    print(f"  Folders with deletions  : {folders_with_deletions}")
    print(f"  Files kept (latest)     : {total_kept}")
    print(f"  Files {'would delete' if args.dry_run else 'deleted'}       : {total_deleted}")
    print(f"  Space {'reclaimable' if args.dry_run else 'freed'}         : {format_bytes(total_freed)}")
    print("=" * 75)


if __name__ == "__main__":
    main()
