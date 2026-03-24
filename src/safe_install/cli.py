"""CLI entry points for safe-install."""

import argparse
import os
import sys
import tempfile
import textwrap

from .config import load_config
from .core import c, check_environment, SourceInspector, HashVerifier
from .ecosystems import ECOSYSTEMS


def print_banner():
    print(c("""
 +------------------------------------------------+
 |  safe-install -- supply chain attack defense    |
 |  pip | npm | cargo | go | gem | docker          |
 +------------------------------------------------+""", 'cyan'))


def cmd_install(args, config):
    eco_class = ECOSYSTEMS.get(args.ecosystem)
    if not eco_class:
        print(f"Unknown ecosystem: {args.ecosystem}")
        return 1

    print_banner()
    print(f"\n  Package:   {c(args.package, 'bold')}")
    print(f"  Ecosystem: {args.ecosystem}")

    eco = eco_class(config)
    ok = eco.full_install(
        args.package,
        extra_args=args.extra_args,
        sandbox=not args.no_sandbox,
        wheel_only=args.binary_only,
        dry_run=args.dry_run,
        force=args.force,
        ci_mode=getattr(args, 'ci', False),
        report_dir=getattr(args, 'report_dir', None),
        skip_typosquat=getattr(args, 'skip_typosquat', False),
        skip_intelligence=getattr(args, 'skip_intelligence', False),
    )
    return 0 if ok else 1


def cmd_audit(args, config):
    eco_class = ECOSYSTEMS.get(args.ecosystem)
    if not eco_class:
        print(f"Unknown ecosystem: {args.ecosystem}")
        return 1

    print_banner()
    print(f"\n  Auditing: {c(args.package, 'bold')} ({args.ecosystem})")

    eco = eco_class(config)

    # Typosquat check
    print(f"\n{c('  Typosquat check', 'bold')}")
    try:
        from .typosquat import TyposquatDetector
        detector = TyposquatDetector(config)
        typo_warnings = detector.check(args.package, args.ecosystem)
        if typo_warnings:
            detector.report(typo_warnings)
        else:
            print(f"  {c('OK', 'green')}")
    except ImportError:
        print(f"  {c('(not available)', 'dim')}")

    print(f"\n{c('  Dependency tree', 'bold')}")
    deps = eco.resolve_deps(args.package)
    if deps:
        print(f"  {len(deps)} packages:")
        for d in deps:
            print(f"    {d['name']}=={d['version']}")
    else:
        print(f"  Could not resolve dependencies")

    # Package intelligence (if --deep)
    if getattr(args, 'deep', False):
        print(f"\n{c('  Package intelligence', 'bold')}")
        try:
            from .intelligence import PackageIntelligence
            intel = PackageIntelligence(config)
            intel.analyze(args.package, args.ecosystem)
            intel.report()
        except ImportError:
            print(f"  {c('(not available)', 'dim')}")

        print(f"\n{c('  Dependency confusion', 'bold')}")
        try:
            from .confusion import DependencyConfusionDetector
            confusion = DependencyConfusionDetector(config)
            confusion.check(args.package, args.ecosystem)
            confusion.report()
        except ImportError:
            print(f"  {c('(not available)', 'dim')}")

    print(f"\n{c('  Source inspection', 'bold')}")
    inspector = SourceInspector(languages=eco.languages, config=config)

    with tempfile.TemporaryDirectory(prefix='safe_audit_') as tmpdir:
        packages = [args.package]
        if deps:
            packages.extend(d['name'] for d in deps[:10])
        for pkg in packages:
            pkg_dir = os.path.join(tmpdir, pkg.replace('/', '_').replace('@', '_'))
            os.makedirs(pkg_dir, exist_ok=True)
            if eco.download_source(pkg, pkg_dir):
                for d in eco.extract_archives(pkg_dir):
                    inspector.scan_directory(d)

    has_critical = inspector.report()

    # Binary analysis (if --deep)
    if getattr(args, 'deep', False):
        print(f"\n{c('  Binary analysis', 'bold')}")
        try:
            from .binary_analysis import BinaryAnalyzer
            analyzer = BinaryAnalyzer(config)
            # Would need extracted dirs — for now just report capability
            analyzer.report()
        except ImportError:
            print(f"  {c('(not available)', 'dim')}")

    has_binary = eco.check_binary_available(args.package)
    print(f"\n  Pre-built binary: {c('yes', 'green') if has_binary else c('no', 'yellow')}")

    if not inspector.findings:
        print(f"\n  {c('Package looks clean.', 'green')}")
    return 1 if has_critical else 0


def cmd_scan(args, config):
    print_banner()
    print(f"\n  Scanning: {c(args.path, 'bold')}")

    langs = args.languages.split(',') if args.languages else ['python', 'javascript', 'rust', 'go', 'ruby']
    inspector = SourceInspector(languages=langs, config=config)

    if os.path.isdir(args.path):
        inspector.scan_directory(args.path)
    elif os.path.isfile(args.path):
        inspector.scan_file(args.path, os.path.basename(args.path))
    else:
        print(f"  {c('Path not found', 'red')}")
        return 1

    has_critical = inspector.report()
    if not inspector.findings:
        print(f"\n  {c('No suspicious patterns found.', 'green')}")
    return 1 if has_critical else 0


def cmd_check_env(args, config):
    print_banner()
    check_environment(config)
    return 0


def cmd_verify(args, config):
    print_banner()
    print(f"\n{c('  Verifying safe-install integrity', 'bold')}")
    try:
        from .bootstrap import BootstrapVerifier
        verifier = BootstrapVerifier(config)
        ok, msg = verifier.verify_self()
        print(f"  {c('PASS' if ok else 'FAIL', 'green' if ok else 'red')}: {msg}")
        return 0 if ok else 1
    except ImportError:
        print(f"  {c('Bootstrap module not available', 'yellow')}")
        return 1


def cmd_monitor(args, config):
    print_banner()
    print(f"\n{c('  Runtime monitoring', 'bold')}")
    print(f"  Command: {' '.join(args.script_args)}")
    print(f"  Mode:    {args.mode}")

    try:
        from .runtime_monitor import RuntimeMonitor
        mon = RuntimeMonitor(config)
        exit_code, events = mon.run_monitored(args.script_args)
        mon.report()
        return exit_code
    except ImportError:
        print(f"  {c('Runtime monitor not available', 'yellow')}")
        return 1


def cmd_guard(args, config):
    print_banner()
    print(f"\n{c('  Import Guard', 'bold')}")

    try:
        from .import_guard import ImportGuard
        guard_config = dict(config)
        guard_config['import_guard'] = {
            'mode': args.mode,
            'whitelist_path': getattr(args, 'whitelist', None),
        }
        guard = ImportGuard(guard_config)
        guard.activate()
        print(f"  Starting Python shell with ImportGuard...")
        print(f"  All imports will be scanned. Press Ctrl+D to exit.\n")
        import code
        code.interact(banner='', local={'guard': guard})
        guard.deactivate()
        guard.report()
        return 0
    except ImportError:
        print(f"  {c('ImportGuard not available', 'yellow')}")
        return 1


def cmd_api(args, config):
    """Programmatic API — returns JSON for other channels."""
    import json as _json
    from .api import audit_package, check_typosquat, get_intelligence, scan_deps_file, get_status

    handlers = {
        'audit': lambda: audit_package(args.target, getattr(args, 'ecosystem', 'pip') or 'pip', config),
        'typosquat': lambda: check_typosquat(args.target, getattr(args, 'ecosystem', 'pip') or 'pip', config),
        'intel': lambda: get_intelligence(args.target, getattr(args, 'ecosystem', 'pip') or 'pip', config),
        'scan-deps': lambda: scan_deps_file(args.target, getattr(args, 'ecosystem', None), config),
        'status': lambda: get_status(config),
    }

    sub = args.api_command
    if sub not in handlers:
        print(f"Unknown api command: {sub}")
        return 1

    result = handlers[sub]()
    print(_json.dumps(result, indent=2, default=str))
    return 0


def cmd_activate(args, config):
    print_banner()
    try:
        from .wrapper.activate import activate_wrapper
        activate_wrapper(config, pip=not args.npm_only, npm=not args.pip_only)
        return 0
    except Exception as e:
        print(f"  {c('Activation failed:', 'red')} {e}")
        return 1


def cmd_deactivate(args, config):
    print_banner()
    try:
        from .wrapper.activate import deactivate_wrapper
        deactivate_wrapper(config)
        return 0
    except Exception as e:
        print(f"  {c('Deactivation failed:', 'red')} {e}")
        return 1


def cmd_wrapper_status(args, config):
    print_banner()
    from .api import get_status
    status = get_status(config)
    print(f"\n  Wrapper active: {c('YES', 'green') if status['wrapper_active'] else c('NO', 'yellow')}")
    print(f"  Active channels: {', '.join(status['active_channels']) or 'none'}")
    print(f"  Scans (last 1h): {status['recent_scans_1h']}")
    print(f"  Critical (1h):   {status['critical_1h']}")
    print(f"  Exposed files:   {status['exposed_files']}")
    print(f"  Exposed vars:    {status['exposed_vars']}")
    return 0


def detect_ecosystem(package):
    if package.startswith('@') or '/' in package:
        return 'npm'
    if '::' in package:
        return 'cargo'
    if package.count('/') >= 2 and '.' in package.split('/')[0]:
        return 'go'
    if ':' in package and not package.startswith('http'):
        return 'docker'
    return 'pip'


def main():
    parser = argparse.ArgumentParser(
        description='safe-install: Supply chain attack defense for all package managers',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Supported ecosystems: pip, npm, cargo, go, gem, docker

            Defense layers (12 total, strongest first):
              1. Docker sandbox       7. Filesystem snapshot
              2. Binary-only          8. Vault hardening
              3. Hash lockfile        9. DNS defense
              4. Typosquat detect    10. Import guard
              5. Package intel       11. Runtime monitor
              6. Source inspection   12. Network monitor

            Examples:
              safe-install install requests                    # sandboxed install
              safe-install install -e npm lodash --binary-only # npm, no scripts
              safe-install audit flask --deep                  # full intelligence
              safe-install scan ./project/ --languages python,javascript
              safe-install monitor python my_script.py         # runtime monitoring
              safe-install guard --mode block                  # import-time defense
              safe-install verify                              # self-integrity check
              safe-install check-env                           # show exposed creds

            Config: ~/.config/safe-install/config.toml or ./safe-install.toml
        """))

    subparsers = parser.add_subparsers(dest='command')

    # install
    p_install = subparsers.add_parser('install', help='Install with protection')
    p_install.add_argument('package')
    p_install.add_argument('extra_args', nargs='*')
    p_install.add_argument('-e', '--ecosystem', default=None)
    p_install.add_argument('--no-sandbox', action='store_true')
    p_install.add_argument('--binary-only', action='store_true')
    p_install.add_argument('--dry-run', action='store_true')
    p_install.add_argument('--force', action='store_true')
    p_install.add_argument('--ci', action='store_true', help='CI mode: strict, machine-readable')
    p_install.add_argument('--report-dir', help='Directory for reports (implies --ci)')
    p_install.add_argument('--skip-typosquat', action='store_true')
    p_install.add_argument('--skip-intelligence', action='store_true')

    # audit
    p_audit = subparsers.add_parser('audit', help='Audit without installing')
    p_audit.add_argument('package')
    p_audit.add_argument('-e', '--ecosystem', default=None)
    p_audit.add_argument('--deep', action='store_true', help='Include intelligence + binary analysis')

    # scan
    p_scan = subparsers.add_parser('scan', help='Scan local directory')
    p_scan.add_argument('path')
    p_scan.add_argument('--languages', default=None)

    # check-env
    subparsers.add_parser('check-env', help='Show exposed credentials')

    # verify
    subparsers.add_parser('verify', help='Verify safe-install integrity')

    # monitor
    p_monitor = subparsers.add_parser('monitor', help='Run with runtime monitoring')
    p_monitor.add_argument('script_args', nargs='+')
    p_monitor.add_argument('--mode', choices=['monitor', 'enforce'], default='monitor')

    # guard
    p_guard = subparsers.add_parser('guard', help='Python shell with import guard')
    p_guard.add_argument('--mode', choices=['monitor', 'block', 'sandbox'], default='monitor')
    p_guard.add_argument('--whitelist', help='Path to whitelist file')

    # api (programmatic JSON interface)
    p_api = subparsers.add_parser('api', help='Programmatic JSON API')
    p_api.add_argument('api_command', choices=['audit', 'typosquat', 'intel', 'scan-deps', 'status'])
    p_api.add_argument('target', nargs='?', default='')
    p_api.add_argument('-e', '--ecosystem', default=None)

    # activate/deactivate wrapper
    p_activate = subparsers.add_parser('activate', help='Activate pip/npm wrapper')
    p_activate.add_argument('--pip-only', action='store_true')
    p_activate.add_argument('--npm-only', action='store_true')
    subparsers.add_parser('deactivate', help='Deactivate pip/npm wrapper')
    subparsers.add_parser('wrapper-status', help='Show wrapper status')

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    config = load_config()

    if getattr(args, 'report_dir', None):
        args.ci = True

    if args.command in ('install', 'audit') and not getattr(args, 'ecosystem', None):
        args.ecosystem = detect_ecosystem(args.package)
        print(f"  Auto-detected ecosystem: {args.ecosystem}")

    commands = {
        'install': cmd_install,
        'audit': cmd_audit,
        'scan': cmd_scan,
        'check-env': cmd_check_env,
        'verify': cmd_verify,
        'monitor': cmd_monitor,
        'guard': cmd_guard,
        'api': cmd_api,
        'activate': cmd_activate,
        'deactivate': cmd_deactivate,
        'wrapper-status': cmd_wrapper_status,
    }
    return commands[args.command](args, config)


def main_pip():
    os.environ['SAFE_INSTALL_ECOSYSTEM'] = 'pip'
    return main()


def main_npm():
    os.environ['SAFE_INSTALL_ECOSYSTEM'] = 'npm'
    return main()


if __name__ == '__main__':
    sys.exit(main())
