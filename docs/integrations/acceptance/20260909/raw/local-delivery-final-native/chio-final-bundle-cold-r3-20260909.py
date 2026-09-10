from pathlib import Path
import hashlib, json, shutil, subprocess, time

BUNDLE = Path('/Users/connor/.local/share/chio-required-candidates/20260909')
OUT = Path('/tmp/chio-final-bundle-cold-r3-20260909')
OUT.mkdir()
manifest = json.loads((BUNDLE / 'manifest.json').read_text())
records = []
for host, name in [('pi', '@chio/pi-plugin')]:
    entry = next(e for e in manifest['entries'] if e['component'] == host)
    area = OUT / host
    area.mkdir()
    archive = area / Path(entry['path']).name
    shutil.copy2(BUNDLE / entry['path'], archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == entry['sha256']
    consumer = area / 'consumer'
    consumer.mkdir()
    (consumer / 'package.json').write_text('{"private":true}\n')
    host_command = ['npm', 'install', '--ignore-scripts', '--install-strategy=nested', '--no-audit', '--no-fund', '--cache', str(area / 'empty-cache'), '@earendil-works/pi-coding-agent@0.85.1']
    native = subprocess.run(host_command, cwd=consumer, capture_output=True, text=True)
    (area / 'host-install.stdout').write_text(native.stdout)
    (area / 'host-install.stderr').write_text(native.stderr)
    native.check_returncode()
    command = ['npm', 'install', '--install-strategy=nested', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', str(area / 'empty-cache'), str(archive)]
    started = time.time()
    proc = subprocess.run(command, cwd=consumer, capture_output=True, text=True)
    (area / 'install.stdout').write_text(proc.stdout)
    (area / 'install.stderr').write_text(proc.stderr)
    proc.check_returncode()
    root = consumer / 'node_modules' / name
    pkg = json.loads((root / 'package.json').read_text())
    assert pkg['name'] == name and not pkg.get('scripts')
    assert all(not v.startswith(('file:', 'link:', 'workspace:')) for v in pkg.get('dependencies', {}).values())
    bins = pkg.get('bin', {})
    targets = [pkg['main']] if pkg.get('main') else []
    targets += [bins] if isinstance(bins, str) else list(bins.values())
    checks = []
    for target in targets:
        path = (root / target).resolve()
        assert path.is_relative_to(root.resolve()) and path.is_file()
        checked = subprocess.run(['node', '--check', str(path)], capture_output=True, text=True)
        checks.append({'entry': target, 'exitCode': checked.returncode, 'stdout': checked.stdout, 'stderr': checked.stderr})
        checked.check_returncode()
    record = {'host': host, 'archiveSha256': entry['sha256'], 'packageName': pkg['name'], 'packageVersion': pkg['version'], 'command': command, 'offline': False, 'initialCacheEmptyBeforePublicHostInstall': True, 'hostInstallCommand': host_command, 'hostInstallExitCode': native.returncode, 'exitCode': proc.returncode, 'elapsedSeconds': time.time() - started, 'entryChecks': checks, 'hostAcceptanceClaim': False}
    (area / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    records.append(record)
    print(json.dumps({'host': host, 'passed': True, 'archiveSha256': entry['sha256']}), flush=True)
(OUT / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
