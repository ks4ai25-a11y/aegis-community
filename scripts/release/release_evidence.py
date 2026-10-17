#!/usr/bin/env python3
"""Supply-chain release evidence (release gate GATE-10).

From a clean checkout, builds the release images, exports each to a tar archive, and runs the
digest-pinned Syft image against the archive with no network to produce CycloneDX SBOMs. Writes
dist/release-<commit>/ with: SBOMs, SHA256SUMS for every artifact, a licence inventory derived
from the SBOMs, and release-manifest.json binding the source commit, Go/Node toolchains, image
IDs and pinned base images. Refuses to run on a dirty tree so the evidence matches a commit.

  python3 scripts/release/release_evidence.py [--allow-dirty] [--tag TAG]
"""
import argparse, collections, hashlib, json, os, pathlib, re, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
LOCK = json.loads((ROOT / "tools/scanners.lock.json").read_text())
SYFT = next(t["image"] for t in LOCK["tools"] if t["id"] == "syft")
BINARIES = [("controller", "aegisctl"), ("controller", "aegis-mcp"), ("alpha", "aegis-scanner-db")]
PLATFORMS = [("linux", "amd64"), ("linux", "arm64"), ("darwin", "arm64")]
IMAGES = [("gateway", "gateway/Dockerfile", None), ("controller", "controller/Dockerfile", None), ("demo-origin", "demo/origin/Dockerfile", None)]


def run(*args, **kw):
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, text=True, **kw).stdout.strip()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def syft(mount_src, mount_dst, source, dest, *extra):
    """Run the pinned Syft image with no network. Docker Desktop can briefly refuse a bind
    mount of a directory that was deleted and recreated, so that error is retried."""
    args = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,size=256m", "-e", "HOME=/tmp", "--mount", f"type=bind,src={mount_src},dst={mount_dst},readonly", SYFT, source, *extra, "-o", "cyclonedx-json", "-q"]
    for attempt in range(12):
        r = subprocess.run(args, capture_output=True, timeout=900)
        if r.returncode == 0:
            dest.write_bytes(r.stdout)
            return
        if b"bind source path does not exist" not in r.stderr or attempt == 11:
            sys.exit(f"syft failed for {source}: {r.stderr.decode(errors='replace')[-2000:]}")
        time.sleep(10)


GOMODCACHE = pathlib.Path(subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True).stdout.strip() or "/nonexistent")


GOROOT = pathlib.Path(subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip() or "/nonexistent")
LICENCE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "COPYING", "LICENSE-APACHE", "LICENSE-MIT")


def go_module_dir(purl):
    m = re.match(r"pkg:golang/(.+)@([^?#]+)", purl or "")
    if not m:
        return None, None
    if m.group(1) == "stdlib":
        return f"stdlib@{m.group(2)}", GOROOT
    escaped = re.sub(r"[A-Z]", lambda x: "!" + x.group(0).lower(), m.group(1))
    return f"{m.group(1)}@{m.group(2)}", GOMODCACHE / f"{escaped}@{m.group(2)}"


def notice_texts(root):
    """Licence and NOTICE files at a package root, in a stable order."""
    names = [n for n in LICENCE_FILES if (root / n).is_file()] + sorted(p.name for p in root.glob("NOTICE*") if p.is_file())
    return [(n, (root / n).read_text(errors="replace")) for n in names]


def go_licence(purl):
    """Classify a Go module's licence from its LICENSE file in the local module cache (offline)."""
    m = re.match(r"pkg:golang/(.+)@([^?#]+)", purl or "")
    if not m:
        return None
    escaped = re.sub(r"[A-Z]", lambda x: "!" + x.group(0).lower(), m.group(1))
    root = GOMODCACHE / f"{escaped}@{m.group(2)}"
    for name in LICENCE_FILES:
        f = root / name
        if f.is_file():
            t = f.read_text(errors="ignore")
            if "Apache License" in t and "Version 2.0" in t:
                return "Apache-2.0"
            if "Mozilla Public License" in t and "2.0" in t:
                return "MPL-2.0"
            if "GNU GENERAL PUBLIC LICENSE" in t or "GNU LESSER GENERAL PUBLIC LICENSE" in t:
                return "GPL-family (review)"
            if "Permission is hereby granted, free of charge" in t:
                return "MIT"
            if "Permission to use, copy, modify, and/or distribute" in t or "ISC License" in t:
                return "ISC"
            if "Redistribution and use in source and binary forms" in t:
                return "BSD-3-Clause" if "Neither the name" in t or "names of its" in t else "BSD-2-Clause"
            if "unlicense" in t.lower() or "public domain" in t.lower():
                return "Unlicense/public-domain"
            return "unclassified-licence-file"
    return None


def base_images(dockerfile):
    return sorted(set(re.findall(r"^FROM\s+(\S+)", (ROOT / dockerfile).read_text(), re.M)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow-dirty", action="store_true")
    ap.add_argument("--tag", default="release-evidence")
    ap.add_argument("--sign-key", help="OpenSSH private key; writes SHA256SUMS.sig (namespace aegis-release)")
    a = ap.parse_args()
    commit = run("git", "rev-parse", "HEAD")
    dirty = run("git", "status", "--porcelain")
    if dirty and not a.allow_dirty:
        sys.exit("refusing: working tree has uncommitted changes (evidence must match a commit)")
    out = ROOT / "dist" / f"release-{commit[:12]}"
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": "1.0", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "source_commit": commit, "working_tree_clean": not dirty,
                "toolchain": {"go": run("go", "version"), "node": run("node", "--version"), "docker": run("docker", "version", "--format", "{{.Server.Version}}")},
                "sbom_tool": SYFT, "images": [], "binaries": [], "console_npm": {}, "notices": {}, "licences": {}, "limitations": [
                    "SHA256SUMS is signed only when --sign-key is given; there is no publisher key or transparency log yet.",
                    "Image IDs are local build results and are not claimed reproducible; CLI binaries are rebuilt twice on this host and compared (rebuild_identical), which is not a cross-host reproducibility proof.",
                    "Licence identifiers come from package metadata as reported by Syft and are not a legal review."]}
    licences = collections.Counter()
    unknown = []
    go_modules = {}
    for name, dockerfile, target in IMAGES:
        tag = f"aegis-community/{name}:{a.tag}"
        args = ["docker", "build", "-q", "-f", dockerfile, "-t", tag] + (["--target", target] if target else []) + ["."]
        image_id = run(*args)
        tar = out / f"{name}.image.tar"
        run("docker", "save", "-o", str(tar), tag)
        sbom = out / f"{name}.cdx.json"
        # Mount the long-lived checkout rather than the new output directory, which Docker
        # Desktop may not see for a while after it is created.
        syft(ROOT, "/in", f"docker-archive:/in/{tar.relative_to(ROOT)}", sbom)
        doc = json.loads(sbom.read_text())
        comps = doc.get("components", [])
        for c in comps:
            label, moddir = go_module_dir(c.get("purl"))
            if moddir and not label.startswith("aegis.local/"):
                go_modules[label] = moddir
            ids = [l.get("license", {}).get("id") or l.get("license", {}).get("name") or l.get("expression") for l in c.get("licenses", [])]
            ids = [i for i in ids if i]
            if ids:
                for i in ids:
                    licences[i] += 1
            elif (g := go_licence(c.get("purl"))):
                licences[g + " (from module LICENSE)"] += 1
            elif c.get("type") == "library" and not (c.get("purl") or "").startswith("pkg:golang/aegis.local"):
                unknown.append(f'{name}:{c.get("name")}@{c.get("version")}')
        manifest["images"].append({"name": name, "dockerfile": dockerfile, "image_id": image_id, "base_images": base_images(dockerfile),
                                   "archive_sha256": sha256(tar), "sbom": sbom.name, "sbom_sha256": sha256(sbom), "components": len(comps)})
        tar.unlink()  # archives are large; their digest is recorded above
    bins = out / "bin"
    for module, cmd in BINARIES:
        for goos, goarch in PLATFORMS:
            name = f"{cmd}-{goos}-{goarch}"
            digests = []
            for attempt in (1, 2):  # build twice from a fresh cache key to check reproducibility
                target = bins / (name if attempt == 1 else name + ".rebuild")
                env = {**os.environ, "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch, "GOFLAGS": "-mod=readonly"}
                subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", str(target), f"./cmd/{cmd}"], cwd=ROOT / module, env=env, check=True, capture_output=True)
                digests.append(sha256(target))
            (bins / (name + ".rebuild")).unlink()
            path = bins / name
            manifest["binaries"].append({"name": name, "module": module, "sha256": digests[0], "bytes": path.stat().st_size, "rebuild_identical": digests[0] == digests[1]})
    # The console's JavaScript is compiled into the controller image, so the image SBOM
    # does not list its npm packages; catalogue them from the lock file.
    console_sbom = out / "console-npm.cdx.json"
    syft(ROOT / "console", "/src", "dir:/src", console_sbom, "--exclude", "./node_modules/**")
    lock = json.loads((ROOT / "console/package-lock.json").read_text())
    if not (ROOT / "console/node_modules").is_dir():
        # Licence texts are read from the installed packages; the npm cache is used when it has them.
        subprocess.run(["npm", "ci", "--ignore-scripts", "--prefer-offline", "--no-audit", "--no-fund"], cwd=ROOT / "console", check=True, capture_output=True)
    npm = collections.Counter()
    for key, pkg in lock.get("packages", {}).items():
        if key and not pkg.get("dev"):
            npm[pkg.get("license") or "unknown"] += 1
    manifest["console_npm"] = {"sbom": console_sbom.name, "sbom_sha256": sha256(console_sbom), "production_packages_by_licence": dict(npm.most_common()),
                               "note": "Licences from package-lock.json; devDependencies (build and test tools) are excluded because they are not shipped."}
    for k, n in npm.items():
        licences[k + " (npm, shipped in console)"] += n
    # One file with the licence and NOTICE texts of every shipped Go module and npm
    # package, read from the local module cache and node_modules (no network).
    parts, missing = [], []
    for label, moddir in sorted(go_modules.items()):
        texts = notice_texts(moddir) if moddir.is_dir() else []
        if not texts:
            missing.append(label)
        for n, t in texts:
            parts.append(f"==== Go module {label} — {n} ====\n{t.rstrip()}\n")
    for key, pkg in sorted(lock.get("packages", {}).items()):
        if key and not pkg.get("dev"):
            texts = notice_texts(ROOT / "console" / key) if (ROOT / "console" / key).is_dir() else []
            if not texts:
                missing.append(f"npm {key.removeprefix('node_modules/')}@{pkg.get('version')}")
            for n, t in texts:
                parts.append(f"==== npm {key.removeprefix('node_modules/')}@{pkg.get('version')} — {n} ====\n{t.rstrip()}\n")
    parts.append("==== Alpine Linux packages ====\nThe images are based on the pinned Alpine images listed in release-manifest.json. Their OS packages (for example busybox and apk-tools, GPL-2.0-only) are unmodified Alpine builds; licence texts are in each image under /usr/share/licenses or /lib/apk/db, and corresponding source is published by the Alpine Linux project (aports) for the recorded package versions.\n")
    notices = out / "THIRD_PARTY_LICENSES.txt"
    notices.write_text("Aegis Community release " + commit + " — third-party licence and notice texts\n\n" + "\n".join(parts))
    manifest["notices"] = {"file": notices.name, "sha256": sha256(notices), "go_modules": len(go_modules), "without_licence_text": missing}
    manifest["licences"] = {"by_identifier": dict(licences.most_common()), "components_without_licence_metadata": len(unknown), "examples_without_licence": unknown[:20]}
    copyleft = sorted(k for k in licences if re.search(r"(A?GPL|LGPL|MPL|EPL|CDDL)", k))
    manifest["licences"]["copyleft_identifiers_for_review"] = copyleft
    (out / "release-manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    sums = [f"{sha256(p)}  {p.name}" for p in sorted(out.iterdir()) if p.is_file() and p.name not in ("SHA256SUMS", "SHA256SUMS.sig")]
    sums += [f"{b['sha256'].removeprefix('sha256:')}  bin/{b['name']}" for b in manifest["binaries"]]
    (out / "SHA256SUMS").write_text("\n".join(sorted(sums, key=lambda x: x.split("  ")[1])) + "\n")
    if a.sign_key:
        # OpenSSH signatures need no paid service or online CA; verify with
        # ssh-keygen -Y verify -f allowed_signers -I <identity> -n aegis-release -s SHA256SUMS.sig < SHA256SUMS
        subprocess.run(["ssh-keygen", "-Y", "sign", "-f", a.sign_key, "-n", "aegis-release", str(out / "SHA256SUMS")], check=True, capture_output=True)
    print(json.dumps({"output": str(out.relative_to(ROOT)), "images": [(i["name"], i["components"]) for i in manifest["images"]], "licence_ids": len(licences), "copyleft_for_review": copyleft, "without_licence": len(unknown), "without_licence_text": manifest["notices"]["without_licence_text"]}, indent=1))


if __name__ == "__main__":
    main()
