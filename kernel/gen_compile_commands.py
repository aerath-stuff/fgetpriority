#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Generate a unity-build-aware compile_commands.json for fgetpriority.

Supports two modes:
1. Local KDIR mode (--kdir / KDIR / KERNEL_SRC): runs Kbuild directly against an
   existing kernel build tree (on the host or inside a DDK container).
2. Docker DDK mode (default when KDIR is unset): extracts kernel headers from a
   ylarod/ddk container image into ~/.cache/fgetpriority/ddk/ and maps container
   include paths to the host filesystem for clangd and LLVM tools.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


KERNEL_DIR = Path(__file__).resolve().parent
REPO_ROOT = KERNEL_DIR.parent
DEFAULT_KMI = "android16-6.12"
DEFAULT_IMAGE_REPO = "ghcr.io/ylarod/ddk"

STRIP_SINGLE_FLAGS = {
    "-c",
    "-w",
    "-Werror",
    "-Werror=unknown-warning-option",
    "-Werror=ignored-optimization-argument",
    "-Werror=option-ignored",
    "-Werror=unused-command-line-argument",
}
STRIP_PAIR_FLAGS = {
    "-o",
    "-mllvm",
}


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def resolve_docker_target(cli_image, cli_kmi):
    env_image = os.environ.get("DDK_IMAGE", "").strip()
    env_kmi = os.environ.get("KMI", "").strip()
    env_repo = os.environ.get("DDK_IMAGE_REPO", "").strip() or DEFAULT_IMAGE_REPO

    image = cli_image or env_image
    kmi = cli_kmi or env_kmi

    if not kmi and image:
        match = re.search(r"android\d+-\d+\.\d+", image)
        if match:
            kmi = match.group(0)
    if not kmi:
        kmi = DEFAULT_KMI
    if not re.fullmatch(r"android\d+-\d+\.\d+", kmi):
        raise RuntimeError(f"Invalid KMI '{kmi}' (expected format like {DEFAULT_KMI})")

    if not image:
        image = f"{env_repo}:{kmi}"
    return image, kmi


def ensure_docker_headers(image, kmi, cache, pull=True):
    inspect = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        capture_output=True,
        text=True,
    )
    if inspect.returncode != 0:
        if not pull:
            raise RuntimeError(f"Docker image not found locally: {image}")
        print(f"Pulling DDK image: {image}", flush=True)
        run(["docker", "pull", image])
        inspect = run(
            ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
            capture_output=True,
        )

    image_id = inspect.stdout.strip()
    identity = cache / ".image-id"
    if identity.exists() and identity.read_text().strip() != image_id:
        print(f"DDK image updated; refreshing header cache in {cache}", flush=True)
        shutil.rmtree(cache)

    kdir_ready = (cache / "kdir" / kmi / "include/generated/autoconf.h").is_file()
    src_uaccess = cache / "src" / kmi / "include/linux/uaccess.h"
    kdir_uaccess = cache / "kdir" / kmi / "include/linux/uaccess.h"

    if not (kdir_ready and (src_uaccess.is_file() or kdir_uaccess.is_file())):
        probe = run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--entrypoint",
                "/bin/sh",
                image,
                "-c",
                f'for d in "/opt/ddk/src/{kmi}" "/opt/ddk/kdir/{kmi}"; do [ -d "$d" ] && echo "$d"; done',
            ],
            capture_output=True,
        ).stdout.splitlines()
        container_dirs = [line.strip() for line in probe if line.strip()]
        if not container_dirs:
            raise RuntimeError(f"Expected /opt/ddk/*/{kmi} layout not found inside {image}")

        container = run(
            ["docker", "create", "--network=none", "--entrypoint", "/bin/true", image],
            capture_output=True,
        ).stdout.strip()
        try:
            for cdir in container_dirs:
                rel = Path(cdir).relative_to("/opt/ddk")
                dest = cache / rel
                if dest.exists():
                    shutil.rmtree(dest)
                dest.parent.mkdir(parents=True, exist_ok=True)
                print(f"Extracting {cdir} -> {dest}", flush=True)
                run(["docker", "cp", f"{container}:{cdir}", str(dest.parent)])
        finally:
            run(["docker", "rm", container], stdout=subprocess.DEVNULL)

        cache.mkdir(parents=True, exist_ok=True)
        identity.write_text(image_id + "\n")

    if not (cache / "kdir" / kmi / "include/generated/autoconf.h").is_file():
        raise RuntimeError(f"Missing generated kernel headers under {cache / 'kdir' / kmi}")
    return image_id


def sync_scratch_module(output):
    scratch = output / "module"
    scratch.mkdir(parents=True, exist_ok=True)
    for src in KERNEL_DIR.iterdir():
        if src.is_file() and (src.suffix in (".c", ".h") or src.name in ("Makefile", "Kconfig")):
            dst = scratch / src.name
            if not dst.exists() or dst.read_bytes() != src.read_bytes():
                shutil.copyfile(src, dst)
    return scratch


def parse_clang_command(stdout_text, scratch):
    candidates = [
        line.strip()
        for line in stdout_text.splitlines()
        if re.match(r"^\s*(?:\S*/)?clang(?:-\d+)?\s+-", line)
        and str(scratch / "main.c") in line
    ]
    if candidates:
        raw = candidates[-1]
    else:
        cmd_file = scratch / ".main.o.cmd"
        if not cmd_file.is_file():
            raise RuntimeError("Failed to capture Kbuild compiler command; see kbuild.log")
        raw = cmd_file.read_text().splitlines()[0].split(" := ", 1)[1]

    args = shlex.split(raw.replace("$(pound)", "#"))
    if "-D__KERNEL__" not in args or "-DMODULE" not in args:
        raise RuntimeError("Captured command is not a kernel module compilation")
    return args


def capture_local(kdir, output):
    scratch = sync_scratch_module(output)
    arch = os.environ.get("ARCH", "arm64")
    llvm = os.environ.get("LLVM", "1")
    llvm_ias = os.environ.get("LLVM_IAS", "1")
    result = subprocess.run(
        [
            "make",
            "-C",
            str(kdir),
            f"M={scratch}",
            f"ARCH={arch}",
            f"LLVM={llvm}",
            f"LLVM_IAS={llvm_ias}",
            "CONFIG_FGETPRIORITY=m",
            "V=1",
            "main.o",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (output / "kbuild.log").write_text(result.stdout)
    return parse_clang_command(result.stdout, scratch), scratch, result.returncode


def capture_docker(image, output):
    scratch = sync_scratch_module(output)
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--mount",
            f"type=bind,source={scratch},target={scratch}",
            "-w",
            str(scratch),
            "--entrypoint",
            "/bin/sh",
            image,
            "-c",
            'make -C "$KERNEL_SRC" M="$PWD" ARCH=arm64 LLVM=1 LLVM_IAS=1 CONFIG_FGETPRIORITY=m V=1 main.o',
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    (output / "kbuild.log").write_text(result.stdout)
    return parse_clang_command(result.stdout, scratch), scratch, result.returncode


def write_database(arguments, scratch, work_kdir, path_rewrites, output, compiler):
    rewritten = [compiler]
    for arg in arguments[1:]:
        for old_prefix, new_prefix in path_rewrites:
            arg = arg.replace(old_prefix, new_prefix)
        arg = arg.replace(str(scratch), str(KERNEL_DIR))
        rewritten.append(arg)

    main_path = str(KERNEL_DIR / "main.c")
    flags = [rewritten[0]]
    skip_next = False
    for arg in rewritten[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg in STRIP_PAIR_FLAGS:
            skip_next = True
            continue
        if (
            arg in STRIP_SINGLE_FLAGS
            or arg == main_path
            or arg.startswith("-Wp,-MMD,")
            or arg.startswith("-Wp,-MD,")
        ):
            continue
        flags.append(arg)

    flags.extend(["-Wno-unknown-warning-option", "-x", "c", f"-I{KERNEL_DIR}"])

    contexts = output / "contexts"
    contexts.mkdir(parents=True, exist_ok=True)
    main_source = (KERNEL_DIR / "main.c").read_text()

    entries = []
    for source in sorted(KERNEL_DIR.iterdir()):
        if source.suffix not in (".c", ".h"):
            continue
        source_flags = flags.copy()
        # Unity build: routine_*.c and internal headers rely on declarations and
        # macro overrides defined earlier in main.c before being #included.
        marker = f'#include "{source.name}"'
        if source.name != "kernel.h" and marker in main_source:
            prefix = main_source.split(marker, 1)[0]
            ctx_header = contexts / f"{source.name}.h"
            ctx_header.write_text(prefix)
            source_flags.extend(["-include", str(ctx_header)])

        entries.append(
            {
                "directory": str(work_kdir),
                "file": str(source),
                "arguments": source_flags + ["-c", str(source)],
            }
        )

    db_path = output / "compile_commands.json"
    db_path.write_text(json.dumps(entries, indent=2) + "\n")
    return db_path, len(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kdir", type=Path, help="Local kernel build directory (skips Docker)")
    parser.add_argument("--docker", action="store_true", help="Force Docker DDK mode")
    parser.add_argument("--image", help="DDK Docker image (or set DDK_IMAGE)")
    parser.add_argument("--kmi", help=f"Target KMI in Docker mode (default: {DEFAULT_KMI})")
    parser.add_argument("--cache", type=Path, help="Host directory for extracted DDK headers")
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / ".cache/clangd")
    parser.add_argument("--compiler", default="clang", help="Compiler driver recorded in CDB")
    parser.add_argument("--no-pull", action="store_true", help="Do not pull missing Docker image")
    opts = parser.parse_args()

    compiler = shutil.which(opts.compiler) or opts.compiler
    output = opts.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)

    env_kdir = os.environ.get("KDIR") or os.environ.get("KERNEL_SRC")
    use_local = False
    if opts.kdir:
        kdir = opts.kdir.expanduser().resolve()
        use_local = True
    elif not opts.docker and not opts.image and not os.environ.get("DDK_IMAGE") and env_kdir:
        candidate = Path(env_kdir).expanduser().resolve()
        if candidate.is_dir():
            kdir = candidate
            use_local = True

    if use_local:
        if not kdir.is_dir():
            raise RuntimeError(f"Kernel directory does not exist: {kdir}")
        if shutil.which("make") is None:
            raise RuntimeError("Required program not found: make")
        arguments, scratch, build_rc = capture_local(kdir, output)
        db_path, count = write_database(arguments, scratch, kdir, [], output, compiler)
    else:
        if shutil.which("docker") is None:
            raise RuntimeError("Docker not found; pass --kdir /path/to/kernel or install docker")
        image, kmi = resolve_docker_target(opts.image, opts.kmi)
        tag = re.sub(r"[^a-zA-Z0-9_.-]", "_", image.rsplit(":", 1)[-1])
        cache = (opts.cache or Path.home() / ".cache/fgetpriority/ddk" / tag).expanduser().resolve()
        ensure_docker_headers(image, kmi, cache, pull=not opts.no_pull)
        arguments, scratch, build_rc = capture_docker(image, output)
        rewrites = [
            ("/opt/ddk/src/", str(cache / "src") + "/"),
            ("/opt/ddk/kdir/", str(cache / "kdir") + "/"),
        ]
        db_path, count = write_database(
            arguments, scratch, cache / "kdir" / kmi, rewrites, output, compiler
        )

    print(f"Generated {db_path} ({count} entries)")
    if build_rc != 0:
        print(
            f"Note: Kbuild exited with {build_rc}; inspect {output / 'kbuild.log'}",
            file=sys.stderr,
        )
    return build_rc


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"gen_compile_commands: {exc}", file=sys.stderr)
        raise SystemExit(1)
