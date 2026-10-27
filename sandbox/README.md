# Sandbox

`Dockerfile` builds a static musl `sorosentinel-scan` on an empty base. `run.sh`
runs one scan with no network, a read-only root FS, all capabilities dropped,
no-new-privileges, the syscall allowlist in `seccomp.json`, a non-root user,
memory/CPU/PID limits and a timeout.

## seccomp.json

Default action: fail the call with `EPERM`. Allowed, in two groups:

- **The scanner:** the syscalls `sorosentinel-scan` makes on every path (valid
  module, known-bad hash list, file argument, garbage, oversized input, empty
  stdin, bad or missing hash list, usage error, missing file). Names differ by
  architecture (`open`/`poll`/`arch_prctl` on x86_64, `openat`/`ppoll` on
  aarch64); names an architecture lacks are skipped when the profile loads.
- **runc init:** with no-new-privileges, runc loads the filter and then still
  runs a few steps of its own before `execve`, so those syscalls must be
  allowed too.

Only native x86_64 and aarch64 are allowed (`archMap` with no
sub-architectures), so 32-bit syscall entry points are refused.

The profile allows nothing the traces did not show. A blocked call returns an
error, so an incomplete list makes the scan fail loud (`unreadable_input`, an
error exit, or a container start failure), never return a clean report.

### How the list was derived

Re-run these steps when the binary, Rust toolchain, base image or Docker/runc
version changes. Inputs (a valid upgradeable module, garbage, a module over
1 MiB, a hash list with the module's hash, a malformed hash list) go in a
directory under `$HOME`, since Colima only shares `$HOME`.

1. **Scanner, aarch64.** Build an Alpine image with `strace` and the binary
   copied from `sorosentinel-scan` (`FROM sorosentinel-scan AS bin`,
   `FROM alpine:3.21`, `apk add strace`, `COPY --from=bin`). In it, run every
   case under `strace -f -o <file>` (container started with
   `--cap-add SYS_PTRACE --security-opt seccomp=unconfined`) and collect the
   syscall names after the `execve("/sorosentinel-scan", ...)` line.
2. **Scanner, x86_64.** Build an x86_64 binary with the same pinned Rust image
   (`docker run --platform linux/amd64 <rust image> cargo build --locked
   --release -p scan-cli`) and run every case under qemu-user with
   `QEMU_STRACE=1`, which logs the guest's syscalls.
3. **runc init.** Run every case through the real sandbox options with a copy
   of the profile whose `defaultAction` is `SCMP_ACT_LOG`, and read the
   `type=1326` audit lines from the kernel log (`colima ssh -- sudo dmesg`).
   Lift the kernel's printk rate limit while doing this
   (`sysctl kernel.printk_ratelimit=0`, then restore it), or lines are dropped.
   Every logged call came from `runc:[2:INIT]`; the scanner logged none.
4. Switch back to `SCMP_ACT_ERRNO` and run each case repeatedly.

Traced on 2026-10-27 with Docker 29.5.2 under Colima on aarch64.
TODO(verify): the runc group was traced on aarch64 only. Before production use
on x86_64, repeat step 3 on an x86_64 Docker host.

### Checking that other syscalls are blocked

The scanner image has no shell, so use busybox under the same options and
profile. On aarch64:

```sh
O="--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --user 65534:65534"
docker run $O --security-opt seccomp=sandbox/seccomp.json alpine:3.21 ls -l /etc/hostname
# ls: /etc/hostname: Operation not permitted   (newfstatat is not allowed)
```

Adding only `writev` (busybox's output path) to a copy of the profile,
`uname -m` prints nothing; adding `writev` and `uname` prints `aarch64`.
