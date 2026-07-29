#!/usr/bin/env python3
"""Interprocess locking for managed TLS certificate generations."""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Iterator


LOCK_NAME = ".certctl.lock"


@contextmanager
def certificate_directory_lock(
    directory: Path,
    *,
    exclusive: bool,
    create: bool = False,
    runtime_gid: int | None = None,
) -> Iterator[None]:
    flags = os.O_RDWR if exclusive else os.O_RDONLY
    if create:
        flags |= os.O_CREAT
    descriptor = os.open(directory / LOCK_NAME, flags, 0o640)
    try:
        if create:
            os.fchmod(descriptor, 0o640)
            if runtime_gid is not None:
                os.fchown(descriptor, 0, runtime_gid)
        fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def managed_pair_lock(certificate: Path, private_key: Path):
    """Return a shared lock context for a certctl-managed active symlink."""
    if certificate.parent == private_key.parent and certificate.parent.is_symlink():
        return certificate_directory_lock(certificate.parent.parent, exclusive=False)
    return nullcontext()
