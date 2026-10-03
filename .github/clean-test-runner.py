"""Run Cargo test executables without ambient build/runner file descriptors.

Descriptor-isolation tests must still catch pipes created by claudectl itself.
Closing descriptors at this boundary also covers pipes Cargo opens after startup.
"""

import subprocess
import sys

raise SystemExit(subprocess.call(sys.argv[1:], close_fds=True))
