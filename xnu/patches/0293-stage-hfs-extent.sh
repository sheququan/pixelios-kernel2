#!/bin/bash
# SWEET: intentionally a no-op now.
#
# The extent dump used to be staged here, but patches/*.sh run BEFORE
# patches/*.patch, so injecting right after `fp = VTOF(vp);` broke 0234's
# patch context (`patch failed: hfs_readwrite.c:3335`) and 0234 does the
# same job with far less risk.  The dump now lives in 0294 (a .patch), which
# applies after 0234 and can anchor on 0234's own SWEET BM3 lines.
set -euo pipefail
exit 0
