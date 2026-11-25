#!/usr/bin/env bash
# SWEET (0275): one-slot proof of concept.  F218 showed the chained-fixup word
# at .27.dylddata foff 0xddc138 is still raw in user memory.  Rewrite that one
# slot to base(mapping j1) + target30 and see whether launchd gets past the
# SWEET LR/PC panic.  Diagnostic only -- no flash, no disk writes.
set -eu

python3 - <<'PY'
import io
import sys

path = "bsd/vm/vm_unix.c"
with io.open(path, "r", encoding="utf-8", newline="") as f:
    s = f.read()

if "SWEET PATCH1" in s:
    print("0275 probe already present")
    sys.exit(0)

anchor = "\tvnode_put(rdir_vp);\n"
if anchor not in s:
    sys.exit("0275: anchor not found")

code = r'''	/* SWEET (0275): see F218.  One chained-fixup slot, patched in place. */
	if (error == 0) {
		user_addr_t sweet_p1_va = (user_addr_t)0x00000021a578138ULL;
		uint64_t sweet_p1_val = 0x00000021a977e2d0ULL;
		int sweet_p1_err = copyout(&sweet_p1_val, sweet_p1_va, sizeof(sweet_p1_val));

		printf("SWEET PATCH1: err %d va %#llx val %#llx\n", sweet_p1_err,
		    (unsigned long long)sweet_p1_va,
		    (unsigned long long)sweet_p1_val);
	}

'''
s = s.replace(anchor, code + anchor, 1)
with io.open(path, "w", encoding="utf-8", newline="") as f:
    f.write(s)
print("0275 patch injected")
PY
