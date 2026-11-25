#!/usr/bin/env bash
# SWEET (0279): let a user SIGILL kill the process instead of panicking the box.
#
# R171 got past the chained-fixup wall and then hit "SWEET SIGILL: pc
# 0x104befc80 instr 0" (F239).  That address is in no known image, and the
# screen before it is full of CLONE/PAGEOUT/SWAPFILE, so the fault may be a
# background process rather than launchd.  Turn the panic back into a print and
# fall through to handle_uncategorized(), so the kernel survives and the console
# can show what happens next.
set -eu

python3 - <<'PY'
import io
import sys

path = "osfmk/arm64/sleh.c"
with io.open(path, "r", encoding="utf-8", newline="") as f:
    s = f.read()

if "SWEET SIGILL-NOPANIC" in s:
    print("0279 already present")
    sys.exit(0)

old = '\t\t\tpanic("SWEET SIGILL: pc %#llx instr %08x esr %#x ec %u far %#llx\\n%s%s%s",'
if old not in s:
    sys.exit("0279: sigill panic not found")

new = ('\t\t\t/* SWEET SIGILL-NOPANIC (0279): keep the kernel alive and let\n'
       '\t\t\t * the process take the SIGILL, so the console shows whether\n'
       '\t\t\t * init survives or the fault was terminal. */\n'
       '\t\t\tprintf("SWEET SIGILL: pc %#llx instr %08x esr %#x ec %u far %#llx\\n",\n'
       '\t\t\t    (unsigned long long)get_saved_state_pc(state), instr, esr,\n'
       '\t\t\t    (unsigned)class, (unsigned long long)far);\n'
       '\t\t\tprintf("%s%s%s", sweet_wrline, sweet_sigpa, sweet_zpage);')

s = s.replace(old, new, 1)
with io.open(path, "w", encoding="utf-8", newline="") as f:
    f.write(s)
print("0279 injected")
PY
