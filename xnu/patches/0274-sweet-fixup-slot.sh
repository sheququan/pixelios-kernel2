#!/usr/bin/env bash
# SWEET (0274): inject the .27.dylddata fixup-slot probe without relying on
# patch line numbers (the 0271/0272 hunks keep moving).  Runs before the .patch
# files, so it anchors on an upstream line that none of them change.
set -eu
# dxb-build.sh has already cd'd us to ${WORK_DIR}/xnu.

python3 - <<'PY'
import io
import sys

path = "bsd/vm/vm_unix.c"
with io.open(path, "r", encoding="utf-8", newline="") as f:
    s = f.read()

if "SWEET FIXFILE" in s:
    print("0274 probe already present")
    sys.exit(0)

anchor = """\tif (error == 0 && (p->p_flag & P_NOSHLIB)) {
\t\tOSBitAndAtomic(~((uint32_t)P_NOSHLIB), &p->p_flag);
\t}

\tvnode_put(rdir_vp);
"""
if anchor not in s:
    sys.exit("0274: anchor not found in bsd/vm/vm_unix.c")

probe = r'''	/*
	 * SWEET (0274): F216 traced the bad branch target to file offset
	 * 0xddc138 of dyld_shared_cache_arm64.27.dylddata; the bytes there
	 * are an arm64e chained-fixup word, not a rebased pointer.  Print the
	 * file's mappings, the on-disk words and the words user space got.
	 * Identical: fixups never ran.  Different: overwritten or rebased
	 * with a wrong base.  Disk words print first, so a wedge in copyin()
	 * still leaves the useful half on the screen.
	 */
	{
		static char sweet_fix_disk[4096];
		static const uint64_t sweet_fix_size = 0x000000000b270000ULL;
		static const off_t sweet_fix_foff = 0x0ddc138LL;
		uint32_t sweet_fix_i, sweet_fix_j;
		uint64_t sweet_fix_new, sweet_fix_pa;
		int sweet_fix_put;

		for (sweet_fix_i = 0; sweet_fix_i < files_count &&
		    sweet_fix_i < 46; sweet_fix_i++) {
			struct _sr_file_mappings *sfmp = &sr_file_mappings[sweet_fix_i];
			uint32_t sweet_fix_dw[8], sweet_fix_mw[8];
			struct shared_file_mapping_slide_np *smp;
			daddr64_t sbpn = 0;
			size_t srun = 0;
			user_addr_t sweet_fix_va = 0;
			int se, found = 0, cerr;

			if (sfmp->mappings_count == 0 || sfmp->vp == NULL ||
			    sfmp->file_size != sweet_fix_size) {
				continue;
			}
			printf("SWEET FIXFILE: f %u size %#llx maps %u\n",
			    sweet_fix_i, (unsigned long long)sfmp->file_size,
			    sfmp->mappings_count);
			for (sweet_fix_j = 0; sweet_fix_j < sfmp->mappings_count &&
			    sweet_fix_j < 16; sweet_fix_j++) {
				smp = &sfmp->mappings[sweet_fix_j];
				printf("SWEET FIXMAP: j %u va %#llx size %#llx foff %#llx prot %#x/%#x\n",
				    sweet_fix_j,
				    (unsigned long long)smp->sms_address,
				    (unsigned long long)smp->sms_size,
				    (unsigned long long)smp->sms_file_offset,
				    smp->sms_init_prot, smp->sms_max_prot);
				if (smp->sms_file_offset <= (uint64_t)sweet_fix_foff &&
				    (uint64_t)sweet_fix_foff < smp->sms_file_offset + smp->sms_size) {
					sweet_fix_va = (user_addr_t)(smp->sms_address +
					    ((uint64_t)sweet_fix_foff - smp->sms_file_offset));
					found = 1;
				}
			}
			if (!found) {
				printf("SWEET FIXMAP: no mapping covers foff %#llx\n",
				    (unsigned long long)sweet_fix_foff);
				continue;
			}
			bzero(sweet_fix_dw, sizeof(sweet_fix_dw));
			se = VNOP_BLOCKMAP(sfmp->vp, sweet_fix_foff, 32, &sbpn,
			    &srun, NULL, VNODE_READ, vfs_context_current());
			if (se == 0 && sbpn >= 0 &&
			    sweet_ufs_read_at(sbpn, 4096, sweet_fix_disk) == 0) {
				bcopy(sweet_fix_disk, sweet_fix_dw,
				    sizeof(sweet_fix_dw));
			}
			printf("SWEET FIXDK: se %d bpn %#llx run %llu w %08x %08x %08x %08x\n",
			    se, (unsigned long long)sbpn,
			    (unsigned long long)srun, sweet_fix_dw[0],
			    sweet_fix_dw[1], sweet_fix_dw[2], sweet_fix_dw[3]);
			bzero(sweet_fix_mw, sizeof(sweet_fix_mw));
			cerr = copyin(sweet_fix_va, (char *)sweet_fix_mw,
			    sizeof(sweet_fix_mw));
			printf("SWEET FIXVA: va %#llx err %d w %08x %08x %08x %08x\n",
			    (unsigned long long)sweet_fix_va, cerr,
			    sweet_fix_mw[0], sweet_fix_mw[1],
			    sweet_fix_mw[2], sweet_fix_mw[3]);

			/* SWEET (0275 merged): one-slot diagnostic.  The raw word
			 * decodes as target30=0x1177e2d0, cacheLevel=2.  Try the
			 * shared-region base (0x180000000) as basePointers[2].
			 * copyout() wedges here (read-only page + broken COW on
			 * SWEET), so write the physical page directly like the
			 * exec fill path does. */
			{
				extern uint64_t pmap_find_pa(pmap_t, addr64_t);
				extern pmap_t current_pmap(void);
				extern void ml_phys_write_double_64(addr64_t, unsigned long long);
				uintptr_t sweet_fix_cv;

				sweet_fix_new = 0x000000019177e2d0ULL;
				sweet_fix_pa = pmap_find_pa(current_pmap(),
				    (addr64_t)sweet_fix_va);
				printf("SWEET FIXPA: pa %#llx\n",
				    (unsigned long long)sweet_fix_pa);
				if (sweet_fix_pa != 0) {
					ml_phys_write_double_64(
					    (addr64_t)(sweet_fix_pa +
					        ((uint64_t)sweet_fix_va & 0x3fffULL)),
					    (unsigned long long)sweet_fix_new);
					for (sweet_fix_cv = (uintptr_t)sweet_fix_va;
					    sweet_fix_cv < (uintptr_t)sweet_fix_va + 8;
					    sweet_fix_cv += 64) {
						__asm__ volatile("dc civac, %0" :: "r"(sweet_fix_cv) : "memory");
					}
					__asm__ volatile("dsb sy" ::: "memory");
					__asm__ volatile("ic ialluis" ::: "memory");
					__asm__ volatile("dsb sy" ::: "memory");
					__asm__ volatile("isb" ::: "memory");
					sweet_fix_put = 0;
				} else {
					sweet_fix_put = EFAULT;
				}
				printf("SWEET FIXPUT: err %d val %#llx\n", sweet_fix_put,
				    (unsigned long long)sweet_fix_new);
			}
		}
	}

'''

s = s.replace(anchor, anchor.replace("\tvnode_put(rdir_vp);", probe + "\tvnode_put(rdir_vp);"), 1)
with io.open(path, "w", encoding="utf-8", newline="") as f:
    f.write(s)
print("0274 probe injected")
PY
