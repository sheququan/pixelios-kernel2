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

			/* SWEET (0277): R167 proved the formula.  Rewriting the
			 * two pages around the bad offset (1220 slots) moved the
			 * panic from LR 0x1029a2b04 to 0x1005cab04, so
			 * 0x180000000 + target30 + slide is the correct rebase and
			 * these slots are on launchd's path.  Now do it for every
			 * page of the two data mappings: .27.dylddata's __DATA is
			 * ~7.1M unapplied rebase words and launchd dies on the
			 * first one it reads.  Print progress every 512 pages so
			 * the watchdog sees activity. */
			{
				extern uint64_t pmap_find_pa(pmap_t, addr64_t);
				extern pmap_t current_pmap(void);
				extern void ml_phys_write_double_64(addr64_t, unsigned long long);
				static char sweet_pg[0x4000];
				uint32_t k;
				uint64_t uva[8], usz[8], ufoff[8];
				uint32_t hmo = 0, hmc = 0;
				uint64_t fixed = 0, pages = 0, skipped = 0;

				for (k = 0; k < 8; k++) { uva[k] = 0; usz[k] = 0; ufoff[k] = 0; }
				bzero(sweet_fix_disk, sizeof(sweet_fix_disk));
				{
					daddr64_t hbpn = 0;
					size_t hrun = 0;
					int hse = VNOP_BLOCKMAP(sfmp->vp, 0, 0x400,
					    &hbpn, &hrun, NULL, VNODE_READ,
					    vfs_context_current());
					if (hse == 0 && hbpn >= 0 &&
					    sweet_ufs_read_at(hbpn, 0x400,
					    sweet_fix_disk) == 0) {
						hmo = *(uint32_t *)(sweet_fix_disk + 0x10);
						hmc = *(uint32_t *)(sweet_fix_disk + 0x14);
						if (hmc > 8) hmc = 8;
						for (k = 0; k < hmc; k++) {
							uva[k] = *(uint64_t *)(sweet_fix_disk + hmo + k * 32);
							usz[k] = *(uint64_t *)(sweet_fix_disk + hmo + k * 32 + 8);
							ufoff[k] = *(uint64_t *)(sweet_fix_disk + hmo + k * 32 + 16);
						}
					}
				}
				for (k = 0; k < hmc; k++) {
					printf("SWEET MAP27: k %u unslid %#llx slid %#llx foff %#llx size %#llx slide %#llx\n",
					    k, (unsigned long long)uva[k],
					    (unsigned long long)sfmp->mappings[k].sms_address,
					    (unsigned long long)ufoff[k],
					    (unsigned long long)usz[k],
					    (unsigned long long)(sfmp->mappings[k].sms_address - uva[k]));
				}

				/* map1 and map2 are the data segments (prot 3/1, 3/3) */
				for (k = 1; k < hmc && k <= 2; k++) {
					uint64_t pslide = sfmp->mappings[k].sms_address - uva[k];
					uint64_t sz = usz[k];
					uint64_t off;

					for (off = 0; off + 0x4000 <= sz; off += 0x4000) {
						user_addr_t pva = (user_addr_t)
						    (sfmp->mappings[k].sms_address + off);
						uint32_t o;

						bzero(sweet_pg, sizeof(sweet_pg));
						if (copyin(pva, sweet_pg, sizeof(sweet_pg)) != 0) {
							skipped++;
							continue;
						}
						for (o = 0; o + 8 <= 0x4000; o += 8) {
							uint64_t v = *(uint64_t *)(sweet_pg + o);
							uint64_t t, np, pa;

							if (v == 0) continue;
							if ((v >> 63) & 1) continue;
							if (((v >> 51) & 0xfff) != 0) continue;
							if (((v >> 32) & 0xffff) != 0x201 &&
							    ((v >> 32) & 0xffff) != 0x601) continue;
							if (((v >> 48) & 7) != 0) continue;
							t = v & 0x3fffffffULL;
							if (t == 0) continue;
							np = 0x180000000ULL + t + pslide;
							if (np < 0x180000000ULL || np >= 0x210000000ULL)
								continue;
							pa = pmap_find_pa(current_pmap(),
							    (addr64_t)(pva + o));
							if (pa == 0) continue;
							ml_phys_write_double_64(
							    (addr64_t)(pa +
							    (((uint64_t)(pva + o)) & 0x3fffULL)),
							    (unsigned long long)np);
							fixed++;
						}
						pages++;
						if ((pages & 0x1ff) == 0) {
							printf("SWEET FULLFIX: pages %llu fixed %llu skip %llu\n",
							    (unsigned long long)pages,
							    (unsigned long long)fixed,
							    (unsigned long long)skipped);
						}
					}
				}
				printf("SWEET FULLFIX: DONE pages %llu fixed %llu skip %llu\n",
				    (unsigned long long)pages,
				    (unsigned long long)fixed,
				    (unsigned long long)skipped);
			}
		}
	}

'''

s = s.replace(anchor, anchor.replace("\tvnode_put(rdir_vp);", probe + "\tvnode_put(rdir_vp);"), 1)
with io.open(path, "w", encoding="utf-8", newline="") as f:
    f.write(s)
print("0274 probe injected")
PY
