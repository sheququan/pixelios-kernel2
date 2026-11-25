#!/usr/bin/env bash
# SWEET (0278): lazy chained-fixup repair for the dyld shared cache.
#
# F232: basePointers for DYLD_CHAINED_PTR_64_KERNEL_CACHE is 0x180000000,
# verified 100% against the 2710 dylibs in imagesText.
# F236: rewriting 1220 slots around foff 0xddc138 moved launchd's panic LR
# from 0x1029a2b04 to 0x1005cab04, so base+target30+slide is the right value.
# F237: doing it for every page up-front is far too slow (91 KB/s), so instead
# register the four mappings of .27.dylddata at map time and repair a page
# inside hfs_vnop_pagein() right after cluster_pagein() filled it - one page
# of work per fault, always in step with launchd.
set -eu

python3 - <<'PY'
import io
import sys

# ---------- 1) vm_unix.c : registry + repair helper ----------
path = "bsd/vm/vm_unix.c"
with io.open(path, "r", encoding="utf-8", newline="") as f:
    s = f.read()

if "sweet_cache_fix_page" in s:
    print("0278 already present")
    sys.exit(0)

fn_anchor = "static int\n_shared_region_map_and_slide(\n\tstruct proc                         *p,"
if fn_anchor not in s:
    sys.exit("0278: function anchor not found")

helper = r'''/*
 * SWEET (0278): lazy rebase for the dyld shared cache data segment.
 *
 * The cache carries DYLD_CHAINED_PTR_64_KERNEL_CACHE words that nobody
 * ever rebases: the cache has no slide info, so dyld4 skips
 * fixupDataPages() entirely (F225/F229).  Doing the whole segment up
 * front is too slow to beat launchd (F237), so register the mappings of
 * .27.dylddata here and repair each page from hfs_vnop_pagein() as it is
 * faulted in.
 */
struct sweet_cache_map {
	void     *vp;
	uint64_t  slid_base;
	uint64_t  file_offset;
	uint64_t  size;
	uint64_t  slide;
};

struct sweet_cache_map sweet_cache_maps[16];
int sweet_cache_map_count;

void
sweet_cache_fix_page(void *vp, uint64_t foff)
{
	extern uint64_t pmap_find_pa(pmap_t, addr64_t);
	extern pmap_t current_pmap(void);
	extern void ml_phys_write_double_64(addr64_t, unsigned long long);
	extern unsigned long long ml_phys_read_double_64(addr64_t);
	int i;

	for (i = 0; i < sweet_cache_map_count; i++) {
		struct sweet_cache_map *m = &sweet_cache_maps[i];
		uint64_t va, pa, o;

		if (m->vp != vp) {
			continue;
		}
		if (foff < m->file_offset ||
		    foff >= m->file_offset + m->size) {
			continue;
		}
		va = m->slid_base + (foff - m->file_offset);
		/*
		 * Read the physical page directly: a copyin() here would go
		 * back into the VM while this very page-in still holds the
		 * UPL, which deadlocks on SWEET.
		 */
		pa = pmap_find_pa(current_pmap(), (addr64_t)va);
		if (pa == 0) {
			return;
		}
		for (o = 0; o < 0x4000; o += 8) {
			uint64_t v = ml_phys_read_double_64((addr64_t)(pa + o));
			uint64_t t, np;

			if (v == 0) {
				continue;
			}
			if ((v >> 63) & 1) {
				continue;
			}
			if (((v >> 51) & 0xfff) != 0) {
				continue;
			}
			if (((v >> 32) & 0xffff) != 0x201 &&
			    ((v >> 32) & 0xffff) != 0x601) {
				continue;
			}
			if (((v >> 48) & 7) != 0) {
				continue;
			}
			t = v & 0x3fffffffULL;
			if (t == 0) {
				continue;
			}
			np = 0x180000000ULL + t + m->slide;
			if (np < 0x180000000ULL || np >= 0x210000000ULL) {
				continue;
			}
			ml_phys_write_double_64((addr64_t)(pa + o),
			    (unsigned long long)np);
		}
		return;
	}
}

'''
s = s.replace(fn_anchor, helper + fn_anchor, 1)

# ---------- 2) vm_unix.c : register .27.dylddata at map time ----------
probe_anchor = """\tif (error == 0 && (p->p_flag & P_NOSHLIB)) {
\t\tOSBitAndAtomic(~((uint32_t)P_NOSHLIB), &p->p_flag);
\t}

\tvnode_put(rdir_vp);
"""
if probe_anchor not in s:
    sys.exit("0278: probe anchor not found")

probe = r'''	/*
	 * SWEET (0278): remember .27.dylddata's mappings so the page-in
	 * path can rebase each page lazily.  unslid VAs come from the file
	 * header, the slide is (mapped VA - unslid VA); every mapping of
	 * this file shares one slide (F236).
	 */
	{
		extern int sweet_ufs_read_at(daddr64_t blkno, uint32_t bytes,
		    void *dst);
		static char sweet_hdr[0x400];
		uint32_t hmo = 0, hmc = 0, k;

		if (files_count != 0 && sr_file_mappings != NULL) {
			for (k = 0; k < files_count && k < 46; k++) {
				struct _sr_file_mappings *sfmp = &sr_file_mappings[k];
				daddr64_t hbpn = 0;
				size_t hrun = 0;
				int hse;

				if (sfmp->vp == NULL || sfmp->mappings == NULL ||
				    sfmp->file_size != 0xb270000ULL) {
					continue;
				}
				bzero(sweet_hdr, sizeof(sweet_hdr));
				hse = VNOP_BLOCKMAP(sfmp->vp, 0, 0x400, &hbpn,
				    &hrun, NULL, VNODE_READ, vfs_context_current());
				if (hse != 0 || hbpn < 0 ||
				    sweet_ufs_read_at(hbpn, 0x400, sweet_hdr) != 0) {
					continue;
				}
				hmo = *(uint32_t *)(sweet_hdr + 0x10);
				hmc = *(uint32_t *)(sweet_hdr + 0x14);
				if (hmc > 8) {
					hmc = 8;
				}
				{
					uint32_t j;
					for (j = 0; j < hmc &&
					    sweet_cache_map_count < 16; j++) {
						struct sweet_cache_map *m;
						uint64_t uva, usz, ufoff;

						if (j >= sfmp->mappings_count) {
							break;
						}
						uva = *(uint64_t *)(sweet_hdr + hmo + j * 32);
						usz = *(uint64_t *)(sweet_hdr + hmo + j * 32 + 8);
						ufoff = *(uint64_t *)(sweet_hdr + hmo + j * 32 + 16);
						if (usz < 0x4000) {
							continue;
						}
						m = &sweet_cache_maps[sweet_cache_map_count++];
						m->vp = sfmp->vp;
						m->slid_base = sfmp->mappings[j].sms_address;
						m->file_offset = ufoff;
						m->size = usz;
						m->slide = sfmp->mappings[j].sms_address - uva;
					}
				}
				printf("SWEET CACHEMAP: files %u maps %d\n",
				    files_count, sweet_cache_map_count);
				break;
			}
		}
	}
'''
s = s.replace(probe_anchor,
              probe + probe_anchor, 1)

with io.open(path, "w", encoding="utf-8", newline="") as f:
    f.write(s)
print("0278 vm_unix.c injected")

# ---------- 3) hfs_readwrite.c : repair each page after cluster_pagein ----------
path2 = "bsd/sweet_hfs/core/hfs_readwrite.c"
with io.open(path2, "r", encoding="utf-8", newline="") as f:
    h = f.read()

if "sweet_cache_fix_page" in h:
    print("0278 hfs already present")
    sys.exit(0)

lines = h.split("\n")
idx = [i for i, l in enumerate(lines) if "cluster_pagein(vp, upl, offset" in l]
if len(idx) != 1:
    sys.exit("0278: cluster_pagein line not found (%d)" % len(idx))
i = idx[0]
ins = [
    "",
    "\t\t/*",
    "\t\t * SWEET (0278): the shared cache data pages carry chained",
    "\t\t * rebase words that dyld never applies on this no-slide",
    "\t\t * cache.  Repair this page right after it was filled; the",
    "\t\t * registry is empty unless the file is .27.dylddata.",
    "\t\t */",
    "\t\tif (error == 0) {",
    "\t\t\textern void sweet_cache_fix_page(void *vp, uint64_t foff);",
    "",
    "\t\t\tsweet_cache_fix_page(vp, (uint64_t)f_offset);",
    "\t\t}",
]
lines[i + 1:i + 1] = ins
h = "\n".join(lines)
with io.open(path2, "w", encoding="utf-8", newline="") as f:
    f.write(h)
print("0278 hfs_readwrite.c injected")
PY
