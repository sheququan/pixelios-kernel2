#!/usr/bin/env bash
# SWEET (0278): apply the shared cache's own slide info, lazily, at page-in.
#
# F161/F235 said the cache had no slide info: that was only true of the main
# dyld_shared_cache_arm64 file.  Every .NN.dylddata subcache carries a
# dyld_cache_slide_info2 blob for its data mappings (F248):
#
#   .27.dylddata map1  slide info foff 0xb207c08 size 0xa788  21424 pages
#   .27.dylddata map2  slide info foff 0xb1fc000 size 0xbc08  24048 pages
#
# dyld never applies them because the kernel drops the slide requests, so the
# slots keep the v2 encoding: bits 40..55 hold the delta to the next slot,
# every other bit is the *unslid* pointer (F249).  The old heuristic in this
# patch (base + target30, only slots whose delta happened to be 8 or 24) got
# both halves wrong: 46% of slots were skipped and 46% of the rewritten ones
# dropped bit 30/31 of the pointer.  This version decodes the real blob.
#
# The blob's page_starts array is read from the file once, at map time, and
# each 4 KiB cache page is repaired right after cluster_pagein() filled it.
set -eu

python3 - <<'PY'
import io
import sys

# ---------- 1) vm_unix.c : slide-info registry + decoder ----------
path = "bsd/vm/vm_unix.c"
with io.open(path, "r", encoding="utf-8", newline="") as f:
    s = f.read()

if "sweet_cache_fix_page" in s:
    print("0278 already present")
    sys.exit(0)

import re
fn_match = re.search(r"static int\r?\n_shared_region_map_and_slide\(", s)
if fn_match is None:
    sys.exit("0278: function anchor not found")

helper = r'''/*
 * SWEET (0278): lazy rebase for the dyld shared cache data mappings.
 *
 * The cache is stored unslid and encodes every interior pointer as
 * {delta:16 at bit 40, pointer:48 elsewhere} per dyld_cache_slide_info2.
 * dyld would apply that blob itself if the kernel passed the slide
 * mappings through; it does not, so the kernel decodes the blob here and
 * repairs a 4 KiB cache page as soon as cluster_pagein() filled it.
 */
struct sweet_cache_map {
	void     *vp;
	uint64_t  slid_base;
	uint64_t  file_offset;
	uint64_t  size;
	uint64_t  slide;
	uint32_t  page_size;
	uint32_t  page_count;
	uint64_t  delta_mask;
	uint64_t  value_add;
	uint16_t *starts;
	uint16_t *extras;
	uint32_t  extras_count;
};

struct sweet_cache_map sweet_cache_maps[16];
int sweet_cache_map_count;

/* SWEET (R177): load bases of the two boot images, set at exec and read by
 * the SIGILL panic so a stray pc can be attributed to an image on screen. */
uint64_t sweet_dyld_base;
uint64_t sweet_main_base;
uint64_t sweet_entry;
uint32_t sweet_entry_word;

static int
sweet_cache_read(void *vp, uint64_t off, uint32_t len, void *dst)
{
	int resid = 0;
	int err;

	err = vn_rdwr(UIO_READ, (struct vnode *)vp, (caddr_t)dst, (int)len,
	    (off_t)off, UIO_SYSSPACE, IO_NOCACHE, kauth_cred_get(), &resid,
	    current_proc());
	if (err != 0 || resid != 0) {
		return -1;
	}
	return 0;
}

static void
sweet_cache_register(void *vp, uint64_t unslid_va, uint64_t slid_va,
    uint64_t foff, uint64_t size, uint64_t slide_off, uint64_t slide_size)
{
	struct sweet_cache_map *m;
	uint8_t hdr[0x28];
	uint32_t ver, psz, pso, psc, peo, pec;

	if (slide_off == 0 || slide_size < 0x28 || size < 0x1000 ||
	    sweet_cache_map_count >= 16) {
		return;
	}
	if (sweet_cache_read(vp, slide_off, 0x28, hdr) != 0) {
		return;
	}
	ver = *(uint32_t *)(void *)(hdr + 0);
	psz = *(uint32_t *)(void *)(hdr + 4);
	pso = *(uint32_t *)(void *)(hdr + 8);
	psc = *(uint32_t *)(void *)(hdr + 12);
	peo = *(uint32_t *)(void *)(hdr + 16);
	pec = *(uint32_t *)(void *)(hdr + 20);
	if (ver != 2 || psz == 0 || psc == 0 || psc > 0x40000 ||
	    *(uint64_t *)(void *)(hdr + 24) == 0) {
		printf("SWEET SLIDE: skip ver %u psz %u cnt %u\n", ver, psz, psc);
		return;
	}
	m = &sweet_cache_maps[sweet_cache_map_count];
	m->vp = vp;
	m->file_offset = foff;
	m->size = size;
	m->slid_base = slid_va;
	m->slide = slid_va - unslid_va;
	m->page_size = psz;
	m->page_count = psc;
	m->delta_mask = *(uint64_t *)(void *)(hdr + 24);
	m->value_add = *(uint64_t *)(void *)(hdr + 32);
	m->starts = kalloc_data((vm_size_t)psc * 2, Z_WAITOK);
	if (m->starts == NULL) {
		return;
	}
	if (sweet_cache_read(vp, slide_off + pso, psc * 2, m->starts) != 0) {
		kfree_data(m->starts, (vm_size_t)psc * 2);
		m->starts = NULL;
		return;
	}
	if (pec != 0 && pec < 0x4000) {
		m->extras = kalloc_data((vm_size_t)pec * 2, Z_WAITOK);
		if (m->extras != NULL &&
		    sweet_cache_read(vp, slide_off + peo, pec * 2,
		    m->extras) == 0) {
			m->extras_count = pec;
		}
	}
	sweet_cache_map_count++;
}

static void
sweet_cache_fix_chain(uint64_t page_pa, uint32_t start,
    struct sweet_cache_map *m)
{
	extern unsigned long long ml_phys_read_double_64(addr64_t);
	extern void ml_phys_write_double_64(addr64_t, unsigned long long);
	uint64_t mask = m->delta_mask;
	uint64_t vmask = ~mask;
	uint32_t shift = (uint32_t)__builtin_ctzll(mask) - 2;
	uint32_t off = start * 4;
	uint64_t delta = 1;
	int guard = 0;

	while (delta != 0 && guard++ < 1024) {
		uint64_t raw, val, np;

		if (off + 8 > m->page_size) {
			break;
		}
		raw = ml_phys_read_double_64((addr64_t)(page_pa + off));
		delta = (raw & mask) >> shift;
		val = raw & vmask;
		if (val != 0) {
			np = val + m->value_add + m->slide;
			ml_phys_write_double_64((addr64_t)(page_pa + off), np);
		}
		off += (uint32_t)delta;
	}
}

void
sweet_cache_fix_page(void *vp, uint64_t foff, void *upl, uint32_t pl_offset)
{
	extern ppnum_t upl_phys_page(upl_page_info_t *upl, int index);
	int i;

	for (i = 0; i < sweet_cache_map_count; i++) {
		struct sweet_cache_map *m = &sweet_cache_maps[i];
		upl_page_info_t *pl;
		uint64_t pa, rel, first;
		uint32_t idx, nsub, s;
		ppnum_t pp;

		if (m->vp != vp || m->starts == NULL) {
			continue;
		}
		if (foff < m->file_offset ||
		    foff >= m->file_offset + m->size) {
			continue;
		}
		/*
		 * Take the physical page from the UPL that cluster_pagein()
		 * just filled.  Looking it up through current_pmap() is wrong
		 * here: the page-in may run on a kernel thread, whose pmap has
		 * nothing to do with this VA, and a stray write through a
		 * wrong pa corrupts the kernel (R173).
		 */
		pl = UPL_GET_INTERNAL_PAGE_LIST((upl_t)upl);
		if (pl == NULL) {
			return;
		}
		idx = pl_offset >> PAGE_SHIFT;
		pp = upl_phys_page(pl, (int)idx);
		if (pp == 0) {
			return;
		}
		pa = (uint64_t)pp << PAGE_SHIFT;
		rel = foff - m->file_offset;
		first = rel / m->page_size;
		nsub = (uint32_t)(PAGE_SIZE / m->page_size);
		if (nsub == 0 || nsub > 8) {
			nsub = 1;
		}
		for (s = 0; s < nsub; s++) {
			uint32_t pi = (uint32_t)first + s;
			uint16_t st;

			if (pi >= m->page_count) {
				break;
			}
			st = m->starts[pi];
			if (st == 0 || (st & 0xC000) == 0x4000) {
				continue;
			}
			if (st & 0x8000) {
				uint32_t ei = st & 0x3FFF;

				while (m->extras != NULL &&
				    ei < m->extras_count) {
					uint16_t e = m->extras[ei];

					sweet_cache_fix_chain(pa +
					    (uint64_t)s * m->page_size,
					    e & 0x3FFF, m);
					if (e & 0x8000) {
						break;
					}
					ei++;
				}
			} else {
				sweet_cache_fix_chain(pa +
				    (uint64_t)s * m->page_size, st, m);
			}
		}
		return;
	}
}
'''
s = s[:fn_match.start()] + helper + s[fn_match.start():]

# ---------- 2) vm_unix.c : register every data mapping that has slide info ----------
probe_match = re.search(
    r"\tif \(error == 0 && \(p->p_flag & P_NOSHLIB\)\) \{", s)
if probe_match is None:
    sys.exit("0278: probe anchor not found")

probe = r'''	/*
	 * SWEET (0278): register each data mapping that carries slide info
	 * so the page-in path can decode it lazily.  The header gives, per
	 * mapping, the unslid VA/size/file offset and the file offset of the
	 * dyld_cache_slide_info2 blob that covers it; the slide is the delta
	 * between the header VA and the VA the kernel mapped it at.
	 */
	{
		static char sweet_hdr[0x400];
		uint32_t k;

		if (files_count != 0 && sr_file_mappings != NULL) {
			for (k = 0; k < files_count && k < 46; k++) {
				struct _sr_file_mappings *sfmp = &sr_file_mappings[k];
				uint32_t hmo, hmc, hso, hsc, j;

				if (sfmp->vp == NULL || sfmp->mappings == NULL) {
					continue;
				}
				bzero(sweet_hdr, sizeof(sweet_hdr));
				if (sweet_cache_read(sfmp->vp, 0, 0x400,
				    sweet_hdr) != 0) {
					continue;
				}
				hmo = *(uint32_t *)(void *)(sweet_hdr + 0x10);
				hmc = *(uint32_t *)(void *)(sweet_hdr + 0x14);
				hso = *(uint32_t *)(void *)(sweet_hdr + 0x138);
				hsc = *(uint32_t *)(void *)(sweet_hdr + 0x13c);
				if (hmc > 8 || hsc > hmc || hso < 0x100 ||
				    hso > 0x300) {
					continue;
				}
				for (j = 0; j < hmc && j < sfmp->mappings_count;
				    j++) {
					uint64_t uva, usz, ufoff;
					uint64_t so, ss;

					if (j >= hsc) {
						break;
					}
					uva = *(uint64_t *)(void *)(sweet_hdr + hmo + j * 32);
					usz = *(uint64_t *)(void *)(sweet_hdr + hmo + j * 32 + 8);
					ufoff = *(uint64_t *)(void *)(sweet_hdr + hmo + j * 32 + 16);
					so = *(uint64_t *)(void *)(sweet_hdr + hso + j * 56 + 24);
					ss = *(uint64_t *)(void *)(sweet_hdr + hso + j * 56 + 32);
					if (so == 0 || ss == 0) {
						continue;
					}
					sweet_cache_register(sfmp->vp, uva,
					    sfmp->mappings[j].sms_address, ufoff,
					    usz, so, ss);
				}
			}
			if (sweet_cache_map_count != 0) {
				printf("SWEET SLIDEMAP: files %u maps %d\n",
				    files_count, sweet_cache_map_count);
			}
		}
	}
'''
s = s[:probe_match.start()] + probe + s[probe_match.start():]

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
    "\t\t * SWEET (0278): the shared cache data pages carry slide-info",
    "\t\t * rebase words that dyld never applies on this rootfs.",
    "\t\t * Decode this page right after it was filled; the registry is",
    "\t\t * empty unless the file is a dylddata subcache with slide info.",
    "\t\t */",
    "\t\tif (error == 0) {",
    "\t\t\textern void sweet_cache_fix_page(void *vp, uint64_t foff,",
    "\t\t\t    void *upl, uint32_t pl_offset);",
    "",
    "\t\t\tsweet_cache_fix_page(vp, (uint64_t)f_offset,",
    "\t\t\t    (void *)upl, (uint32_t)offset);",
    "\t\t}",
]
lines[i + 1:i + 1] = ins
h = "\n".join(lines)
with io.open(path2, "w", encoding="utf-8", newline="") as f:
    f.write(h)
print("0278 hfs_readwrite.c injected")
PY
