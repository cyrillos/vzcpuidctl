#ifndef VZCPUIDCTL_FPU_H__
#define VZCPUIDCTL_FPU_H__

#include <stdint.h>

#include "compiler.h"

#define FP_MIN_ALIGN_BYTES		64
#define FXSAVE_ALIGN_BYTES		16

#define FP_XSTATE_MAGIC1		0x46505853U
#define FP_XSTATE_MAGIC2		0x46505845U
#define FP_XSTATE_MAGIC2_SIZE		sizeof(FP_XSTATE_MAGIC2)

#define XSTATE_FP			0x1
#define XSTATE_SSE			0x2
#define XSTATE_YMM			0x4

#define FXSAVE_SIZE			512
#define XSAVE_SIZE			4096

#define XSAVE_HDR_SIZE			64
#define XSAVE_HDR_OFFSET		FXSAVE_SIZE

#define XSAVE_YMM_SIZE			256
#define XSAVE_YMM_OFFSET		(XSAVE_HDR_SIZE + XSAVE_HDR_OFFSET)

/*
 * List of XSAVE features Linux knows about:
 */
enum xfeature {
	XFEATURE_FP,
	XFEATURE_SSE,
	/*
	 * Values above here are "legacy states".
	 * Those below are "extended states".
	 */
	XFEATURE_YMM,
	XFEATURE_BNDREGS,
	XFEATURE_BNDCSR,
	XFEATURE_OPMASK,
	XFEATURE_ZMM_Hi256,
	XFEATURE_Hi16_ZMM,
	XFEATURE_PT,
	XFEATURE_PKRU,
	XFEATURE_HDC,

	XFEATURE_MAX,
};

#define XSTATE_CPUID			0x0000000d

#define XFEATURE_MASK_FP		(1 << XFEATURE_FP)
#define XFEATURE_MASK_SSE		(1 << XFEATURE_SSE)
#define XFEATURE_MASK_YMM		(1 << XFEATURE_YMM)
#define XFEATURE_MASK_BNDREGS		(1 << XFEATURE_BNDREGS)
#define XFEATURE_MASK_BNDCSR		(1 << XFEATURE_BNDCSR)
#define XFEATURE_MASK_OPMASK		(1 << XFEATURE_OPMASK)
#define XFEATURE_MASK_ZMM_Hi256		(1 << XFEATURE_ZMM_Hi256)
#define XFEATURE_MASK_Hi16_ZMM		(1 << XFEATURE_Hi16_ZMM)
#define XFEATURE_MASK_PT		(1 << XFEATURE_PT)
#define XFEATURE_MASK_PKRU		(1 << XFEATURE_PKRU)
#define XFEATURE_MASK_HDC		(1 << XFEATURE_HDC)
#define XFEATURE_MASK_MAX		(1 << XFEATURE_MAX)

#define XFEATURE_MASK_FPSSE		(XFEATURE_MASK_FP | XFEATURE_MASK_SSE)
#define XFEATURE_MASK_AVX512		(XFEATURE_MASK_OPMASK | XFEATURE_MASK_ZMM_Hi256 | XFEATURE_MASK_Hi16_ZMM)

#define FIRST_EXTENDED_XFEATURE		XFEATURE_YMM

/* Supervisor features */
#define XFEATURE_MASK_SUPERVISOR	(XFEATURE_MASK_PT | XFEATURE_MASK_HDC)

/* All currently supported features */
#define XCNTXT_MASK							  \
	(XFEATURE_MASK_FP		| XFEATURE_MASK_SSE		| \
	 XFEATURE_MASK_YMM		| XFEATURE_MASK_OPMASK		| \
	 XFEATURE_MASK_ZMM_Hi256	| XFEATURE_MASK_Hi16_ZMM	| \
	 XFEATURE_MASK_PKRU		| XFEATURE_MASK_BNDREGS		| \
	 XFEATURE_MASK_BNDCSR)

struct fpx_sw_bytes {
	uint32_t			magic1;
	uint32_t			extended_size;
	uint64_t			xstate_bv;
	uint32_t			xstate_size;
	uint32_t			padding[7];
};

struct i387_fxsave_struct {
	uint16_t			cwd; /* Control Word			*/
	uint16_t			swd; /* Status Word			*/
	uint16_t			twd; /* Tag Word			*/
	uint16_t			fop; /* Last Instruction Opcode		*/
	union {
		struct {
			uint64_t	rip; /* Instruction Pointer		*/
			uint64_t	rdp; /* Data Pointer			*/
		};
		struct {
			uint32_t	fip; /* FPU IP Offset			*/
			uint32_t	fcs; /* FPU IP Selector			*/
			uint32_t	foo; /* FPU Operand Offset		*/
			uint32_t	fos; /* FPU Operand Selector		*/
		};
	};
	uint32_t			mxcsr;		/* MXCSR Register State */
	uint32_t			mxcsr_mask;	/* MXCSR Mask		*/

	/* 8*16 bytes for each FP-reg = 128 bytes				*/
	uint32_t			st_space[32];

	/* 16*16 bytes for each XMM-reg = 256 bytes				*/
	uint32_t			xmm_space[64];

	uint32_t			padding[12];

	union {
		uint32_t		padding1[12];
		uint32_t		sw_reserved[12];
	};

} __aligned(FXSAVE_ALIGN_BYTES);

struct xsave_hdr_struct {
	uint64_t			xstate_bv;
	uint64_t			xcomp_bv;
	uint64_t			reserved[6];
};

/*
 * xstate_header.xcomp_bv[63] indicates that the extended_state_area
 * is in compacted format.
 */
#define XCOMP_BV_COMPACTED_FORMAT	((uint64_t)1 << 63)

/*
 * State component 2:
 *
 * There are 16x 256-bit AVX registers named YMM0-YMM15.
 * The low 128 bits are aliased to the 16 SSE registers (XMM0-XMM15)
 * and are stored in 'struct fxregs_state::xmm_space[]' in the
 * "legacy" area.
 *
 * The high 128 bits are stored here.
 */
struct ymmh_struct {
	uint32_t                        ymmh_space[64];
};

/* Intel MPX support: */

struct mpx_bndreg {
	uint64_t			lower_bound;
	uint64_t			upper_bound;
};

/*
 * State component 3 is used for the 4 128-bit bounds registers
 */
struct mpx_bndreg_state {
	struct mpx_bndreg		bndreg[4];
};

/*
 * State component 4 is used for the 64-bit user-mode MPX
 * configuration register BNDCFGU and the 64-bit MPX status
 * register BNDSTATUS.  We call the pair "BNDCSR".
 */
struct mpx_bndcsr {
	uint64_t			bndcfgu;
	uint64_t			bndstatus;
};

/*
 * The BNDCSR state is padded out to be 64-bytes in size.
 */
struct mpx_bndcsr_state {
	union {
		struct mpx_bndcsr	bndcsr;
		uint8_t			pad_to_64_bytes[64];
	};
};

/* AVX-512 Components: */

/*
 * State component 5 is used for the 8 64-bit opmask registers
 * k0-k7 (opmask state).
 */
struct avx_512_opmask_state {
	uint64_t			opmask_reg[8];
};

/*
 * State component 6 is used for the upper 256 bits of the
 * registers ZMM0-ZMM15. These 16 256-bit values are denoted
 * ZMM0_H-ZMM15_H (ZMM_Hi256 state).
 */
struct avx_512_zmm_uppers_state {
	uint64_t			zmm_upper[16 * 4];
};

/*
 * State component 7 is used for the 16 512-bit registers
 * ZMM16-ZMM31 (Hi16_ZMM state).
 */
struct avx_512_hi16_state {
	uint64_t			hi16_zmm[16 * 8];
};

/*
 * State component 9: 32-bit PKRU register.  The state is
 * 8 bytes long but only 4 bytes is used currently.
 */
struct pkru_state {
	uint32_t			pkru;
	uint32_t			pad;
};

/*
 * This is our most modern FPU state format, as saved by the XSAVE
 * and restored by the XRSTOR instructions.
 *
 * It consists of a legacy fxregs portion, an xstate header and
 * subsequent areas as defined by the xstate header. Not all CPUs
 * support all the extensions, so the size of the extended area
 * can vary quite a bit between CPUs.
 *
 *
 * One page should be enough for the whole xsave state.
 */
#define EXTENDED_STATE_AREA_SIZE	(4096 - sizeof(struct i387_fxsave_struct) - sizeof(struct xsave_hdr_struct))

/*
 * cpu requires it to be 64 byte aligned
 */
struct xsave_struct {
	struct i387_fxsave_struct	i387;
	struct xsave_hdr_struct		xsave_hdr;
	union {
		/*
		 * This ymmh is unndeed, for
		 * backward compatibility.
		 */
		struct ymmh_struct	ymmh;
		uint8_t			extended_state_area[EXTENDED_STATE_AREA_SIZE];
	};
} __aligned(FP_MIN_ALIGN_BYTES);

#endif /* VZCPUIDCTL_FPU_H__ */
