/* Target-dependent code for 3DS. */

/* This uses code from GDB, which license is: */

/*
   Copyright (C) 2002-2017 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "gdbcore.h"
#include "target.h"
#include "osabi.h"
#include "xml-syscall.h"

#include "arch/arm.h"
#include "arch/arm-get-next-pcs.h"
#include "arm-tdep.h"

static const gdb_byte arm_3ds_arm_le_breakpoint[] = {0xff, 0x00, 0x00, 0xef};
static const gdb_byte arm_3ds_thumb_le_breakpoint[] = {0xff, 0xdf};

static CORE_ADDR
  arm_3ds_get_next_pcs_syscall_next_pc (struct arm_get_next_pcs *self);

/* Operation function pointers for get_next_pcs.  */
static struct arm_get_next_pcs_ops arm_3ds_get_next_pcs_ops = {
  arm_get_next_pcs_read_memory_unsigned_integer,
  arm_3ds_get_next_pcs_syscall_next_pc,
  arm_get_next_pcs_addr_bits_remove,
  arm_get_next_pcs_is_thumb,
  NULL,
};

static CORE_ADDR
arm_3ds_get_next_pcs_syscall_next_pc (struct arm_get_next_pcs *self)
{
  CORE_ADDR next_pc = 0;
  CORE_ADDR pc = regcache_read_pc (self->regcache);
  int is_thumb = arm_is_thumb (self->regcache);
  ULONGEST svc_number = 0;

  if (is_thumb)
    {
      next_pc = pc + 2;
    }
  else
    {
      next_pc = pc + 4;
    }

  /* Addresses for calling Thumb functions have the bit 0 set.  */
  if (is_thumb)
    next_pc = MAKE_THUMB_ADDR (next_pc);

  return next_pc;
}

static VEC (CORE_ADDR) *
arm_3ds_software_single_step (struct regcache *regcache)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  struct arm_get_next_pcs next_pcs_ctx;
  CORE_ADDR pc;
  int i;
  VEC (CORE_ADDR) *next_pcs = NULL;
  struct cleanup *old_chain;

  /* If the target does have hardware single step, GDB doesn't have
     to bother software single step.  */
  if (target_can_do_single_step () == 1)
    return NULL;

  old_chain = make_cleanup (VEC_cleanup (CORE_ADDR), &next_pcs);

  arm_get_next_pcs_ctor (&next_pcs_ctx,
			 &arm_3ds_get_next_pcs_ops,
			 gdbarch_byte_order (gdbarch),
			 gdbarch_byte_order_for_code (gdbarch),
			 1,
			 regcache);

  next_pcs = arm_get_next_pcs (&next_pcs_ctx);

  for (i = 0; VEC_iterate (CORE_ADDR, next_pcs, i, pc); i++)
    {
      pc = gdbarch_addr_bits_remove (gdbarch, pc);
      VEC_replace (CORE_ADDR, next_pcs, i, pc);
    }

  discard_cleanups (old_chain);

  return next_pcs;
}

static LONGEST
arm_3ds_get_syscall_number (struct gdbarch *gdbarch,
			      ptid_t ptid)
{
  struct regcache *regs = get_thread_regcache (ptid);

  ULONGEST pc;
  ULONGEST cpsr;
  ULONGEST t_bit = arm_psr_thumb_bit (gdbarch);
  int is_thumb;
  ULONGEST svc_number = -1;

  regcache_cooked_read_unsigned (regs, ARM_PC_REGNUM, &pc);
  regcache_cooked_read_unsigned (regs, ARM_PS_REGNUM, &cpsr);
  is_thumb = (cpsr & t_bit) != 0;

  if (is_thumb)
    {
      enum bfd_endian byte_order_for_code = 
	gdbarch_byte_order_for_code (gdbarch);

      /* PC gets incremented before the syscall-stop, so read the
	 previous instruction.  */
      unsigned long this_instr = 
	read_memory_unsigned_integer (pc - 2, 2, byte_order_for_code);

      unsigned long svc_operand = (0x00ff & this_instr);
      svc_number = svc_operand;
    }
  else
    {
      enum bfd_endian byte_order_for_code = 
	gdbarch_byte_order_for_code (gdbarch);

      /* PC gets incremented before the syscall-stop, so read the
	 previous instruction.  */
      unsigned long this_instr = 
	read_memory_unsigned_integer (pc - 4, 4, byte_order_for_code);

      unsigned long svc_operand = (0x000000ff & this_instr);
      svc_number = svc_operand;
    }
  
  if (svc_number == 0xfe)
    {
      regcache_cooked_read_unsigned (regs, 12, &svc_number);
    }

  return svc_number;
}

static void
arm_3ds_init_abi (struct gdbarch_info info,
			    struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  switch (info.byte_order)
    {
    case BFD_ENDIAN_LITTLE:
      tdep->arm_breakpoint = arm_3ds_arm_le_breakpoint;
      tdep->thumb_breakpoint = arm_3ds_thumb_le_breakpoint;
      tdep->arm_breakpoint_size = sizeof (arm_3ds_arm_le_breakpoint);
      tdep->thumb_breakpoint_size = sizeof (arm_3ds_thumb_le_breakpoint);
      break;

    default:
      internal_error (__FILE__, __LINE__,
        _("arm_gdbarch_init: bad byte order"));
    }
  tdep->fp_model = ARM_FLOAT_VFP;
  
  /* Single stepping.  */
  set_gdbarch_software_single_step (gdbarch, arm_3ds_software_single_step);

  /* `catch syscall' */
  set_xml_syscall_file_name (gdbarch, "syscalls/arm-3ds.xml");
  set_gdbarch_get_syscall_number (gdbarch, arm_3ds_get_syscall_number);
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
extern initialize_file_ftype _initialize_arm_3ds_tdep;

void
_initialize_arm_3ds_tdep (void)
{
  gdbarch_register_osabi (bfd_arch_arm, 0, GDB_OSABI_3DS,
                          arm_3ds_init_abi);
}
