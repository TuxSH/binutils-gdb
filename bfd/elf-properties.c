/* ELF program property support.
   Copyright (C) 2017 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include "libbfd.h"
#include "elf-bfd.h"

/* Get a property, allocate a new one if needed.  */

elf_property *
_bfd_elf_get_property (bfd *abfd, unsigned int type, unsigned int datasz)
{
  elf_property_list *p, **lastp;

  /* Keep the property list in order of type.  */
  lastp = &elf_properties (abfd);
  for (p = *lastp; p; p = p->next)
    {
      /* Reuse the existing entry.  */
      if (type == p->property.type)
        return &p->property;
      else if (type < p->property.type)
	break;
      lastp = &p->next;
    }
  p = (elf_property_list *) bfd_alloc (abfd, sizeof (*p));
  memset (p, 0, sizeof (*p));
  p->property.type = type;
  p->property.datasz = datasz;
  p->next = *lastp;
  *lastp = p;
  return &p->property;
}

/* Parse GNU properties.  */

bfd_boolean
_bfd_elf_parse_gnu_properties (bfd *abfd, Elf_Internal_Note *note)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);
  unsigned int align_size = bed->s->elfclass == ELFCLASS64 ? 8 : 4;
  bfd_byte *ptr = (bfd_byte *) note->descdata;
  bfd_byte *ptr_end = ptr + note->descsz;

  if (note->descsz < 8 || (note->descsz % align_size) != 0)
    {
bad_size:
      _bfd_error_handler
	(_("warning: %B: corrupt GNU_PROPERTY_TYPE (%ld) size: %#lx\n"),
	 abfd, note->type, note->descsz);
      return FALSE;
    }

  while (1)
    {
      unsigned int type = bfd_h_get_32 (abfd, ptr);
      unsigned int datasz = bfd_h_get_32 (abfd, ptr + 4);
      elf_property *prop;

      ptr += 8;

      if ((ptr + datasz) > ptr_end)
	{
	  _bfd_error_handler
	    (_("warning: %B: corrupt GNU_PROPERTY_TYPE (%ld) type (0x%x) datasz: 0x%x\n"),
	     abfd, note->type, type, datasz);
	  /* Clear all properties.  */
	  elf_properties (abfd) = NULL;
	  return FALSE;
	}

      if (type >= GNU_PROPERTY_LOPROC)
	{
	  if (type < GNU_PROPERTY_LOUSER)
	    {
	      enum elf_property_kind kind;

	      if (bed->parse_gnu_properties)
		kind = bed->parse_gnu_properties (abfd, type, ptr,
						  datasz);
	      else
		kind = property_ignored;

	      if (kind == property_corrupted)
		{
		  /* Clear all properties.  */
		  elf_properties (abfd) = NULL;
		  return FALSE;
		}

	      goto next;
	    }
	}
      else
	{
	  switch (type)
	    {
	    case GNU_PROPERTY_STACK_SIZE:
	      if (datasz != align_size)
		{
		  _bfd_error_handler
		    (_("warning: %B: corrupt stack size: 0x%x\n"),
		     abfd, datasz);
		  /* Clear all properties.  */
		  elf_properties (abfd) = NULL;
		  return FALSE;
		}
	      prop = _bfd_elf_get_property (abfd, type, datasz);
	      if (datasz == 8)
		prop->u.value = bfd_h_get_64 (abfd, ptr);
	      else
		prop->u.value = bfd_h_get_32 (abfd, ptr);
	      prop->kind = property_value;
	      goto next;

	    case GNU_PROPERTY_NO_COPY_ON_PROTECTED:
	      if (datasz != 0)
		{
		  _bfd_error_handler
		    (_("warning: %B: corrupt no copy on protected size: 0x%x\n"),
		     abfd, datasz);
		  /* Clear all properties.  */
		  elf_properties (abfd) = NULL;
		  return FALSE;
		}
	      prop = _bfd_elf_get_property (abfd, type, datasz);
	      prop->kind = property_value;
	      goto next;

	    default:
	      break;
	    }
	}

      _bfd_error_handler
	(_("warning: %B: unsupported GNU_PROPERTY_TYPE (%ld) type: 0x%x\n"),
	 abfd, note->type, type);

next:
      ptr += (datasz + (align_size - 1)) & ~ (align_size - 1);
      if (ptr == ptr_end)
	break;

      if (ptr > (ptr_end - 8))
	goto bad_size;
    }

  return TRUE;
}

/* Merge GNU property.  Return TRUE if property is updated.  */

static bfd_boolean
elf_merge_gnu_properties (bfd *abfd, elf_property *prop, elf_property *p)
{
  const struct elf_backend_data *bed = get_elf_backend_data (abfd);

  if (prop->type >= GNU_PROPERTY_LOPROC
      && prop->type < GNU_PROPERTY_LOUSER
      && bed->merge_gnu_properties != NULL)
    return bed->merge_gnu_properties (abfd, prop, p);

  switch (prop->type)
    {
    case GNU_PROPERTY_STACK_SIZE:
      if (p->u.value > prop->u.value)
	{
	  prop->u.value = p->u.value;
	  return TRUE;
	}
      break;

    case GNU_PROPERTY_NO_COPY_ON_PROTECTED:
      break;

    default:
      /* Never should happen.  */
      abort ();
    }

  return FALSE;
}

/* Merge GNU property list.  Return TRUE if property list is updated.  */

static bfd_boolean
elf_merge_gnu_property_list (bfd *abfd, elf_property_list *list)
{
  bfd_boolean updated = FALSE;

  for (; list != NULL; list = list->next)
    {
      elf_property *p;
      p = _bfd_elf_get_property (abfd, list->property.type,
				 list->property.datasz);
      if (p->kind == property_unknown)
	{
	  /* Add a new property.  */
	  *p = list->property;
	  updated = TRUE;
	}
      else
	updated |= elf_merge_gnu_properties (abfd, p, &list->property);
    }

  return updated;
}

/* Set up GNU properties.  */

void
_bfd_elf_link_setup_gnu_properties (struct bfd_link_info *info)
{
  bfd *abfd, *first_pbfd = NULL;
  elf_property_list *list;
  asection *sec;
  bfd_boolean updated = FALSE;
  const struct elf_backend_data *bed;
  unsigned int align_size;

  for (abfd = info->input_bfds; abfd != NULL; abfd = abfd->link.next)
    if (bfd_get_flavour (abfd) == bfd_target_elf_flavour
	&& bfd_count_sections (abfd) != 0)
      {
	/* Check .note.gnu.property section.  */
	list = elf_properties (abfd);
	if (list)
	  {
	    if (first_pbfd == NULL)
	      {
		/* Keep .note.gnu.property section in FIRST_PBFD.  */
		first_pbfd = abfd;
		continue;
	      }

	    /* Merge properties with FIRST_PBFD.  */
	    updated |= elf_merge_gnu_property_list (first_pbfd, list);

	    /* Discard .note.gnu.property section in the rest inputs.  */
	    sec = bfd_get_section_by_name (abfd, ".note.gnu.property");
	    sec->output_section = bfd_abs_section_ptr;
	  }
      }

  /* Do nothing if there is no .note.gnu.property section.  */
  if (first_pbfd == NULL)
    return;

  bed = get_elf_backend_data (first_pbfd);
  align_size = bed->s->elfclass == ELFCLASS64 ? 8 : 4;

  /* Update stack size in .note.gnu.property with -z stack-size=N.  */
  if (info->stacksize && first_pbfd != NULL)
    {
      elf_property *p;
      /* info->stacksize == -1 means explicit no-stack.  */
      bfd_vma stacksize = info->stacksize < 0 ? 0 : info->stacksize;

      p = _bfd_elf_get_property (first_pbfd, GNU_PROPERTY_STACK_SIZE,
				 align_size);
      if (p->kind == property_unknown)
	{
	  /* Create GNU_PROPERTY_STACK_SIZE.  */
	  p->u.value = stacksize;
	  p->kind = property_value;
	  updated = TRUE;
	}
      else if (stacksize > p->u.value || stacksize == 0)
	{
	  p->u.value = stacksize;
	  updated = TRUE;
	}
    }

  if (updated)
    {
      unsigned int size;
      unsigned int descsz;
      bfd_byte *contents;
      Elf_External_Note *e_note;

      sec = bfd_get_section_by_name (first_pbfd, ".note.gnu.property");

      /* Compute the section size.  */
      descsz = offsetof (Elf_External_Note, name[sizeof "GNU"]);
      descsz = (descsz + 3) & -(unsigned int) 4;
      size = descsz;
      for (list = elf_properties (first_pbfd);
	   list != NULL;
	   list = list->next)
	{
	  /* There are 4 byte type + 4 byte datasz for each property.  */
	  size += 4 + 4 + list->property.datasz;
	  /* Align each property.  */
	  size = (size + (align_size - 1)) & ~(align_size - 1);
	}

      /* Update .note.gnu.property section now.  */
      sec->size = size;
      contents = (bfd_byte *) bfd_zalloc (first_pbfd, size);

      e_note = (Elf_External_Note *) contents;
      bfd_h_put_32 (first_pbfd, sizeof "GNU", &e_note->namesz);
      bfd_h_put_32 (first_pbfd, size - descsz, &e_note->descsz);
      bfd_h_put_32 (first_pbfd, NT_GNU_PROPERTY_TYPE_0, &e_note->type);
      memcpy (e_note->name, "GNU", sizeof "GNU");

      size = descsz;
      for (list = elf_properties (first_pbfd);
	   list != NULL;
	   list = list->next)
	{
	  /* There are 4 byte type + 4 byte datasz for each property.  */
	  bfd_h_put_32 (first_pbfd, list->property.type,
			contents + size);
	  bfd_h_put_32 (first_pbfd, list->property.datasz,
			contents + size + 4);
	  size += 4 + 4;

	  /* Write out property value.  */
	  switch (list->property.kind)
	    {
	    case property_value:
	      switch (list->property.datasz)
		{
		default:
		  /* Never should happen.  */
		  abort ();

		case 0:
		  break;

		case 4:
		  bfd_h_put_32 (first_pbfd, list->property.u.value,
				contents + size);
		  break;

		case 8:
		  bfd_h_put_64 (first_pbfd, list->property.u.value,
				contents + size);
		  break;
		}
	      break;

	    default:
	      /* Never should happen.  */
	      abort ();
	    }
	  size += list->property.datasz;

	  /* Align each property.  */
	  size = (size + (align_size - 1)) & ~ (align_size - 1);
	}

      /* Cache the section contents for elf_link_input_bfd.  */
      elf_section_data (sec)->this_hdr.contents = contents;
    }
}
