#include <aos/aos.h>
#include <aos/coreboot.h>
#include <spawn/multiboot.h>
#include <elf/elf.h>
#include <string.h>
#include <barrelfish_kpi/arm_core_data.h>
#include <aos/kernel_cap_invocations.h>
#include <aos/cache.h>
#include <aos/macros.h>

#define ARMv8_KERNEL_OFFSET 0xffff000000000000

extern struct bootinfo *bi;

struct mem_info {
    size_t size;         // Size in bytes of the memory region
    void *buf;           // Address where the region is currently mapped
    lpaddr_t phys_base;  // Physical base address
};

/**
 * Load a ELF image into memory.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF will be loaded
 * entry_point:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t load_elf_binary(genvaddr_t binary,
                                                          const struct mem_info *mem,
                                                          genvaddr_t entry_point,
                                                          genvaddr_t *reloc_entry_point)

{
    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    /* Load the CPU driver from its ELF image. */
    bool found_entry_point = 0;
    bool loaded = 0;

    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) {
            DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                         ", memory size 0x%" PRIx64 " SKIP\n",
                         i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);
            continue;
        }

        DEBUG_PRINTF("Segment %d load address 0x% " PRIx64 ", file size %" PRIu64
                     ", memory size 0x%" PRIx64 " LOAD\n",
                     i, phdr[i].p_vaddr, phdr[i].p_filesz, phdr[i].p_memsz);


        if (loaded) {
            USER_PANIC("Expected one load able segment!\n");
        }
        loaded = 1;

        void *dest = mem->buf;
        lpaddr_t dest_phys = mem->phys_base;

        assert(phdr[i].p_offset + phdr[i].p_memsz <= mem->size);

        /* copy loadable part */
        memcpy(dest, (void *)(binary + phdr[i].p_offset), phdr[i].p_filesz);

        /* zero out BSS section */
        memset(dest + phdr[i].p_filesz, 0, phdr[i].p_memsz - phdr[i].p_filesz);

        if (!found_entry_point) {
            if (entry_point >= phdr[i].p_vaddr
                && entry_point - phdr[i].p_vaddr < phdr[i].p_memsz) {
                *reloc_entry_point = (dest_phys + (entry_point - phdr[i].p_vaddr));
                found_entry_point = 1;
            }
        }
    }

    if (!found_entry_point) {
        USER_PANIC("No entry point loaded\n");
    }

    return SYS_ERR_OK;
}

/**
 * Relocate an already loaded ELF image.
 *
 * binary:            Valid pointer to ELF image in current address space
 * mem:               Where the ELF is loaded
 * kernel_:       Virtual address of the entry point
 * reloc_entry_point: Return the loaded, physical address of the entry_point
 */
__attribute__((__used__)) static errval_t
relocate_elf(genvaddr_t binary, struct mem_info *mem, lvaddr_t load_offset)
{
    DEBUG_PRINTF("Relocating image.\n");

    struct Elf64_Ehdr *ehdr = (struct Elf64_Ehdr *)binary;

    size_t shnum = ehdr->e_shnum;
    struct Elf64_Phdr *phdr = (struct Elf64_Phdr *)(binary + ehdr->e_phoff);
    struct Elf64_Shdr *shead = (struct Elf64_Shdr *)(binary + (uintptr_t)ehdr->e_shoff);

    /* Search for relocaton sections. */
    for (size_t i = 0; i < shnum; i++) {
        struct Elf64_Shdr *shdr = &shead[i];
        if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
            if (shdr->sh_info != 0) {
                DEBUG_PRINTF("I expected global relocations, but got"
                             " section-specific ones.\n");
                return ELF_ERR_HEADER;
            }


            uint64_t segment_elf_base = phdr[0].p_vaddr;
            uint64_t segment_load_base = mem->phys_base;
            uint64_t segment_delta = segment_load_base - segment_elf_base;
            uint64_t segment_vdelta = (uintptr_t)mem->buf - segment_elf_base;

            size_t rsize;
            if (shdr->sh_type == SHT_REL) {
                rsize = sizeof(struct Elf64_Rel);
            } else {
                rsize = sizeof(struct Elf64_Rela);
            }

            assert(rsize == shdr->sh_entsize);
            size_t nrel = shdr->sh_size / rsize;

            void *reldata = (void *)(binary + shdr->sh_offset);

            /* Iterate through the relocations. */
            for (size_t ii = 0; ii < nrel; ii++) {
                void *reladdr = reldata + ii * rsize;

                switch (shdr->sh_type) {
                case SHT_REL:
                    DEBUG_PRINTF("SHT_REL unimplemented.\n");
                    return ELF_ERR_PROGHDR;
                case SHT_RELA: {
                    struct Elf64_Rela *rel = reladdr;

                    uint64_t offset = rel->r_offset;
                    uint64_t sym = ELF64_R_SYM(rel->r_info);
                    uint64_t type = ELF64_R_TYPE(rel->r_info);
                    uint64_t addend = rel->r_addend;

                    uint64_t *rel_target = (void *)offset + segment_vdelta;

                    switch (type) {
                    case R_AARCH64_RELATIVE:
                        if (sym != 0) {
                            DEBUG_PRINTF("Relocation references a"
                                         " dynamic symbol, which is"
                                         " unsupported.\n");
                            return ELF_ERR_PROGHDR;
                        }

                        /* Delta(S) + A */
                        *rel_target = addend + segment_delta + load_offset;
                        break;

                    default:
                        DEBUG_PRINTF("Unsupported relocation type %d\n", type);
                        return ELF_ERR_PROGHDR;
                    }
                } break;
                default:
                    DEBUG_PRINTF("Unexpected type\n");
                    break;
                }
            }
        }
    }

    return SYS_ERR_OK;
}

static errval_t create_kcb(lpaddr_t *kcb_paddr)
{
    struct capref kcb_ram_cap;
    errval_t err = ram_alloc_aligned(&kcb_ram_cap, OBJSIZE_KCB, 16 * 1024);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_RAM_ALLOC_ALIGNED);

    *kcb_paddr = cap_get_paddr(kcb_ram_cap);

    struct capref kcb_cap;
    err = slot_alloc(&kcb_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);

    err = cap_retype(kcb_cap, kcb_ram_cap, 0, ObjType_KernelControlBlock, OBJSIZE_KCB, 1);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_RETYPE);

    return SYS_ERR_OK;
}

static errval_t load_and_relocate(const char *name, const char *ep_sym,
                                  struct mem_info *mem, genpaddr_t *entry_paddr,
                                  size_t relocate_offset)
{
    errval_t err;

    // Get the module and map it.
    struct mem_region *module = multiboot_find_module(bi, name);
    RETURN_ERR_IF_NULL(module, LIB_ERR_MULTIBOOT_MODULE_FIND);

    struct capref mod_frame = { cnode_module, module->mrmod_slot };
    lvaddr_t mod_vaddr;
    err = paging_map_frame_complete(get_current_paging_state(),
                                    (void **)&mod_vaddr,  // Intended confusion :)
                                    mod_frame);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);

    // Alloc memory where the module will be loaded and map it.
    struct capref elf_frame;
    err = frame_alloc(&elf_frame, round_page(module->mrmod_size), NULL);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    void *elf_buf;
    err = paging_map_frame_complete(get_current_paging_state(), &elf_buf, elf_frame);

    *mem = (struct mem_info) {
        module->mrmod_size,
        elf_buf,
        cap_get_paddr(elf_frame),
    };

    // Load and relocate.
    struct Elf64_Sym *entry_sym = elf64_find_symbol_by_name(mod_vaddr, module->mrmod_size,
                                                            ep_sym, 0, STT_FUNC, NULL);
    RETURN_ERR_IF_NULL(entry_sym, LIB_ERR_COREBOOT_FIND_SYMBOL);

    err = load_elf_binary(mod_vaddr, mem, entry_sym->st_value, entry_paddr);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_LOAD_ELF_BINARY);

    err = relocate_elf(mod_vaddr, mem, relocate_offset);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_RELOCATE_ELF_BINARY);

    return SYS_ERR_OK;
}

errval_t coreboot(coreid_t mpid, const char *boot_driver, const char *cpu_driver,
                  const char *init, struct frame_identity urpc_frame_id)
{
    // TODO: create and push errors.

    // - Get a new KCB by retyping a RAM cap to ObjType_KernelControlBlock.
    //   Note that it should at least OBJSIZE_KCB, and it should also be aligned
    //   to a multiple of 16k.
    lpaddr_t kcb_paddr;
    errval_t err = create_kcb(&kcb_paddr);
    RETURN_IF_ERR(err);

    // - Get and load the CPU driver binary.
    // - Relocate the boot and CPU driver. The boot driver runs with a 1:1
    //   VA->PA mapping. The CPU driver is expected to be loaded at the
    //   high virtual address space, at offset ARMV8_KERNEL_OFFSET.
    struct mem_info cpu_mem;
    genpaddr_t cpu_entry_paddr;
    err = load_and_relocate(cpu_driver, "arch_init", &cpu_mem, &cpu_entry_paddr,
                            ARMv8_KERNEL_OFFSET);
    RETURN_IF_ERR(err);

    // - Get and load the boot driver binary.
    struct mem_info boot_mem;
    genpaddr_t boot_entry_paddr;
    // Idk why it needs to be relocated to 0, but it doesn't work otherwise.
    err = load_and_relocate(boot_driver, "boot_entry_psci", &boot_mem, &boot_entry_paddr,
                            0);
    RETURN_IF_ERR(err);

    // - Map init blob
    struct mem_region *init_mod = multiboot_find_module(bi, init);
    RETURN_ERR_IF_NULL(init_mod, LIB_ERR_MULTIBOOT_MODULE_FIND);

    struct capref init_mod_cap = { .cnode = cnode_module, .slot = init_mod->mrmod_slot };

    void *init_blob;
    err = paging_map_frame_complete(get_current_paging_state(), &init_blob, init_mod_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);

    // - Alloc memory
    struct capref memory_cap;
    size_t memory_size;

    size_t init_size = elf_virtual_size((lvaddr_t)init_blob);
    err = frame_alloc(&memory_cap,
                      ARMV8_CORE_DATA_PAGES * BASE_PAGE_SIZE
                          + ROUND_UP(init_size, BASE_PAGE_SIZE),
                      &memory_size);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_RAM_ALLOC);

    // - Allocate stack memory for the new cpu driver (at least 16 pages)
    struct capref stack_frame;
    size_t stack_size = 16 * BASE_PAGE_SIZE;
    err = frame_alloc(&stack_frame, stack_size, NULL);
    RETURN_IF_ERR(err);

    genpaddr_t stack_paddr = cap_get_paddr(stack_frame);

    // - Allocate a page for the core data struct
    struct capref core_data_frame;
    err = frame_alloc(&core_data_frame, BASE_PAGE_SIZE, NULL);
    RETURN_IF_ERR(err);

    struct armv8_core_data *core_data;
    err = paging_map_frame_complete(get_current_paging_state(), (void **)&core_data,
                                    core_data_frame);
    RETURN_IF_ERR(err);

    // - Fill in the core data struct, for a description, see the definition
    //   in include/target/aarch64/barrelfish_kpi/arm_core_data.h
    *core_data = (struct armv8_core_data) {
        .boot_magic = ARMV8_BOOTMAGIC_PSCI,
        .cpu_driver_stack = stack_paddr + stack_size,
        .cpu_driver_stack_limit = stack_paddr,
        .cpu_driver_globals_pointer = 0, // Overwritten at later point.
        .cpu_driver_entry = cpu_entry_paddr + ARMv8_KERNEL_OFFSET,
        .cpu_driver_cmdline = {0},
        .page_table_root = 0, // Overwritten at later point.
        .memory = (struct armv8_coredata_memreg) {
            .base = cap_get_paddr(memory_cap),
            .length = memory_size,
        },
        .urpc_frame = (struct armv8_coredata_memreg) {
            .base = urpc_frame_id.base,
            .length = urpc_frame_id.bytes
        },
        .monitor_binary = (struct armv8_coredata_memreg) {
            .base = cap_get_paddr(init_mod_cap),
            .length = init_mod->mrmod_size
        },
        .multiboot_image = {0}, // Not set for APP cores.
        .efi_mmap = 0, // Not set for APP cores.
        .start_kernel_ram = 0, // Not set for APP cores.
        .start_free_ram = 0, // Not set for APP cores.
        .chan_id = 0, // Not set for APP cores.
        .kcb = kcb_paddr,
        .src_core_id = disp_get_core_id(),
        .dst_core_id = mpid,
        .src_arch_id = disp_get_core_id(),
        .dst_arch_id = mpid,
    };

    // - Flush the cache.
    // TODO barrier, invalidate, clean
    // (it might be easier to allocate all memory as a contiguous block.

    // Invalidate cache. I have no idea which function out of the ones in cache.h to use
    // but this seems to work.
    cpu_dcache_wb_range((vm_offset_t)cpu_mem.buf, cpu_mem.size);
    cpu_dcache_wb_range((vm_offset_t)boot_mem.buf, boot_mem.size);
    cpu_dcache_wb_range((vm_offset_t)core_data, sizeof *core_data);

    // - Call the invoke_monitor_spawn_core with the entry point
    //   of the boot driver and pass the (physical, of course) address of the
    //   boot struct as argument.
    err = invoke_monitor_spawn_core(core_data->dst_arch_id, CPU_ARM8, boot_entry_paddr,
                                    cap_get_paddr(core_data_frame), 0);
    PUSH_RETURN_IF_ERR(err, MON_ERR_SPAWN_CORE);

    return SYS_ERR_OK;
}
