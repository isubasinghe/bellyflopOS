#include <ctype.h>
#include <string.h>

#include <aos/aos.h>
#include <spawn/spawn.h>

#include <elf/elf.h>
#include <aos/caddr.h>
#include <aos/dispatcher_arch.h>
#include <aos/lmp_chan.h>
#include <aos/macros.h>
#include <aos/types.h>
#include <aos/aos_rpc.h>
#include <barrelfish_kpi/paging_arm_v8.h>
#include <barrelfish_kpi/domain_params.h>
#include <spawn/multiboot.h>
#include <spawn/argv.h>
#include <aos/paging_state_rebase.h>
#include <aos/aos_rpc_servers.h>

extern struct bootinfo *bi;

// Top 8 bits are core ID.
static domainid_t get_new_domainid(void)
{
    // 0 is reserved for init itself.
    static local_domainid_t next_local_domainid = 1;

    domainid_t did = did_from(disp_get_core_id(), next_local_domainid);
    ++next_local_domainid;
    return did;
}

/**
 * \brief Set the base address of the .got (Global Offset Table) section of the ELF binary
 *
 * \param arch_load_info This must be the base address of the .got section (local to the
 * child's VSpace). Must not be NULL.
 * \param handle The handle for the new dispatcher that is to be spawned. Must not be NULL.
 * \param enabled_area The "resume enabled" register set. Must not be NULL.
 * \param disabled_area The "resume disabled" register set. Must not be NULL.
 */
__attribute__((__used__)) static void
armv8_set_registers(void *arch_load_info, dispatcher_handle_t handle,
                    arch_registers_state_t *enabled_area,
                    arch_registers_state_t *disabled_area)
{
    assert(arch_load_info != NULL);
    uintptr_t got_base = (uintptr_t)arch_load_info;

    struct dispatcher_shared_aarch64 *disp_arm = get_dispatcher_shared_aarch64(handle);
    disp_arm->got_base = got_base;

    enabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
    disabled_area->regs[REG_OFFSET(PIC_REGISTER)] = got_base;
}

static errval_t setup_child_cspace(struct spawninfo *si, struct capref argcn0,
                                   struct capref argcn1, struct capref argcn2)
{
    // Create l1 root cnode
    errval_t err = cnode_create_l1(&si->rootcn_cap, &si->rootcn);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_ROOTCN);

    // Create task cnode
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_TASKCN, &si->taskcn);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_TASKCN);

    // Create the dispatcher in parent cspace, since we will need to invoke it later.
    err = slot_alloc(&si->disp_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);
    err = dispatcher_create(si->disp_cap);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_DISPATCHER);

    // Copy the dispatcher cap to task, since it will need it as well.
    struct capref task_disp = { si->taskcn, TASKCN_SLOT_DISPATCHER };
    err = cap_copy(task_disp, si->disp_cap);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_COPY_DISPATCHER);

    // Set task selfep
    struct capref task_selfep = { si->taskcn, TASKCN_SLOT_SELFEP };
    err = cap_retype(task_selfep, si->disp_cap, 0, ObjType_EndPointLMP, 0, 1);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_SELFEP);

    // Set task rootcn
    struct capref task_rootcn = { si->taskcn, TASKCN_SLOT_ROOTCN };
    err = cap_copy(task_rootcn, si->rootcn_cap);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_MINT_ROOTCN);


    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_SLOT_ALLOC0, NULL);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_SLOT_ALLOC1, NULL);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_SLOT_ALLOC2, NULL);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);

    // Setup base page frame cnode.
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_BASE_PAGE_CN, &si->basecn);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_SLOTALLOC_CNODE);

    // Fill base page frame cnode with frames (Alloc base frame and split into smaller frames).
    struct capref base_frame;
    err = ram_alloc(&base_frame, L2_CNODE_SLOTS * BASE_PAGE_SIZE);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_RAM_ALLOC);
    err = cap_retype((struct capref) { si->basecn, 0 }, base_frame, 0, ObjType_RAM,
                     BASE_PAGE_SIZE, L2_CNODE_SLOTS);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_RETYPE);
    err = cap_delete(base_frame);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_DELETE);

    // Setup page cnode (contains l0 pt cap & other pt & mapping caps)
    err = cnode_create_foreign_l2(si->rootcn_cap, ROOTCN_SLOT_PAGECN, &si->pagecn);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_PAGECN);
    si->pagecn_cap.cnode = si->rootcn;
    si->pagecn_cap.slot = ROOTCN_SLOT_PAGECN;

    // Setup argcn cap.
    if (!capref_is_null(argcn0)) {
        DEBUG_PRINTF("Copying argcn0 cap\n");

        struct capref task_argcn0 = { si->taskcn, TASKCN_SLOT_ARGCN0 };
        err = cap_copy(task_argcn0, argcn0);
        PUSH_RETURN_IF_ERR(err, SPAWN_ERR_COPY_ARGCN);
    }

    if (!capref_is_null(argcn1)) {
        DEBUG_PRINTF("Copying argcn1 cap\n");
        struct capref task_argcn1 = { si->taskcn, TASKCN_SLOT_ARGCN1 };
        err = cap_copy(task_argcn1, argcn1);
        PUSH_RETURN_IF_ERR(err, SPAWN_ERR_COPY_ARGCN);
    }

    if (!capref_is_null(argcn2)) {
        DEBUG_PRINTF("Copying argcn2 cap\n");
        struct capref task_argcn2 = { si->taskcn, TASKCN_SLOT_ARGCN2 };
        err = cap_copy(task_argcn2, argcn2);
        PUSH_RETURN_IF_ERR(err, SPAWN_ERR_COPY_ARGCN);
    }


    return SYS_ERR_OK;
}

// Note: It is not possible to map into a page table referenced with a capref which has a
// "foreign" croot.
//       (see `assert(get_croot_addr(dest) == CPTR_ROOTCN)` in `vnode_map()`).
//       Therefore, we allocate all of the slots for vnodes and mappings in the parent's
//       CSpace and only the L0 vnode is copied into the child's CSpace.
__attribute__((unused)) static errval_t setup_child_vspace(struct spawninfo *si)
{
    size_t bufsize = SINGLE_SLOT_ALLOC_BUFLEN(L2_CNODE_SLOTS);
    void *buf = malloc(bufsize);
    assert(buf != NULL);


    errval_t err = single_slot_alloc_init_raw(&si->single_slot_alloc, si->pagecn_cap,
                                              si->pagecn, L2_CNODE_SLOTS, buf, bufsize);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SINGLE_SLOT_ALLOC_INIT_RAW);

    err = si->single_slot_alloc.a.alloc(&si->single_slot_alloc.a, &si->l0_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);
    assert(si->l0_cap.slot == 0);

    // Create L0 vnode in parent, use it to initialize the child's paging state and copy
    // it to child's CSpace.
    struct capref l0_in_parent;
    slot_alloc(&l0_in_parent);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_SLOT_ALLOC);

    err = vnode_create(l0_in_parent, ObjType_VNode_AARCH64_l0);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_VNODE);


    // Set start_vaddr to BASE_PAGE_SIZE to allow mapping full virtual address space, but
    // avoid mapping NULL :)
    err = paging_init_state_foreign(si->paging_state, /*start_vaddr=*/BASE_PAGE_SIZE,
                                    l0_in_parent, get_default_slot_allocator());
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_PAGING_INIT_STATE_FOREIGN);

    err = cap_copy(si->l0_cap, l0_in_parent);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);

    return SYS_ERR_OK;
}

__attribute__((__unused__)) static errval_t
elf_allocator(void *state, genvaddr_t gvbase, size_t size, uint32_t flags, void **ret)
{
    struct spawninfo *si = state;

    // Base and size are not necessarily page-aligned.
    genvaddr_t gvbase_aligned = ROUND_DOWN(gvbase, BASE_PAGE_SIZE);
    size_t base_offset = gvbase - gvbase_aligned;
    size_t size_aligned = ROUND_UP(size + base_offset, BASE_PAGE_SIZE);

    // Allocate frame for the current segment.
    struct capref section_frame_cap;
    size_t retbytes;
    errval_t err = frame_alloc(&section_frame_cap, size_aligned, &retbytes);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    // Map it into the parent.
    void *parent_map_addr;
    err = paging_map_frame(get_current_paging_state(), &parent_map_addr, retbytes,
                           section_frame_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_VSPACE_MAP);
    assert(si->loaded_segments_arr_next_idx < si->loaded_segments_arr_size);
    si->loaded_segments_arr[si->loaded_segments_arr_next_idx++] = parent_map_addr;

    // Map it into the child.
    err = paging_map_fixed_attr(si->paging_state, gvbase_aligned, section_frame_cap,
                                retbytes, flags);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_VSPACE_MAP);

    *ret = (char *)parent_map_addr + base_offset;
    return SYS_ERR_OK;
}

static errval_t setup_load_elf(struct spawninfo *si, void **got_base_in_child_vspace)
{
    struct capref child_frame = {
        .cnode = cnode_module,
        .slot = si->module->mrmod_slot,
    };

    void *elf_base = NULL;
    struct paging_state *pst = get_current_paging_state();
    errval_t err = paging_map_frame(
        pst, &elf_base, ROUND_UP(si->module->mrmod_size, BASE_PAGE_SIZE), child_frame);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_ELF_MAP);

    si->loaded_segments_arr_size = elf_number_of_segments(PT_LOAD, (lvaddr_t)elf_base,
                                                          si->module->mrmod_size);
    si->loaded_segments_arr = malloc(si->loaded_segments_arr_size * sizeof(void *));
    si->loaded_segments_arr_next_idx = 0;

    err = elf_load(EM_AARCH64, elf_allocator, si, (lvaddr_t)elf_base,
                   si->module->mrmod_size, &si->binary_entry_addr);
    RETURN_IF_ERR(err);

    // GOT offset.
    struct Elf64_Shdr *got = elf64_find_section_header_name(
        (genvaddr_t)elf_base, si->module->mrmod_size, ".got");
    if (got == NULL) {
        return ELF_ERR_HEADER;  // Not exactly the right error to return, but close enough.
    }

    *got_base_in_child_vspace = (void *)got->sh_addr;

    // Unmap ELF memory from the parent.
    err = paging_unmap(pst, elf_base);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_VSPACE_REMOVE_REGION);

    for (size_t i = 0; i < si->loaded_segments_arr_size; ++i) {
        err = paging_unmap(pst, si->loaded_segments_arr[i]);
        PUSH_RETURN_IF_ERR(err, LIB_ERR_VSPACE_REMOVE_REGION);
    }

    return SYS_ERR_OK;
}

static errval_t spawn_setup_args(struct spawninfo *si, int argc, char *argv[])
{
    // TODO: what if we have very long args? More than a page long?
    const size_t frame_size = BASE_PAGE_SIZE;

    errval_t err;

    struct capref frame_capref;
    err = frame_alloc(&frame_capref, frame_size, NULL);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    // Copy the frame cap into the argspace cap.
    struct capref argspace_capref = { si->taskcn, TASKCN_SLOT_ARGSPAGE };
    err = cap_copy(argspace_capref, frame_capref);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);

    void *parent_ptr_frame;
    err = paging_map_frame(get_current_paging_state(), &parent_ptr_frame, frame_size,
                           frame_capref);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);

    // Map it into the child space as well but read only.
    void *child_ptr_frame;
    err = paging_map_frame_attr(si->paging_state, &child_ptr_frame, frame_size,
                                frame_capref, VREGION_FLAGS_READ);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);
    si->args_ptr_child_vspace = (genvaddr_t)child_ptr_frame;

    // The child’s startup code expects everything that does not explicitly have
    // to be filled in by init to be zeroed.
    memset(parent_ptr_frame, 0, frame_size);

    struct spawn_domain_params *sdp = parent_ptr_frame;

    sdp->argc = argc;
    // TODO: We do not do enviornment strings yet.
    sdp->envp[0] = NULL;
    // TODO: I am not sure why I am doing this.
    sdp->pagesize = BASE_PAGE_SIZE;

    // Copy the command line arguments behind the spawn_domain_params struct.
    char *write_addr_base = parent_ptr_frame + sizeof(struct spawn_domain_params);
    char *child_addr_base = child_ptr_frame + sizeof(struct spawn_domain_params);

    size_t offset = 0;
    // Code stolen from startup.c
    int i;
    for (i = 0; i < argc; i++) {
        size_t arglen = strlen(argv[i]);
        // Assert that our args are not to long.
        assert(sizeof(struct spawn_domain_params) + offset + arglen + 1 < BASE_PAGE_SIZE);
        sdp->argv[i] = (void *)(child_addr_base + offset);
        strcpy(write_addr_base + offset, argv[i]);

        offset += arglen + 1;
    }
    assert(sdp->argv[i] == NULL);  // Because of memset earlier.
    si->sdp = sdp;

    return SYS_ERR_OK;
}

static errval_t spawn_setup_dispatcher(struct spawninfo *si,
                                       void *got_base_in_child_vspace)
{
    errval_t err;

    struct capref dispatcher_frame;
    err = frame_alloc(&dispatcher_frame, DISPATCHER_FRAME_SIZE, NULL);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CREATE_DISPATCHER_FRAME);

    // Copy the frame cap into the Dispframe slot.
    struct capref disp_frame = { si->taskcn, TASKCN_SLOT_DISPFRAME };
    si->disp_frame = disp_frame;
    err = cap_copy(si->disp_frame, dispatcher_frame);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);

    void *disp_buf;
    err = paging_map_frame_attr(get_current_paging_state(), &disp_buf,
                                DISPATCHER_FRAME_SIZE, dispatcher_frame,
                                VREGION_FLAGS_READ_WRITE);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_MAP_DISPATCHER_TO_SELF);

    err = paging_map_frame_attr(si->paging_state, (void **)&si->disp_frame_addr,
                                DISPATCHER_FRAME_SIZE, si->disp_frame,
                                VREGION_FLAGS_READ_WRITE);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_MAP_DISPATCHER_TO_NEW);

    // This code is copied from the book:
    dispatcher_handle_t handle = (dispatcher_handle_t)disp_buf;
    struct dispatcher_shared_generic *disp = get_dispatcher_shared_generic(handle);
    struct dispatcher_generic *disp_gen = get_dispatcher_generic(handle);
    arch_registers_state_t *enabled_area = dispatcher_get_enabled_save_area(handle);
    arch_registers_state_t *disabled_area = dispatcher_get_disabled_save_area(handle);


    // core id of the process
    disp_gen->core_id = disp_get_core_id();
    disp_gen->domain_id = si->pid;
    // Virtual address of the dispatcher frame in child’s VSpace
    disp->udisp = si->disp_frame_addr;
    // Start in disabled mode
    disp->disabled = 1;
    // A name (for debugging)
    strncpy(disp->name, si->binary_name, DISP_NAME_LEN);
    // Set program counter (where it should start to execute)
    disabled_area->named.pc = si->binary_entry_addr;

    // Honestly, this is a copypaste from Barrelfish.
    // TODO: Figure out why the argument is set for enabled area and not disabled.
    registers_set_param(enabled_area, si->args_ptr_child_vspace);

    // Initialize offset registers
    // got_addr is the address of the .got in the child’s VSpace
    armv8_set_registers(got_base_in_child_vspace, handle, enabled_area, disabled_area);

    // we won’t use error handling frames
    disp_gen->eh_frame = 0;
    disp_gen->eh_frame_size = 0;
    disp_gen->eh_frame_hdr = 0;
    disp_gen->eh_frame_hdr_size = 0;

    return SYS_ERR_OK;
}


// Important: This should be called after all paging is done.
static errval_t spawn_setup_serialised_pmap(struct spawninfo *si)
{
    errval_t err;

    size_t frame_size = rebase_get_page_table_storage_size(&si->paging_state->l0_ptable);
    frame_size = ROUND_UP(frame_size, BASE_PAGE_SIZE);

    size_t num_pages = frame_size / BASE_PAGE_SIZE;
    // This is worst case ptables that can be added by calling paging_map_frame into child
    // space.
    // TODO DANGEROUS: THIS should be somehow recursive since by doing this we increse
    // num_pages again Put a While loop and find a stable point. For now we just multiply
    // with 2 :D Someone should do the math on this.
    size_t extra_ptables
        = num_pages / PTABLE_ENTRIES + num_pages / (PTABLE_ENTRIES * PTABLE_ENTRIES)
          + num_pages / (PTABLE_ENTRIES * PTABLE_ENTRIES * PTABLE_ENTRIES) + 3;
    extra_ptables *= 2;

    frame_size = frame_size + extra_ptables * sizeof(struct page_table);
    frame_size = ROUND_UP(frame_size, BASE_PAGE_SIZE);

    // Create frame to store the shadow page table in.
    struct capref pmap_frame;
    err = frame_alloc(&pmap_frame, frame_size, NULL);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_FRAME_ALLOC);

    // Copy cap to child.
    struct capref pmap_frame_child = { si->taskcn, TASKCN_SLOT_PMAPSPACE };
    si->pmap_frame = pmap_frame_child;
    cap_copy(si->pmap_frame, pmap_frame);

    // Map it into our memory:
    void *buf = NULL;
    err = paging_map_frame(get_current_paging_state(), &buf, frame_size, pmap_frame);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);

    // Map it into childs memory:
    void *child_buf = NULL;
    err = paging_map_frame(si->paging_state, &child_buf, frame_size, pmap_frame);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_MAP);
    si->sdp->vspace_buf = child_buf;
    si->sdp->vspace_buf_len = frame_size;

    // print_mappings(&si->paging_state->l0_ptable);


    err = rebase_to_relative_frame(si->paging_state, buf, frame_size,
                                   (struct slot_allocator *)&si->single_slot_alloc);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_REBASE_RELATIVE_TO_FRAME);

    return SYS_ERR_OK;
}

static errval_t spawn_init_server_endpoints(struct spawninfo *si)
{
    errval_t err;


    err = aos_rpc_init_lmp_server(&si->init_server_rpc, get_default_waitset(),
                                  &init_eventhandler, si);
    RETURN_IF_ERR(err);
    assert(capref_is_null(si->init_server_rpc.chan.lmp.remote_cap));
    // Create channels.
    err = aos_rpc_init_lmp_server(&si->mem_server_rpc, mem_server_get_ws(),
                                  &mem_eventhandler, si);
    RETURN_IF_ERR(err);

    // Put parent's endpoints into the child.
    struct capref init_ep = { si->taskcn, TASKCN_SLOT_INITEP },
                  mem_ep = { si->taskcn, TASKCN_SLOT_MEMEP };
    err = cap_copy(init_ep, si->init_server_rpc.chan.lmp.local_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);

    err = cap_copy(mem_ep, si->mem_server_rpc.chan.lmp.local_cap);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_CAP_COPY);

    si->has_domain_client_rpc = false;

    return SYS_ERR_OK;
}

__unused static void release_frame(void* arg) {
    struct capref* frame = arg;
    assert(frame!=NULL);
    assert(!capref_is_null(*frame));
    frame_free(*frame);
    free(frame);
}

static void spawn_setup_memory_tracking(struct spawninfo *si) 
{
    si->memory_tracking.remaining_quota_B = DEFAULT_MEMORY_QUOTA_B;
    collections_list_create(&si->memory_tracking.allocated_ram_caps, /*release_frame*/ NULL);
}

static errval_t spawn_cleanup(struct spawninfo *si)
{
    errval_t err;

    err = paging_unmap(get_current_paging_state(), si->sdp);
    PUSH_RETURN_IF_ERR(err, LIB_ERR_PMAP_UNMAP);
    
    si->sdp = NULL;
    return SYS_ERR_OK;
}



/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher called 'argv[0]' with 'argc' arguments.
 *
 * This function spawns a new dispatcher running the ELF binary called
 * 'argv[0]' with 'argc' - 1 additional arguments. It fills out 'si'
 * and 'pid'.
 *
 * \param argc The number of command line arguments. Must be > 0.
 * \param argv An array storing 'argc' command line arguments.
 * \param si A pointer to the spawninfo struct representing
 * the child. It will be filled out by this function. Must not be NULL.
 * \param pid A pointer to a domainid_t variable that will be
 * assigned to by this function. Must not be NULL.
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_argv(int argc, char *argv[], struct spawninfo *si, domainid_t *pid)
{
    return spawn_load_argv_argcn(argc, argv, si, pid, NULL_CAP, NULL_CAP, NULL_CAP);
}

errval_t spawn_load_argv_argcn(int argc, char *argv[], struct spawninfo *si,
                               domainid_t *pid, struct capref argcn0,
                               struct capref argcn1, struct capref argcn2)
{
    // TODO: Implement me
    // - Initialize the spawn_info struct
    // - Get the module from the multiboot image
    //   and map it (take a look at multiboot.c)
    // - Setup the child's cspace
    // - Setup the child's vspace
    // - Load the ELF binary
    // - Setup the dispatcher
    // - Setup the environment
    // - Make the new dispatcher runnable
    //

    // spawninfo owns this data now and is responsible for freeing it
    // spawninfo can be freed by free_spawninfo
    si->binary_name = strdup(argv[0]);

    si->pid = get_new_domainid();
    *pid = si->pid;

    si->paging_state = malloc(sizeof(struct paging_state));
    if (si->paging_state == NULL) {
        return LIB_ERR_MALLOC_FAIL;
    }

    errval_t err = setup_child_cspace(si, argcn0, argcn1, argcn2);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_SETUP_CSPACE);

    err = setup_child_vspace(si);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_SETUP_VSPACE);

    si->module = multiboot_find_module(bi, argv[0]);
    if (si->module == NULL) {
        return SPAWN_ERR_MODULE_NOT_FOUND;
    }

    void *got_base_in_child_vspace = NULL;
    err = setup_load_elf(si, &got_base_in_child_vspace);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_ELF_MAP);

    err = spawn_setup_args(si, argc, argv);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_SETUP_ARGS);


    err = spawn_setup_dispatcher(si, got_base_in_child_vspace);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_DISPATCHER_SETUP);

    err = spawn_init_server_endpoints(si);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_INIT_SERVER_ENDPOINTS);

    err = spawn_setup_serialised_pmap(si);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_SERIALISE_PMAP);

    spawn_setup_memory_tracking(si);

    invoke_dispatcher(si->disp_cap, cap_dispatcher, si->rootcn_cap, si->l0_cap,
                      si->disp_frame, true);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_DISPATCHER_INVOKE);

    struct spawnstore *ss = get_default_spawnstore();
    if (!spawnstore_add(ss, si)) {
        return SPAWN_ERR_SPAWNSTORE_ADD;
    }

    // TODO: Clean up here to not leak resources.
    // 1) Destroy si->paging_state?

    err = spawn_cleanup(si);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_CLEANUP);

    return SYS_ERR_OK;
}




/**
 * TODO(M2): Implement this function.
 * \brief Spawn a new dispatcher executing 'binary_name'
 *
 * \param binary_name The name of the binary.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 *
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */
errval_t spawn_load_by_name(char *binary_name, struct spawninfo *si, domainid_t *pid)
{
    // TODO: Implement me
    // - Get the mem_region from the multiboot image
    // - Fill in argc/argv from the multiboot command line
    // - Call spawn_load_argv

    struct mem_region *module = multiboot_find_module(bi, binary_name);
    RETURN_ERR_IF_NULL(module, LIB_ERR_MULTIBOOT_MODULE_FIND);

    // TODO: When is the mapping unmapped that is created in multiboot_module_opts?
    char *args_string = (char *)multiboot_module_opts(module);
    RETURN_ERR_IF_NULL(module, LIB_ERR_MULTIBOOT_MODULE_OPS);


    int argc;
    char *argv_buf;
    char **argv = make_argv(args_string, &argc, &argv_buf);
    RETURN_ERR_IF_NULL(argv, err_push(LIB_ERR_ARGV_MAKE, SPAWN_ERR_GET_CMDLINE_ARGS));

    DEBUG_PRINTF("calling spawn load argc\n");
    errval_t err = spawn_load_argv(argc, argv, si, pid);
    free(argv);
    free(argv_buf);

    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_LOAD);

    return SYS_ERR_OK;
}

/**
 * \brief Spawn a new dispatcher executing 'binary_name'
 *
 * \param cmd_line_string The Command line string.
 * \param si A pointer to a spawninfo struct that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 * \param pid A pointer to a domainid_t that will be
 * filled out by spawn_load_by_name. Must not be NULL.
 *
 * \return Either SYS_ERR_OK if no error occured or an error
 * indicating what went wrong otherwise.
 */

errval_t spawn_load_by_cmdline(char *cmd_line_string, struct spawninfo *si,
                               domainid_t *pid)
{
    return spawn_load_by_cmdline_argcn(cmd_line_string, si, pid, NULL_CAP, NULL_CAP,
                                       NULL_CAP);
}


errval_t spawn_load_by_cmdline_argcn(char *cmd_line_string, struct spawninfo *si,
                                     domainid_t *pid, struct capref argcn0,
                                     struct capref argcn1, struct capref argcn2)
{
    int argc;
    char *argv_buf;
    char **argv = make_argv(cmd_line_string, &argc, &argv_buf);
    RETURN_ERR_IF_NULL(argv, err_push(LIB_ERR_ARGV_MAKE, SPAWN_ERR_GET_CMDLINE_ARGS));
    errval_t err = spawn_load_argv_argcn(argc, argv, si, pid, argcn0, argcn1, argcn2);
    free(argv);
    free(argv_buf);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_LOAD);

    return SYS_ERR_OK;
}

static errval_t spawn_free(struct spawninfo *si)
{
    // // Not sure if we can call ram free. This was create weirdly.
    // cap_destroy(si->rootcn_cap);
    // cap_destroy(si->pagecn_cap);

    // // No Idea how to deltete cnodes.
    // // cap_destroy(si->rootcn);
    // // cap_destroy(si->taskcn);
    // // cap_destroy(si->pagecn);
    // // cap_destroy(si->basecn);
    // // Not sure if this works since this is a ObjType_Dispatcher now.
    // frame_free(si->disp_cap);
    // frame_free(si->disp_frame);
    // frame_free(si->pmap_frame);
    // DEBUG_PRINTF("Freeing list of caps\n");
    collections_listnode * frames_to_free = si->memory_tracking.allocated_ram_caps;
    // This actually calls release_frame on every entry in the list.
    // Noep it does not since this gvies page faults.
    collections_list_release(frames_to_free);
    DEBUG_PRINTF("Freeing list of caps done\n");

    // // I dont know why but this does not work.
    // // paging_state_destroy(si->paging_state);
    // // free(si->paging_state);

    // free(si->binary_name);
    // free(si);
    return SYS_ERR_OK;
}

errval_t spawn_kill_and_free(struct spawninfo *si) {
    errval_t err = invoke_dispatcher_stop(si->disp_cap);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_INVOKE_DISPATCHER_STOP);
    spawn_free(si);

    return SYS_ERR_OK;
}

errval_t spawn_kill_by_pid(struct spawnstore *ss, domainid_t pid)
{
    struct spawninfo *si;
    uint32_t ith;
    if (!spawnstore_get(ss, pid, &si, &ith)) {
        return SPAWN_ERR_SPAWNSTORE_GET;
    }

    errval_t err = spawn_kill_and_free(si);
    PUSH_RETURN_IF_ERR(err, SPAWN_ERR_KILL_DISPATCHER);
    bool res = spawnstore_remove_by_pid(ss, pid);
    (void) res;
    DEBUG_PRINTF("Successfully removed spawninfo from spawnstore %d\n", res);
    return SYS_ERR_OK;
}
