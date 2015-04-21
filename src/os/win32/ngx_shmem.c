
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


static volatile size_t g_addrbaseoffs = 0;

static volatile int g_SystemInfo_init = 0;
SYSTEM_INFO g_SystemInfo;

int ngx_shm_init_once() {
    if (g_SystemInfo_init)
        return 1;
    g_SystemInfo_init = 1;
    GetSystemInfo(&g_SystemInfo);
    return 1;
}


ngx_int_t
ngx_shm_alloc(ngx_shm_t *shm)
{
    u_char    *name;
    uint64_t   size;
    u_char    *addr;
    u_char    *addrbase;

    ngx_shm_init_once();

    name = ngx_alloc(shm->name.len + 2 + NGX_INT32_LEN, shm->log);
    if (name == NULL) {
        return NGX_ERROR;
    }

    (void) ngx_sprintf(name, "%V_%s%Z", &shm->name, ngx_unique);

    ngx_set_errno(0);

    size = shm->size;

    /* increase for base address, will be saved inside shared mem :*/
    size += sizeof(addr);

    shm->handle = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                    (u_long) (size >> 32),
                                    (u_long) (size & 0xffffffff),
                                    (char *) name);

    if (shm->handle == NULL) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CreateFileMapping(%uz, %s) failed",
                      size, name);
        ngx_free(name);

        return NGX_ERROR;
    }

    ngx_free(name);

    shm->exists = 0;
    if (ngx_errno == ERROR_ALREADY_EXISTS) {
        shm->exists = 1;
    }

    /*
     * Because of Win x64 since Vista/Win7 (always ASLR in kernel32), and nginx uses pointer 
     * inside this shared areas, we should use the same address for shared memory (Windows IPC)

     * Now we set preferred base to a hardcoded address that newborn processes never seem to be using (in available versions of Windows).
     * The addresses was selected somewhat randomly in order to minimize the probability that some other library doing something similar 
     * conflicts with us. That is, using conspicuous addresses like 0x20000000 might not be good if someone else does it.
     */
    #ifdef _WIN64
        /* 
         * There is typically a giant hole (almost 8TB):
         * 00000000 7fff0000
         * ...
         * 000007f6 8e8b0000
         */
        addrbase = (u_char*) 0x0000047047e00000ULL;
    #else
        /* 
         * This is more dicey.  However, even with ASLR there still
         * seems to be a big hole:
         * 10000000
         * ...
         * 70000000
         */
        addrbase = (u_char*) 0x2efe0000;
    #endif

    /* add offset (corresponding all used shared) to preferred base: */
    addrbase += g_addrbaseoffs;

    addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, addrbase);

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, shm->log, 0, "map shared \"%V\" -> %p (base %p), size: %uz", &shm->name, addr, addrbase, size);

    if (addr != NULL) {

        /* get allocated address if already exists: */
        if (shm->exists) {
            /* get base and realoc using it if different */
            addrbase = *(u_char **)addr;
            ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm->log, 0, "shared \"%V\" -> %p -> %p", &shm->name, addr, addrbase);
            if (addrbase != addr) {
                /* free: */
                if (UnmapViewOfFile(addr) == 0) {
                    ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                                  "UnmapViewOfFile(%p) of file mapping \"%V\" failed",
                                  addr, &shm->name);
                }
                /* allocate again using base address: */
                addr = MapViewOfFileEx(shm->handle, FILE_MAP_WRITE, 0, 0, 0, 
                                       addrbase /* lpBaseAddress */
                                        );
            }
        } else {
            ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm->log, 0, "shared \"%V\" -> %p (base %p)", &shm->name, addr, addrbase);
            /* save first allocated address as base for next caller: */
            *(u_char **) addr = addr;
        }

        if (addr != NULL) {
            /* increase base offset (use proper alignment, obtain it from dwAllocationGranularity): */
            g_addrbaseoffs += (size + g_SystemInfo.dwAllocationGranularity) & (0xffffffff & ~(g_SystemInfo.dwAllocationGranularity-1));
            /* ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm->log, 0, "offset %ui, granularity %ui", g_addrbaseoffs, g_SystemInfo.dwAllocationGranularity); */
            shm->addr = addr + sizeof(addr);
            ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm->log, 0, "shared alloc \"%V\" -> %p = %p", &shm->name, addr, shm->addr);
            return NGX_OK;
        }
    }

    ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                  "MapViewOfFile(%uz) of file mapping \"%V\" failed",
                  shm->size, &shm->name);

    if (CloseHandle(shm->handle) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CloseHandle() of file mapping \"%V\" failed",
                      &shm->name);
    }

    return NGX_ERROR;
}


void
ngx_shm_free(ngx_shm_t *shm)
{
    u_char    *addr;

    addr = shm->addr - sizeof(addr);
    ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm->log, 0, "shared free \"%V\" -> %p = %p", &shm->name, addr, shm->addr);
    if (UnmapViewOfFile(addr) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "UnmapViewOfFile(%p) of file mapping \"%V\" failed",
                      addr, &shm->name);
    }

    if (CloseHandle(shm->handle) == 0) {
        ngx_log_error(NGX_LOG_ALERT, shm->log, ngx_errno,
                      "CloseHandle() of file mapping \"%V\" failed",
                      &shm->name);
    }
}
