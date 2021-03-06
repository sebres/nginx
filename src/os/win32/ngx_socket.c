
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {

    ngx_pid_t      pid;
    ngx_uint_t     nelts;
    ngx_int_t      worker_processes;

    /* WSAPROTOCOL_INFO * [listening.nelts] */

} ngx_shm_listener_t;

static ngx_shm_t shm_listener = {0};


int
ngx_nonblocking(ngx_socket_t s)
{
    unsigned long  nb = 1;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
ngx_blocking(ngx_socket_t s)
{
    unsigned long  nb = 0;

    return ioctlsocket(s, FIONBIO, &nb);
}


int
ngx_tcp_push(ngx_socket_t s)
{
    return 0;
}


ngx_int_t ngx_get_listening_share(ngx_cycle_t *cycle)
{

    size_t            size;

    size = sizeof(ngx_shm_listener_t) +
        sizeof(WSAPROTOCOL_INFO) * cycle->listening.nelts;

    if (!shm_listener.addr || shm_listener.size < size) {
        if (shm_listener.addr) {
            ngx_shm_free(&shm_listener);
        }

        shm_listener.addr = NULL;
        shm_listener.size = size;
        shm_listener.name.len = sizeof("nginx_shared_listener") - 1;
        shm_listener.name.data = (u_char *) "nginx_shared_listener";
        shm_listener.log = cycle->log;

        if (ngx_shm_alloc(&shm_listener) != NGX_OK) {
            return NGX_ERROR;
        }
        
        ngx_log_debug4(NGX_LOG_DEBUG_CORE, cycle->log, 0, 
            "[%d] shared mem for %d listener(s) - %p, %d bytes", 
            ngx_process, cycle->listening.nelts, 
            shm_listener.addr, shm_listener.size);
    }

    return NGX_OK;
}


void ngx_free_listening_share(ngx_cycle_t *cycle)
{
    if (shm_listener.addr) {

        ngx_shm_free(&shm_listener);
        shm_listener.addr = NULL;

    }
}


ngx_int_t
ngx_get_listening_share_info(ngx_cycle_t *cycle, ngx_shared_socket_info * pshinfo, ngx_pid_t pid)
{
    ngx_int_t            waitint;
    ngx_int_t            waitcnt;
    ngx_shm_listener_t  *shml;

    *pshinfo = NULL;

    if (shm_listener.addr == NULL) {
        if (ngx_get_listening_share(cycle) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    shml = (ngx_shm_listener_t *)shm_listener.addr;
        
    /* TODO: wait time and count configurable */
    waitcnt = 10;
    waitint = 5;
    do {
        if (shml->worker_processes == 1) {
            *pshinfo = NGX_CONF_UNSET_PTR;
            return NGX_OK;
        }
        if (shml->pid == pid) {
            break;
        }
        /* not found - wait until master process shared sockets */
        ngx_msleep(waitint);
        if (waitint < 100) {
            waitint += waitint; 
            waitint = min(100, waitint);
        }
    
    } while (waitcnt--);

    if (shml->pid != pid) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, 
            "wait for shared socket failed, process %d, found %d", pid, shml->pid);
        return NGX_AGAIN;
    }
    if (cycle->listening.nelts > shml->nelts) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "unexpected shared len,"
            " expected %d, but got %d", cycle->listening.nelts, shml->nelts);
        return NGX_ERROR;
    }
    
    *pshinfo = (WSAPROTOCOL_INFO *)(shml+1);

    return NGX_OK;
}


ngx_int_t 
ngx_share_listening_sockets(ngx_cycle_t *cycle, ngx_pid_t pid)
{
    ngx_uint_t           i;
    ngx_listening_t     *ls;
    ngx_core_conf_t     *ccf;
    ngx_shm_listener_t  *shml;
    WSAPROTOCOL_INFO    *protoInfo;

    if (ngx_process > NGX_PROCESS_MASTER) {
        return NGX_OK;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (ccf->worker_processes == 1) {
        /* close before create shmem (to avoid free shmem) */
        ngx_close_listening_sockets(cycle);
    }

    /* create shared memory for shared listener info */
    ngx_get_listening_share(cycle);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0, 
        "[%d] share %d listener(s) for %d",
        ngx_process, cycle->listening.nelts, pid);

    ls = cycle->listening.elts;

    /* share sockets for worker with pid */
    shml = (ngx_shm_listener_t *)shm_listener.addr;
    protoInfo = (WSAPROTOCOL_INFO *)(shml+1);

    shml->nelts = cycle->listening.nelts;
    shml->worker_processes = ccf->worker_processes;

    if (ccf->worker_processes > 1) {
        for (i = 0; i < cycle->listening.nelts; i++) {

            if (ls[i].ignore) {
                continue;
            }

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, cycle->log, 0, 
                "[%d] dup %d listener %d for %d", ngx_process, i, ls[i].fd, pid);

            if (WSADuplicateSocket(ls[i].fd, pid, &protoInfo[i]) != 0) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                    "WSADuplicateSocket() failed");
                return NGX_ERROR;
            };

        }
    }

    shml->pid = pid;

    return NGX_OK;
}
