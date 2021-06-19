
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos;  /* 当buf指向的数据在内存中时，pos指向数据开始的位置 */
    u_char          *last; /* 当buf指向的数据在内存中时，last指向数据结束的位置 */
    off_t            file_pos;  /* 当buf指向的数据在文件中时，file_pos指向数据开始的位置在文件中的偏移量 */
    off_t            file_last; /* 当buf指向的数据在文件中时，file_last指向数据结束的位置在文件中的偏移量 */

    u_char          *start;         /* start of buffer 当前数据占用的大内存的开始位置，这个大内存中可能包含多个数据 */
    u_char          *end;           /* end of buffer 当前数据占用的大内存的结束位置 */
    ngx_buf_tag_t    tag; /* 使用者自己使用，自己赋予其含义 */
    ngx_file_t      *file; /* 当buf执行的数据在文件中时，file指向对应的文件字段 */
    ngx_buf_t       *shadow; /* 当多个buf指向同一快内存或者同一个文件的同一部分时，这个字段指向对方的buf，资源释放时需谨慎 */


    /* the buf's content could be changed */
    unsigned         temporary:1; /* 取值为1表示buf包含的内容在用户创建的内存中，并且可以在filter处理的过程中进行变更，并且不会造成问题 */

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1; /* 取值为1表示buf包含的内容在内存中，不可以在filter处理的过程中进行变更 */

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1; /* 取值为1表示buf包含的内容在内存中，并且是通过mmap使用内存映射从文件映射到内存中的，不可以在filter处理的过程中进行变更 */

    unsigned         recycled:1; /* 取值为1表示内存可以回收，通常配合shadow进行使用，告诉对方buf，这块内存可以释放 */
    unsigned         in_file:1; /* 取值为1表示buf包含的内容在文件中 */
    unsigned         flush:1; /* 取值为1的buf所在的chain，即使该chain的数据不是最后的数据，即last_buf未设置为1，也会进行输出，不会受postpone_output配置的限制，但是会受到发送速率等其他条件的限制 */
    unsigned         sync:1;
    unsigned         last_buf:1; /* 数据以多个chain的方式传递给过滤器，取值为1表示这是最后一个buf */
    unsigned         last_in_chain:1; /* 取值为1表示当前buf是当前chain的最后一个，last_in_chain的buf不一定是last_buf，但是last_buf一定是last_in_chain。数据会被以多个chain传递给某个filter模块 */

    unsigned         last_shadow:1;
    unsigned         temp_file:1;

    /* STUB */ int   num;
};


struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
    unsigned                     unaligned:1;
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
    unsigned                     aio:1;

#if (NGX_HAVE_FILE_AIO || NGX_COMPAT)
    ngx_output_chain_aio_pt      aio_handler;
#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    ssize_t                    (*aio_preload)(ngx_buf_t *file);
#endif
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_int_t                  (*thread_handler)(ngx_thread_task_t *task,
                                                 ngx_file_t *file);
    ngx_thread_task_t           *thread_task;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)       ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_in_memory_only(b)  (ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_special(b)                                                   \
    (((b)->flush || (b)->last_buf || (b)->sync)                              \
     && !ngx_buf_in_memory(b) && !(b)->in_file)

#define ngx_buf_sync_only(b)                                                 \
    ((b)->sync && !ngx_buf_in_memory(b)                                      \
     && !(b)->in_file && !(b)->flush && !(b)->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) ((b)->last - (b)->pos):                  \
                            ((b)->file_last - (b)->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    (cl)->next = (pool)->chain;                                              \
    (pool)->chain = (cl)



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);

off_t ngx_chain_coalesce_file(ngx_chain_t **in, off_t limit);

ngx_chain_t *ngx_chain_update_sent(ngx_chain_t *in, off_t sent);

#endif /* _NGX_BUF_H_INCLUDED_ */
