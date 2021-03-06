#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_echo_filter.h"
#include "ngx_http_echo_util.h"
#include "ngx_http_echo_echo.h"

#include <ngx_log.h>



ngx_http_output_header_filter_pt ngx_http_echo_next_header_filter;

ngx_http_output_body_filter_pt ngx_http_echo_next_body_filter;

static ngx_int_t ngx_http_echo_header_filter(ngx_http_request_t *r);

static ngx_int_t ngx_http_echo_body_filter(ngx_http_request_t *r,
        ngx_chain_t *in);

/* filter handlers */
static ngx_int_t ngx_http_echo_exec_filter_cmds(ngx_http_request_t *r,
    ngx_http_echo_ctx_t *ctx, ngx_array_t *cmds, ngx_uint_t *iterator);


static volatile ngx_cycle_t  *ngx_http_echo_prev_cycle = NULL;


ngx_int_t
ngx_http_echo_filter_init(ngx_conf_t *cf)
{
    int                              multi_http_blocks;
    ngx_http_echo_main_conf_t       *emcf;

    emcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_echo_module);

    if (ngx_http_echo_prev_cycle != ngx_cycle) {
        ngx_http_echo_prev_cycle = ngx_cycle;
        multi_http_blocks = 0;

    } else {
        multi_http_blocks = 1;
    }

    if (multi_http_blocks || emcf->requires_filter) { /* 指令类型分为句柄指令和过滤指令，当指令类型为过滤类型时，需要设置filter函数（在nginx.conf中配置该模块指令之后，会设置该指令类型） */
        dd("top header filter: %ld",
           (unsigned long) ngx_http_top_header_filter);

        ngx_http_echo_next_header_filter = ngx_http_top_header_filter; /* 利用这种方式组成模块的执行顺序，进入ngx_http_echo_header_filter之后，执行ngx_http_echo_next_header_filter，，因为下一个header_filter是从原来的top_header中获取，所以就是下一个head_filter*/
        ngx_http_top_header_filter = ngx_http_echo_header_filter;

        dd("top body filter: %ld", (unsigned long) ngx_http_top_body_filter);

        ngx_http_echo_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter  = ngx_http_echo_body_filter;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_echo_header_filter(ngx_http_request_t *r)
{
    ngx_http_echo_loc_conf_t    *conf;
    ngx_http_echo_ctx_t         *ctx;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "echo header filter, uri \"%V?%V\"", &r->uri, &r->args);

    ctx = ngx_http_get_module_ctx(r, ngx_http_echo_module);

    /* XXX we should add option to insert contents for responses
     * of non-200 status code here... */
    /*
    if (r->headers_out.status != NGX_HTTP_OK) {
        if (ctx != NULL) {
            ctx->skip_filter = 1;
        }
        return ngx_http_echo_next_header_filter(r);
    }
    */

    conf = ngx_http_get_module_loc_conf(r, ngx_http_echo_module);
    if (conf->before_body_cmds == NULL && conf->after_body_cmds == NULL) {
        if (ctx != NULL) {
            ctx->skip_filter = 1;
        }
        return ngx_http_echo_next_header_filter(r);
    }

    if (ctx == NULL) {
        ctx = ngx_http_echo_create_ctx(r);
        if (ctx == NULL) {
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, ngx_http_echo_module);
    }

    /* enable streaming here (use chunked encoding) */
    ngx_http_clear_content_length(r); /* 由此可看出如果是正常的请求，响应码包含200和206*/
    ngx_http_clear_accept_ranges(r); /* 将响应头域中的 Content-Length 和 Accept-Ranges 删除，不支持全部响应和返回请求，仅支持 chunk 响应，也就是说我们使用 echo 输出响应的时候，响应一定是 chunk传输 */

    return ngx_http_echo_next_header_filter(r); /* header filter仅用来删除头域信息 */
}


static ngx_int_t /* header filter 的参数仅为 ngx_http_request_t , body_filter 多了一个 ngx_chain_t 里面保存的是响应内容 */
ngx_http_echo_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_echo_ctx_t         *ctx;
    ngx_int_t                    rc;
    ngx_http_echo_loc_conf_t    *conf;
    unsigned                     last;
    ngx_chain_t                 *cl;
    ngx_buf_t                   *b;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "echo body filter, uri \"%V?%V\"", &r->uri, &r->args);

    if (in == NULL || r->header_only) {
        return ngx_http_echo_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_echo_module);

    if (ctx == NULL || ctx->skip_filter) { /* 为什么 body_filter 时 ctx 为空，不创建ctx 呢？*/
        return ngx_http_echo_next_body_filter(r, in);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_echo_module);

    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1; /* 标志位，控制函数 ngx_http_echo_exec_filter_cmds 只执行一次 */

        if (conf->before_body_cmds != NULL) {
            rc = ngx_http_echo_exec_filter_cmds(r, ctx, conf->before_body_cmds,
                                                &ctx->next_before_body_cmd);
            if (rc != NGX_OK) {
                return NGX_ERROR;
            }
        }
    }

    if (conf->after_body_cmds == NULL) {
        ctx->skip_filter = 1;
        return ngx_http_echo_next_body_filter(r, in);
    }
    /* 下面开始所有的操作都是为了执行 after_body_cmds，也就是说当所有的 body_filter 都执行结束之后，才会执行的操作，L169 首先执行其他所有的 body_filter，执行结束之后，再根据判断条件 L179 判断是否执行 after_body_cmds */
    last = 0;

    for (cl = in; cl; cl = cl->next) {
        dd("cl %p, special %d", cl, ngx_buf_special(cl->buf));

        if (cl->buf->last_buf || cl->buf->last_in_chain) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 0;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    dd("in %p, last %d", in, (int) last);

    if (in) {
        rc = ngx_http_echo_next_body_filter(r, in);

#if 0
        if (rc == NGX_AGAIN) {
            return NGX_ERROR;
        }
#endif

        dd("next filter returns %d, last %d", (int) rc, (int) last);

        if (rc == NGX_ERROR || rc > NGX_OK || !last) { /* 如果 rc == NGX_OK, last == 0 程序直接返回。last == 0 意味着当前链中的所有bug都是当前链的最后一个，也不是所有链的最后一个 */
            return rc; /* 也就是说，只有传参 in 中包含当前 chain 的最后一个 buf， 或者所有 chain 的最后一个 buf，才会执行下面的操作，否则直接返回 */
        }/* 为什么要判断last呢？如果last == 1，则说明将本来是最后一个buf的标志变成了不是最后一个buf, 如果我做了这个欺骗操作，则后面需要继续操作来处理自己的谎言。其实也在说明，如果当前的buf都不是最后一个buf，则后面的操作也不需要执行 */
    }

    dd("exec filter cmds for after body cmds");

    rc = ngx_http_echo_exec_filter_cmds(r, ctx, conf->after_body_cmds,
                                        &ctx->next_after_body_cmd);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        dd("FAILED: exec filter cmds for after body cmds");
        return NGX_ERROR;
    }

    ctx->skip_filter = 1;

    dd("after body cmds executed...terminating...");

    /* XXX we can NOT use
     * ngx_http_send_special(r, NGX_HTTP_LAST) here
     * because we should bypass the upstream filters. */

    b = ngx_calloc_buf(r->pool); /* 这里是一个为了让后面的 body_filter 继续执行的一个欺骗操作，给之后的 body_filter 一个空的 buf，完成 nginx 的响应处理流程 */
    if (b == NULL) {
        return NGX_ERROR;
    }

    if (r == r->main && !r->post_action) { /* 如果当前请求是主请求，而且（不是Post请求？），设置当前buf是整个响应的最后一个 buf */
        b->last_buf = 1;

    } else { /* 如果是子请求，设置当前buf，是整个链的最后一个buf */
        b->sync = 1;
        b->last_in_chain = 1;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->next = NULL;
    cl->buf = b;

    return ngx_http_echo_next_body_filter(r, cl);
}


static ngx_int_t
ngx_http_echo_exec_filter_cmds(ngx_http_request_t *r,
    ngx_http_echo_ctx_t *ctx, ngx_array_t *cmds, ngx_uint_t *iterator)
{
    ngx_int_t                    rc;
    ngx_array_t                 *opts = NULL;
    ngx_array_t                 *computed_args = NULL;
    ngx_http_echo_cmd_t         *cmd;
    ngx_http_echo_cmd_t         *cmd_elts;

    for (cmd_elts = cmds->elts; *iterator < cmds->nelts; (*iterator)++) { /* 遍历所有的指令 */
        cmd = &cmd_elts[*iterator]; /* cmd 类型 ngx_http_echo_cmd_t ，即为每个指令的信息 */

        /* evaluate arguments for the current cmd (if any) */
        if (cmd->args) { /* 以下首先创建两个临时变量，为执行执行服务 */
            computed_args = ngx_array_create(r->pool, cmd->args->nelts,
                                             sizeof(ngx_str_t));
            if (computed_args == NULL) {
                return NGX_ERROR;
            }

            opts = ngx_array_create(r->pool, 1, sizeof(ngx_str_t));
            if (opts == NULL) {
                return NGX_ERROR;
            }

            rc = ngx_http_echo_eval_cmd_args(r, cmd, computed_args, opts); /* 初始化临时变量，计算指令参数 */

            if (rc != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "Failed to evaluate arguments for "
                              "the directive.");
                return rc;
            }
        }

        /* do command dispatch based on the opcode */
        switch (cmd->opcode) {
        case echo_opcode_echo_before_body:
        case echo_opcode_echo_after_body:
            dd("exec echo_before_body or echo_after_body...");

            rc = ngx_http_echo_exec_echo(r, ctx, computed_args, /* 执行指令 */
                                         1 /* in filter */, opts);

            if (rc == NGX_ERROR || rc > NGX_OK) {
                return rc;
            }

            break;
        default:
            break;
        }
    }

    return NGX_OK;
}
