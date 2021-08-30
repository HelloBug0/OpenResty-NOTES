
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_429)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_uint_t                       status;
    ngx_msec_t                       response_time;
    ngx_msec_t                       connect_time;
    ngx_msec_t                       header_time;
    ngx_msec_t                       queue_time;
    off_t                            response_length;
    off_t                            bytes_received;
    off_t                            bytes_sent;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    ngx_uint_t                       down;

    unsigned                         backup:1;

    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020
#define NGX_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_http_upstream_local_t;


typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream; /* 当在ngx_http_upstream_t中没有实现resolved成员时，upstreams结构体才会生效，定义上游服务器的配置 */

    ngx_msec_t                       connect_timeout; /* 建立TCP连接的超时时间，实际就是写事件添加到定时器中时设置的时间 */
    ngx_msec_t                       send_timeout; /* 发送请求的超时时间，实际就是写事件添加到定时器中时设置的时间 */
    ngx_msec_t                       read_timeout; /* 接收响应的超时时间，实际就是读事件添加到定时器中时设置的时间 */
    ngx_msec_t                       next_upstream_timeout;

    size_t                           send_lowat; /* TCP的SO_SNOLOWAT选项，表示发送缓冲区的下限 */
    size_t                           buffer_size; /* 接收头部缓冲区大小，当不转发响应或buffering=0时，同样表示接收包体的缓冲区大小 */
    size_t                           limit_rate;1

    size_t                           busy_buffers_size; /* 仅当buffering=1并且向下游转发响应时，会被设置到ngx_event_pipe_t结构体的busy_size成员 */
    size_t                           max_temp_file_size; /* buffering=1时，如果上游速度大于下游速度，响应缓存到临时文件的最大长度。将会限制 ngx_event_pipe_t结构体中的temp_file */
    size_t                           temp_file_write_size; /* 将缓冲区的响应写入临时文件时，一次写入字符流的最大长度 */

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    ngx_bufs_t                       bufs; /* 以缓存响应的方式转发上游服务器的包体时所使用的内存大小 */

    ngx_uint_t                       ignore_headers; /* 使用二进制位的方式指示在转发包头时，跳过哪些包头的处理（针对ngx_http_upstream_t中的headers_in成员进行筛选）*/
    ngx_uint_t                       next_upstream; /* 以二进制位来表示一些错误码，如果处理上游服务器发现这些错误码，在响应没有发送给下游客户端时，将会选择下一个上游服务器来重发请求 */
    ngx_uint_t                       store_access; /* buffering=1转发响应时，响应可能存放在临时文件里，当ngx_http_upstream_t中的store标志=1时，store_access表示所创建的目录、文件的权限 */
    ngx_uint_t                       next_upstream_tries;
    ngx_flag_t                       buffering; /* 解释其他字段的bufferring就是该buffering，=1表示打开缓存，认为上游速度大于下游速度，会尽量在内存或者磁盘中缓存上游的响应；=0仅会开辟一块固定大小的内存块作为缓存转发响应 */
    ngx_flag_t                       request_buffering;
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    ngx_flag_t                       ignore_client_abort; /* =1表示与上游进行交互时，不会检查Nginx与下游的连接是否断开，即使下游主动关闭连接，也不中断与上游服务器间的交互 */
    ngx_flag_t                       intercept_errors; /* 解析上游的包头时，如果解析到的headers_in结构体中的status_n错误码大于400，则会试图把他与error_page中指定的错误码匹配，匹配成功，则发送error_page中指定的响应，否则返回上游服务器的响应 */
    ngx_flag_t                       cyclic_temp_file; /* =1复用临时文件中已经使用的空间 */
    ngx_flag_t                       force_ranges;

    ngx_path_t                      *temp_path; /* buffering=1时转发响应，临时文件的路径 */

    ngx_hash_t                       hide_headers_hash; /* 不转发的头部散列表 */
    ngx_array_t                     *hide_headers; /* ups 响应的头部信息哪些需要隐藏 */
    ngx_array_t                     *pass_headers;/* ups 响应的头部信息哪些需要转发到下游 */

    ngx_http_upstream_local_t       *local; /* 连接上游服务器使用的本机地址 */
    ngx_flag_t                       socket_keepalive;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;
    ngx_msec_t                       cache_lock_age;

    ngx_flag_t                       cache_revalidate;
    ngx_flag_t                       cache_convert_head;
    ngx_flag_t                       cache_background_update;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *cache_purge;
    ngx_array_t                     *no_cache;
#endif

    ngx_array_t                     *store_lengths; /* ngx_http_upstream_t的store=1，如果需要将上游的响应保存到文件中，store_lengths表示存放路径的长度，store_values表示存放路径 */
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    signed                           cache:2;
#endif
    signed                           store:2;
    unsigned                         intercept_404:1; /* =1，表示即使上游服务器的404响应和error_page匹配，也会直接将404发送给下游 */
    unsigned                         change_buffering:1; /* =1表示会根据ngx_http_upstream_t中header_in结构体中的X-Accel-Buffering头部，值为yes/no来修改buffering，值位yes，buffering=1，值为no,buffering=0 */
    unsigned                         pass_trailers:1;
    unsigned                         preserve_output:1;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    ngx_http_complex_value_t        *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_flag_t                       ssl_verify;
#endif

    ngx_str_t                        module; /* 使用upstream的模块名称，仅用于记录日志 */

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;
    ngx_list_t                       trailers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    ngx_http_upstream_handler_pt     read_event_handler; /* 处理读事件的回调方法，不同阶段方法不同 */
    ngx_http_upstream_handler_pt     write_event_handler; /* 处理写事件的回调方法，不同阶段方法不同 */

    ngx_peer_connection_t            peer; /* 向上游服务器发起的连接 */

    ngx_event_pipe_t                *pipe; /* 向下游客户端发送响应时(ngx_http_request_t结构体中的subrequest_in_memory=0)，如果打开了缓存(conf配置中的buffering=1)，
	并且认为上游网速更快，使用pipe成员转发响应。使用该方法转发响应时，必须由HTTP模块在使用upstream机制前构造pipe结构体，否则会出现coredump */
    ngx_chain_t                     *request_bufs; /* 以链表的方式链接ngx_buf_t缓冲区，保存发送给上游服务器的请求。HTTP模块是新的create_request回调方法就在于构造request_bufs链表 */

    ngx_output_chain_ctx_t           output; /* 定义向下游发送响应的方式 */
    ngx_chain_writer_ctx_t           writer;

    ngx_http_upstream_conf_t        *conf; /* 使用upstream机制时的配置*/
    ngx_http_upstream_srv_conf_t    *upstream;
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif

#define HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS  1
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;

    ngx_http_upstream_headers_in_t   headers_in; /* HTTP模块在实现process_header方法是，如果希望upstream直接转发响应，需要把解析出的响应头部适配为HTTP响应头部，然后把包头中的
	信息设置到headers_in结构体中。最后会把该结构体中的头部信息添加到要发送到下游客户端的响应头部headers_out中 */
    ngx_http_upstream_resolved_t    *resolved; /* 用于解析主机域名 */

    ngx_buf_t                        from_client;

    ngx_buf_t                        buffer; /* 读取 ups 响应时，缓冲区里保存响应内容，如果 buffer 满，但是未读完响应，则请求出错 */
    off_t                            length; /* 来自上游服务器的响应包体的长度，上述buffer是接收上游服务器响应包头的缓冲区，在不需要把响应直接转发给客户端，或者buffering标志位
	=0的情况下，接收包体的缓冲区使用buffer。注意：如果没有自定义input_filter方法处理包体，将会使用buffer存储全部的包体，这是buffer必须足够大，他的大小由ngx_http_upstream_conf_t结构体中的buffer_size决定 */
    ngx_chain_t                     *out_bufs; /* 当不需要转发包体时，且使用默认的input_filter(ngx_http_upstream_non_buffered_filter)方法处理包体，out_bufs指向响应包体，事实上，out_bufs链表中会产生多个ngx_buf_t缓冲区，每个缓冲区都指向buffer缓冲中的一部分，而这部分就是每次调用recv方法接收到的一段tcp流；当需要转发响应体到下游时(bufferring标志=0，即以下游网速优先)，这个链表指向上一次向下游转发的响应到现在这段时间内接收自上游的缓存响应 */
    ngx_chain_t                     *busy_bufs; /* 当需要转发响应体到下游时(buffering=0，下游网速优先)，表示上一次向下游转发响应时没有发送完的内容 */
    ngx_chain_t                     *free_bufs; /* 回收out_bufs中已经发送给下游的ngx_buf_t结构体，应用于buffering=0，即下游网速优先的场景 */

    ngx_int_t                      (*input_filter_init)(void *data); /* 处理 ups 的响应体前的初始化工作，data指向下面的input_filter_ctx字段 */
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes); /* 处理响应体的方法，data为input_filter_ctx指针，bytes表示本次接收到的包体长度。返回NGX_ERR表示处理包体错误，请求需要结束，否则将继续upstream流程 */
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    ngx_int_t                      (*create_request)(ngx_http_request_t *r); /* 构造发送给 ups 的请求，设置 ups 服务器的地址，建立 TCP 连接 */
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r); /* 和 ups 建立 TCP 连接之后，判断字段 request_sent 是否为1， 如果为1，则调用该函数处理连接断开网络事件。如果该指针为 NULL，不会调用该函数 */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r); /* 处理 ups 返回的 HTTP 头部，该函数会多次调用，直到该函数返回值不等于 NGX_AGAIN */
    void                           (*abort_request)(ngx_http_request_t *r); /* 该方法目前不会调用 */
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc); /* 请求销毁前，都会调用该函数，该函数必须实现，否则函数指针值空指针也会被调用 */
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r, /* ngx_http_upstream_process_headers 方法调用 rewrite_direct 函数，处理 ups 响应头域中的 Location 头域 */
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       start_time;

    ngx_http_upstream_state_t       *state; /* 表示上游响应的错误码、包体长度等信息 */

    ngx_str_t                        method; /* 不使用文件缓存时没有意义 */
    ngx_str_t                        schema; /* schema 和 uri 仅在记录日志时会用到 */
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        ssl_name;
#endif

    ngx_http_cleanup_pt             *cleanup; /* 目前仅用于表示是否需要清理资源，相当于一个标志位，实际不会调用到他所指向的方法 */

    unsigned                         store:1; /* 是否指定文件缓存路径 */
    unsigned                         cacheable:1; /* 是否启用文件缓存 */
    unsigned                         accel:1; /* 暂无意义 */
    unsigned                         ssl:1; /* 是否基于SSL协议访问上游服务器 */
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1; /* 向下游转发上游的响应体时，是否开启更大的缓存以及临时磁盘文件用户缓存来不及发送到下游的响应包体 */
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;
    unsigned                         error:1;

    unsigned                         request_sent:1; /* =1表示已经向上游服务器发送了全部或者部分的请求。事实上，这个标志位更多的是为了使用ngx_output_chain方法发送请求，因为该方法发送请求时会自动把未发送结束的request_bufs链表记录下来为了防止反复发送重复请求，必须由request_sent标志记录是否调用过ngx_output_chain方法 */
    unsigned                         request_body_sent:1;
    unsigned                         request_body_blocked:1;
    unsigned                         header_sent:1; /* =1表示已经把响应包头发送给客户端 */
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_int_t ngx_http_upstream_non_buffered_filter_init(void *data);
ngx_int_t ngx_http_upstream_non_buffered_filter(void *data, ssize_t bytes);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#ifndef HAVE_BALANCER_STATUS_CODE_PATCH
#define HAVE_BALANCER_STATUS_CODE_PATCH
#endif


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
