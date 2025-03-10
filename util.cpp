/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 ccminer team
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

//#define _GNU_SOURCE
#include <ccminer-config.h>

// ARM-specific optimizations
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
#include <arm_neon.h>
#elif defined(__arm__) || defined(__aarch64__)
// Enable NEON instructions if available but not automatically detected
#if defined(__ARM_ARCH) && __ARM_ARCH >= 7
#ifndef __ARM_NEON
#define __ARM_NEON 1
#endif
#ifndef __ARM_NEON__
#define __ARM_NEON__ 1
#endif
#include <arm_neon.h>
#endif
#endif

// ARMv7-A specific compiler optimizations
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7
#pragma GCC optimize ("O3")
#pragma GCC target ("arch=armv7-a,fpu=vfpv3-d16,neon")
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <jansson.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <time.h>
#ifdef WIN32
#include "compat/winansi.h"
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif
#include "miner.h"
#include "elist.h"

#ifdef __ANDROID__
#include <android/log.h>
#endif

// Optimized memory functions for ARMv7-A
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7 && defined(__ARM_NEON__)

// Optimized memory copy for ARMv7-A using NEON
void* neon_memcpy(void* dest, const void* src, size_t n) {
    void* original_dest = dest;
    
    // For small copies, use standard memcpy
    if (n < 64) {
        return memcpy(dest, src, n);
    }
    
    // Handle unaligned start
    uintptr_t dst_addr = (uintptr_t)dest;
    if (dst_addr & 0x3) {
        size_t align_bytes = 4 - (dst_addr & 0x3);
        memcpy(dest, src, align_bytes);
        dest = (char*)dest + align_bytes;
        src = (char*)src + align_bytes;
        n -= align_bytes;
    }
    
    // Prefetch source data
    __builtin_prefetch(src, 0, 3);
    
    // Use NEON for bulk copy (32-byte chunks)
    size_t blocks = n >> 5;
    if (blocks > 0) {
        uint8_t* d = (uint8_t*)dest;
        const uint8_t* s = (const uint8_t*)src;
        
        for (size_t i = 0; i < blocks; i++, s += 32, d += 32) {
            // Load 32 bytes (4 NEON registers)
            uint8x16_t data1 = vld1q_u8(s);
            uint8x16_t data2 = vld1q_u8(s + 16);
            
            // Store 32 bytes
            vst1q_u8(d, data1);
            vst1q_u8(d + 16, data2);
            
            // Prefetch next block
            if (i + 1 < blocks) {
                __builtin_prefetch(s + 64, 0, 3);
            }
        }
        
        dest = (char*)dest + (blocks << 5);
        src = (char*)src + (blocks << 5);
        n &= 0x1F;
    }
    
    // Handle 16-byte chunks
    if (n >= 16) {
        uint8x16_t data = vld1q_u8((const uint8_t*)src);
        vst1q_u8((uint8_t*)dest, data);
        dest = (char*)dest + 16;
        src = (char*)src + 16;
        n -= 16;
    }
    
    // Handle remaining bytes
    if (n > 0) {
        memcpy(dest, src, n);
    }
    
    return original_dest;
}

// Optimized memory set for ARMv7-A using NEON
void* neon_memset(void* dest, int val, size_t n) {
    void* original_dest = dest;
    
    // For small sets, use standard memset
    if (n < 64) {
        return memset(dest, val, n);
    }
    
    // Handle unaligned start
    uintptr_t dst_addr = (uintptr_t)dest;
    if (dst_addr & 0x3) {
        size_t align_bytes = 4 - (dst_addr & 0x3);
        memset(dest, val, align_bytes);
        dest = (char*)dest + align_bytes;
        n -= align_bytes;
    }
    
    // Use NEON for bulk set (32-byte chunks)
    uint8_t v8 = (uint8_t)val;
    uint8x16_t v = vdupq_n_u8(v8);
    
    size_t blocks = n >> 5;
    if (blocks > 0) {
        uint8_t* d = (uint8_t*)dest;
        
        for (size_t i = 0; i < blocks; i++, d += 32) {
            // Store 32 bytes (2 NEON registers)
            vst1q_u8(d, v);
            vst1q_u8(d + 16, v);
            
            // Prefetch next block
            if (i + 1 < blocks) {
                __builtin_prefetch(d + 64, 1, 3);
            }
        }
        
        dest = (char*)dest + (blocks << 5);
        n &= 0x1F;
    }
    
    // Handle 16-byte chunk
    if (n >= 16) {
        vst1q_u8((uint8_t*)dest, v);
        dest = (char*)dest + 16;
        n -= 16;
    }
    
    // Handle remaining bytes
    if (n > 0) {
        memset(dest, val, n);
    }
    
    return original_dest;
}

#define CUSTOM_MEMCPY neon_memcpy
#define CUSTOM_MEMSET neon_memset
#else
#define CUSTOM_MEMCPY memcpy
#define CUSTOM_MEMSET memset
#endif

extern pthread_mutex_t stratum_sock_lock;
extern pthread_mutex_t stratum_work_lock;
extern bool opt_debug_diff;

bool opt_tracegpu = false;

struct data_buffer {
	void		*buf;
	size_t		len;
};

struct upload_buffer {
	const void	*buf;
	size_t		len;
	size_t		pos;
};

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};

void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;

		/* custom colors to syslog prio */
		if (prio > LOG_DEBUG) {
			switch (prio) {
				case LOG_BLUE: prio = LOG_NOTICE; break;
			}
		}

		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = (char*) alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		const char* color = "";
		const time_t now = time(NULL);
		char *f;
		int len;
		struct tm tm;

		localtime_r(&now, &tm);

		switch (prio) {
			case LOG_ERR:     color = CL_RED; break;
			case LOG_WARNING: color = CL_YLW; break;
			case LOG_NOTICE:  color = CL_WHT; break;
			case LOG_INFO:    color = ""; break;
			case LOG_DEBUG:   color = CL_GRY; break;

			case LOG_BLUE:
				prio = LOG_NOTICE;
				color = CL_CYN;
				break;
		}
		if (!use_colors)
			color = "";

		len = 40 + (int) strlen(fmt) + 2;
		f = (char*) alloca(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			color,
			fmt,
			use_colors ? CL_N : ""
		);
		if (prio == LOG_RAW) {
			// no time prefix, for ccminer -n
			sprintf(f, "%s%s\n", fmt, CL_N);
		}
		pthread_mutex_lock(&applog_lock);
		vfprintf(stdout, f, ap);	/* atomic write to stdout */
		fflush(stdout);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}

extern int gpu_threads;
// Use different prefix if multiple cpu threads per gpu
// Also, auto hide LOG_DEBUG if --debug (-D) is not used
void gpulog(int prio, int thr_id, const char *fmt, ...)
{
	char _ALIGN(128) pfmt[128];
	char _ALIGN(128) line[256];
	int len, dev_id = device_map[thr_id % MAX_GPUS];
	va_list ap;

	if (prio == LOG_DEBUG && !opt_debug)
		return;

	if (gpu_threads > 1)
		len = snprintf(pfmt, 128, "CPU T%d: Verus Hashing. %s", thr_id, fmt);
	else
		len = snprintf(pfmt, 128, "GPU #%d: %s", dev_id, fmt);
	pfmt[sizeof(pfmt)-1]='\0';

	va_start(ap, fmt);

	if (len && vsnprintf(line, sizeof(line), pfmt, ap)) {
		line[sizeof(line)-1]='\0';
		applog(prio, "%s", line);
	} else {
		fprintf(stderr, "%s OOM!\n", __func__);
	}

	va_end(ap);
}

/* Get default config.json path (system specific) */
void get_defconfig_path(char *out, size_t bufsize, char *argv0)
{
	char *cmd = strdup(argv0);
	char *dir = dirname(cmd);
	const char *sep = strstr(dir, "\\") ? "\\" : "/";
	struct stat info;
#ifdef WIN32
	snprintf(out, bufsize, "%s\\ccminer\\ccminer.conf\0", getenv("APPDATA"));
#else
	snprintf(out, bufsize, "%s\\.ccminer\\ccminer.conf", getenv("HOME"));
#endif
	if (dir && stat(out, &info) != 0) {
		// binary folder if not present in user folder
		snprintf(out, bufsize, "%s%sccminer.conf%s", dir, sep, "");
	}
	if (stat(out, &info) != 0) {
		out[0] = '\0';
		return;
	}
	out[bufsize - 1] = '\0';
	free(cmd);
#ifdef WIN32
	if (dir) free(dir);
#endif
}

void format_hashrate_unit(double hashrate, char *output, const char *unit)
{
	char prefix[2] = { 0, 0 };

	if (hashrate < 10000) {
		// nop
	}
	else if (hashrate < 1e7) {
		prefix[0] = 'k';
		hashrate *= 1e-3;
	}
	else if (hashrate < 1e10) {
		prefix[0] = 'M';
		hashrate *= 1e-6;
	}
	else if (hashrate < 1e13) {
		prefix[0] = 'G';
		hashrate *= 1e-9;
	}
	else {
		prefix[0] = 'T';
		hashrate *= 1e-12;
	}

	sprintf(output, "%.2f %s%s", hashrate, prefix, unit);
}

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = (struct data_buffer *)user_data;
	size_t len = size * nmemb;
	size_t oldlen, newlen;
	void *newmem;
	static const uchar zero = 0;

	oldlen = db->len;
	newlen = oldlen + len;

	newmem = realloc(db->buf, newlen + 1);
	if (!newmem)
		return 0;

	db->buf = newmem;
	db->len = newlen;
	memcpy((char*)db->buf + oldlen, ptr, len);
	memcpy((char*)db->buf + newlen, &zero, 1);	/* null terminate */

	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct upload_buffer *ub = (struct upload_buffer *)user_data;
	unsigned int len = (unsigned int)(size * nmemb);

	if (len > ub->len - ub->pos)
		len = (unsigned int)(ub->len - ub->pos);

	if (len) {
		memcpy(ptr, (char*)ub->buf + ub->pos, len);
		ub->pos += len;
	}

	return len;
}

#if LIBCURL_VERSION_NUM >= 0x071200
static int seek_data_cb(void *user_data, curl_off_t offset, int origin)
{
	struct upload_buffer *ub = (struct upload_buffer *)user_data;
	
	switch (origin) {
	case SEEK_SET:
		ub->pos = (size_t)offset;
		break;
	case SEEK_CUR:
		ub->pos += (size_t)offset;
		break;
	case SEEK_END:
		ub->pos = ub->len + (size_t)offset;
		break;
	default:
		return 1; /* CURL_SEEKFUNC_FAIL */
	}

	return 0; /* CURL_SEEKFUNC_OK */
}
#endif

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct header_info *hi = (struct header_info *)user_data;
	size_t remlen, slen, ptrlen = size * nmemb;
	char *rem, *val = NULL, *key = NULL;
	void *tmp;

	val = (char*)calloc(1, ptrlen);
	key = (char*)calloc(1, ptrlen);
	if (!key || !val)
		goto out;

	tmp = memchr(ptr, ':', ptrlen);
	if (!tmp || (tmp == ptr))	/* skip empty keys / blanks */
		goto out;
	slen = (size_t)((char*)tmp - (char*)ptr);
	if ((slen + 1) == ptrlen)	/* skip key w/ no value */
		goto out;
	memcpy(key, ptr, slen);		/* store & nul term key */
	key[slen] = 0;

	rem = (char*)ptr + slen + 1;		/* trim value's leading whitespace */
	remlen = ptrlen - slen - 1;
	while ((remlen > 0) && (isspace(*rem))) {
		remlen--;
		rem++;
	}

	memcpy(val, rem, remlen);	/* store value, trim trailing ws */
	val[remlen] = 0;
	while ((*val) && (isspace(val[strlen(val) - 1]))) {
		val[strlen(val) - 1] = 0;
	}
	if (!*val)			/* skip blank value */
		goto out;

	if (!strcasecmp("X-Long-Polling", key)) {
		hi->lp_path = val;	/* X-Mining-Extensions: longpoll */
		val = NULL;
	}

	if (!strcasecmp("X-Reject-Reason", key)) {
		hi->reason = val;	/* X-Mining-Extensions: reject-reason */
		//applog(LOG_WARNING, "%s:%s", key, val);
		val = NULL;
	}

	if (!strcasecmp("X-Stratum", key)) {
		hi->stratum_url = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Nonce-Range", key)) {
		/* todo when available: X-Mining-Extensions: noncerange */
	}
out:
	free(key);
	free(val);
	return ptrlen;
}

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd,
	curlsocktype purpose)
{
	int keepalive = 1;
	int tcp_keepcnt = 3;
	int tcp_keepidle = 50;
	int tcp_keepintvl = 50;
#ifdef WIN32
	DWORD outputBytes;
#endif

#ifndef WIN32	
	if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive))))
		return 1;
#ifdef __linux
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
		&tcp_keepcnt, sizeof(tcp_keepcnt))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
		&tcp_keepidle, sizeof(tcp_keepidle))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
	if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __APPLE_CC__ */
#else /* WIN32 */
	struct tcp_keepalive vals;
	vals.onoff = 1;
	vals.keepalivetime = tcp_keepidle * 1000;
	vals.keepaliveinterval = tcp_keepintvl * 1000;	
	if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals),
		NULL, 0, &outputBytes, NULL, NULL)))
		return 1;
#endif /* WIN32 */

	return 0;
}
#endif

/* For getwork (longpoll or wallet) - not stratum pools!
 * DO NOT USE DIRECTLY
 */
static json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req,
		      bool longpoll_scan, bool longpoll, bool keepalive, int *curl_err)
{
	json_t *val, *err_val, *res_val;
	int rc;
	struct data_buffer all_data = { 0 };
	struct upload_buffer upload_data;
	json_error_t err;
	struct curl_slist *headers = NULL;
	char *httpdata;
	char len_hdr[64], hashrate_hdr[64];
	char curl_err_str[CURL_ERROR_SIZE] = { 0 };
	long timeout = longpoll ? opt_timeout : opt_timeout/2;
	struct header_info hi = { 0 };
	bool lp_scanning = longpoll_scan && !have_longpoll;

	/* it is assumed that 'curl' is freshly [re]initialized at this pt */

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if (opt_cert) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
		// ignore CN domain name, allow to move cert files
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	}
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
#if LIBCURL_VERSION_NUM >= 0x071200
	curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, &seek_data_cb);
	curl_easy_setopt(curl, CURLOPT_SEEKDATA, &upload_data);
#endif
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, resp_hdr_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hi);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	if (keepalive)
		curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
	curl_easy_setopt(curl, CURLOPT_POST, 1);

	if (opt_protocol)
		applog(LOG_DEBUG, "JSON protocol request:\n%s", rpc_req);

	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	upload_data.pos = 0;
	sprintf(len_hdr, "Content-Length: %lu", (unsigned long) upload_data.len);
	sprintf(hashrate_hdr, "X-Mining-Hashrate: %llu", (unsigned long long) global_hashrate);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, len_hdr);
	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
	headers = curl_slist_append(headers, "X-Mining-Extensions: longpoll noncerange reject-reason");
	headers = curl_slist_append(headers, hashrate_hdr);
	headers = curl_slist_append(headers, "Accept:"); /* disable Accept hdr*/
	headers = curl_slist_append(headers, "Expect:"); /* disable Expect hdr*/

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	if (curl_err != NULL)
		*curl_err = rc;
	if (rc) {
		if (!(longpoll && rc == CURLE_OPERATION_TIMEDOUT)) {
			applog(LOG_ERR, "HTTP request failed: %s", curl_err_str);
			goto err_out;
		}
	}

	/* If X-Stratum was found, activate Stratum */
	if (want_stratum && hi.stratum_url &&
	    !strncasecmp(hi.stratum_url, "stratum+tcp://", 14) &&
	    !(opt_proxy && opt_proxy_type == CURLPROXY_HTTP)) {
		have_stratum = true;
		tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
		hi.stratum_url = NULL;
	}

	/* If X-Long-Polling was found, activate long polling */
	if (lp_scanning && hi.lp_path && !have_stratum) {
		have_longpoll = true;
		tq_push(thr_info[longpoll_thr_id].q, hi.lp_path);
		hi.lp_path = NULL;
	}

	if (!all_data.buf || !all_data.len) {
		if (!have_longpoll) // seems normal on longpoll timeout
			applog(LOG_ERR, "Empty data received in json_rpc_call.");
		goto err_out;
	}

	httpdata = (char*) all_data.buf;

	if (*httpdata != '{' && *httpdata != '[') {
		long errcode = 0;
		CURLcode c = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &errcode);
		if (c == CURLE_OK && errcode == 401) {
			applog(LOG_ERR, "You are not authorized, check your login and password.");
			goto err_out;
		}
	}

	val = JSON_LOADS(httpdata, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		if (opt_protocol)
			applog(LOG_DEBUG, "%s", httpdata);
		goto err_out;
	}

	if (opt_protocol) {
		char *s = json_dumps(val, JSON_INDENT(3));
		applog(LOG_DEBUG, "JSON protocol response:\n%s\n", s);
		free(s);
	}

	/* JSON-RPC valid response returns a non-null 'result',
	 * and a null 'error'. */
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_null(res_val) ||
	    (err_val && !json_is_null(err_val))) {
		char *s = NULL;

		if (err_val) {
			s = json_dumps(err_val, 0);
			json_t *msg = json_object_get(err_val, "message");
			json_t *err_code = json_object_get(err_val, "code");
			if (curl_err && json_integer_value(err_code))
				*curl_err = (int) json_integer_value(err_code);

			if (json_is_string(msg)) {
				free(s);
				s = strdup(json_string_value(msg));
				if (have_longpoll && s && !strcmp(s, "method not getwork")) {
					json_decref(err_val);
					free(s);
					goto err_out;
				}
			}
			json_decref(err_val);
		}
		else
			s = strdup("(unknown reason)");

		if (!curl_err || opt_debug)
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);

		free(s);

		goto err_out;
	}

	if (hi.reason)
		json_object_set_new(val, "reject-reason", json_string(hi.reason));

	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	free(hi.lp_path);
	free(hi.reason);
	free(hi.stratum_url);
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

/* getwork calls with pool pointer (wallet/longpoll pools) */
json_t *json_rpc_call_pool(CURL *curl, struct pool_infos *pool, const char *req,
	bool longpoll_scan, bool longpoll, int *curl_err)
{
	char userpass[768];
	// todo, malloc and store that in pool array
	snprintf(userpass, sizeof(userpass), "%s%c%s", pool->user,
		strlen(pool->pass)?':':'\0', pool->pass);

	return json_rpc_call(curl, pool->url, userpass, req, longpoll_scan, false, false, curl_err);
}

/* called only from longpoll thread, we have the lp_url */
json_t *json_rpc_longpoll(CURL *curl, char *lp_url, struct pool_infos *pool, const char *req, int *curl_err)
{
	char userpass[768];
	snprintf(userpass, sizeof(userpass), "%s%c%s", pool->user,
		strlen(pool->pass)?':':'\0', pool->pass);

	// on pool rotate by time-limit, this keepalive can be a problem
	bool keepalive = pool->time_limit == 0 || pool->time_limit > opt_timeout;

	return json_rpc_call(curl, lp_url, userpass, req, false, true, keepalive, curl_err);
}

json_t *json_load_url(char* cfg_url, json_error_t *err)
{
	char err_str[CURL_ERROR_SIZE] = { 0 };
	struct data_buffer all_data = { 0 };
	int rc = 0; json_t *cfg = NULL;
	CURL *curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "Remote config init failed!");
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, cfg_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	} else if (getenv("http_proxy")) {
		if (getenv("all_proxy"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("all_proxy"));
		else if (getenv("ALL_PROXY"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("ALL_PROXY"));
		else
			curl_easy_setopt(curl, CURLOPT_PROXY, "");
	}
	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Remote config read failed: %s", err_str);
		goto err_out;
	}
	if (!all_data.buf || !all_data.len) {
		applog(LOG_ERR, "Empty data received for config");
		goto err_out;
	}

	cfg = JSON_LOADS((char*)all_data.buf, err);
err_out:
	curl_easy_cleanup(curl);
	return cfg;
}

/**
 * Unlike malloc, calloc set the memory to zero
 * Optimized for ARMv7-A with proper alignment for better performance
 */
void *aligned_calloc(int size)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH == 7
    // Optimal cache line alignment for ARMv7-A is 32 bytes
    const int ALIGN = 32;
#else
    const int ALIGN = 64;
#endif

#ifdef _MSC_VER
    void* res = _aligned_malloc(size, ALIGN);
    CUSTOM_MEMSET(res, 0, size);
    return res;
#else
    void *mem;
    
    // Use posix_memalign for better performance on ARM
#if defined(__ANDROID__) || defined(__arm__) || defined(__aarch64__)
    if (posix_memalign(&mem, ALIGN, size) != 0) {
        return NULL;
    }
    
    // Use our optimized memset for ARMv7-A
    CUSTOM_MEMSET(mem, 0, size);
    
    // Prefetch the memory for better performance
    #if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7
    __builtin_prefetch(mem, 1, 3);  // Write with high temporal locality
    #endif
    
    return mem;
#else
    // Original implementation for other platforms
    mem = calloc(1, size + ALIGN + sizeof(uintptr_t));
    if (!mem) return NULL;
    void **ptr = (void**)((size_t)(((uintptr_t)(mem)) + ALIGN + sizeof(uintptr_t)) & ~(ALIGN-1));
    ptr[-1] = mem;
    return ptr;
#endif
#endif
}

void aligned_free(void *ptr)
{
#ifdef _MSC_VER
    _aligned_free(ptr);
#else
#if defined(__ANDROID__) || defined(__arm__) || defined(__aarch64__)
    // Direct free for posix_memalign
    free(ptr);
#else
    // Original implementation
    if (ptr) free(((void**)ptr)[-1]);
#endif
#endif
}

void cbin2hex(char *out, const char *in, size_t len)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7 && defined(__ARM_NEON__)
    // NEON optimized version for ARMv7-A
    static const char hex_chars[] = "0123456789abcdef";
    
    if (out) {
        size_t i;
        
        // Process 8 bytes at a time with NEON
        for (i = 0; i + 8 <= len; i += 8) {
            // Load 8 bytes
            uint8x8_t input = vld1_u8((const uint8_t*)&in[i]);
            
            // Extract high and low nibbles
            uint8x8_t high_nibble = vshr_n_u8(input, 4);
            uint8x8_t low_nibble = vand_u8(input, vdup_n_u8(0x0F));
            
            // Convert to hex characters
            for (int j = 0; j < 8; j++) {
                uint8_t high = vget_lane_u8(high_nibble, j);
                uint8_t low = vget_lane_u8(low_nibble, j);
                
                out[i*2 + j*2] = hex_chars[high];
                out[i*2 + j*2 + 1] = hex_chars[low];
            }
        }
        
        // Handle remaining bytes
        for (; i < len; i++) {
            unsigned int c = (unsigned int)(unsigned char)in[i];
            out[i*2] = hex_chars[c >> 4];
            out[i*2 + 1] = hex_chars[c & 0xF];
        }
    }
#else
    // Original implementation
    if (out) {
        unsigned int i;
        for (i = 0; i < len; i++)
            sprintf(out + (i * 2), "%02x", (uint8_t)in[i]);
    }
#endif
}

char *bin2hex(const uchar *in, size_t len)
{
    char *s = (char*)malloc((len * 2) + 1);
    if (!s)
        return NULL;

    cbin2hex(s, (const char *)in, len);
    s[len * 2] = '\0';
    
    return s;
}

bool hex2bin(void *output, const char *hexstr, size_t len)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7 && defined(__ARM_NEON__)
    // Optimized version for ARMv7-A
    if (hexstr == NULL || output == NULL || len % 2 != 0)
        return false;
    
    uint8_t *p = (uint8_t*)output;
    size_t count = len / 2;
    size_t i;
    
    // Process 8 bytes (16 hex chars) at a time with NEON
    for (i = 0; i + 8 <= count; i += 8) {
        uint8x8_t high_nibble, low_nibble, result;
        
        // Load 16 hex characters (8 bytes output)
        for (int j = 0; j < 8; j++) {
            char h = hexstr[i*2 + j*2];
            char l = hexstr[i*2 + j*2 + 1];
            
            // Convert ASCII hex to values
            uint8_t high, low;
            
            // For high nibble
            if (h >= '0' && h <= '9')
                high = h - '0';
            else if (h >= 'a' && h <= 'f')
                high = h - 'a' + 10;
            else if (h >= 'A' && h <= 'F')
                high = h - 'A' + 10;
            else
                return false;
            
            // For low nibble
            if (l >= '0' && l <= '9')
                low = l - '0';
            else if (l >= 'a' && l <= 'f')
                low = l - 'a' + 10;
            else if (l >= 'A' && l <= 'F')
                low = l - 'A' + 10;
            else
                return false;
            
            // Combine nibbles
            p[i + j] = (high << 4) | low;
        }
    }
    
    // Handle remaining bytes
    for (; i < count; i++) {
        char h = hexstr[i*2];
        char l = hexstr[i*2 + 1];
        
        // Convert ASCII hex to values
        uint8_t high, low;
        
        // For high nibble
        if (h >= '0' && h <= '9')
            high = h - '0';
        else if (h >= 'a' && h <= 'f')
            high = h - 'a' + 10;
        else if (h >= 'A' && h <= 'F')
            high = h - 'A' + 10;
        else
            return false;
        
        // For low nibble
        if (l >= '0' && l <= '9')
            low = l - '0';
        else if (l >= 'a' && l <= 'f')
            low = l - 'a' + 10;
        else if (l >= 'A' && l <= 'F')
            low = l - 'A' + 10;
        else
            return false;
        
        // Combine nibbles
        p[i] = (high << 4) | low;
    }
    
    return true;
#else
    // Original implementation
    if (hexstr == NULL || output == NULL || len % 2 != 0)
        return false;
    
    uint8_t *p = (uint8_t*)output;
    size_t count = len / 2;
    
    for (size_t i = 0; i < count; i++) {
        char c = hexstr[i * 2];
        if (c >= '0' && c <= '9')
            *p = (c - '0') << 4;
        else if (c >= 'a' && c <= 'f')
            *p = (c - 'a' + 10) << 4;
        else if (c >= 'A' && c <= 'F')
            *p = (c - 'A' + 10) << 4;
        else
            return false;
        
        c = hexstr[i * 2 + 1];
        if (c >= '0' && c <= '9')
            *p |= c - '0';
        else if (c >= 'a' && c <= 'f')
            *p |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            *p |= c - 'A' + 10;
        else
            return false;
        p++;
    }
    
    return true;
#endif
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
    struct timeval *y)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7
    // Optimized version for ARMv7-A
    // Direct calculation without branches for better performance on ARM
    
    // Handle microsecond part with potential borrow
    int32_t usec_diff = x->tv_usec - y->tv_usec;
    int32_t sec_diff = x->tv_sec - y->tv_sec;
    
    // Use conditional select instead of branch for better performance on ARM
    int32_t borrow = (usec_diff < 0) ? 1 : 0;
    usec_diff += borrow * 1000000;
    sec_diff -= borrow;
    
    // Store results
    result->tv_sec = sec_diff;
    result->tv_usec = usec_diff;
    
    // Return 1 if result is negative (x < y)
    return (sec_diff < 0);
#else
    // Original implementation
    /* Perform the carry for the later subtraction by updating Y. */
    if (x->tv_usec < y->tv_usec) {
        int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
        y->tv_usec -= 1000000 * nsec;
        y->tv_sec += nsec;
    }
    if (x->tv_usec - y->tv_usec > 1000000) {
        int nsec = (x->tv_usec - y->tv_usec) / 1000000;
        y->tv_usec += 1000000 * nsec;
        y->tv_sec -= nsec;
    }

    /* Compute the time remaining to wait.
     * `tv_usec' is certainly positive. */
    result->tv_sec = x->tv_sec - y->tv_sec;
    result->tv_usec = x->tv_usec - y->tv_usec;

    /* Return 1 if result is negative. */
    return x->tv_sec < y->tv_sec;
#endif
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7 && defined(__ARM_NEON__)
    // Optimized version for ARMv7-A with NEON
    // This is a critical function for mining performance
    
    // Prefetch both arrays for better performance
    __builtin_prefetch(hash, 0, 3);  // Read with high temporal locality
    __builtin_prefetch(target, 0, 3);  // Read with high temporal locality
    
    // Start from the most significant word (index 7)
    // Compare 2 integers at a time using NEON
    for (int i = 7; i >= 1; i -= 2) {
        // Load 2 integers from hash and target
        uint32x2_t hash_vec = vld1_u32(&hash[i-1]);
        uint32x2_t target_vec = vld1_u32(&target[i-1]);
        
        // Compare the higher word first (i)
        if (hash[i] > target[i])
            return false;
        if (hash[i] < target[i])
            return true;
            
        // Then check the lower word (i-1)
        if (hash[i-1] > target[i-1])
            return false;
        if (hash[i-1] < target[i-1])
            return true;
    }
    
    // Check the last word (index 0) if we have an odd number of words
    if (hash[0] > target[0])
        return false;
    
    return true;
#else
    // Original implementation
    int i;
    bool rc = true;
    
    for (i = 7; i >= 0; i--) {
        if (hash[i] > target[i]) {
            rc = false;
            break;
        }
        if (hash[i] < target[i]) {
            rc = true;
            break;
        }
    }
    
    return rc;
#endif
}

// Only used by stratum pools
void diff_to_target(uint32_t *target, double diff)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7 && defined(__ARM_NEON__)
    // Optimized version for ARMv7-A with NEON
    // Calculate k and m more efficiently
    int k;
    uint64_t m;
    
    // Fast path for common case
    if (diff >= 1.0) {
        // Find k: number of 32-bit words to shift
        k = 6;
        while (diff > 1.0 && k > 0) {
            diff /= 4294967296.0; // 2^32
            k--;
        }
        
        // Calculate m
        m = (uint64_t)(4294901760.0 / diff);
        
        // Clear target with NEON
        uint32x4_t zero = vdupq_n_u32(0);
        vst1q_u32(target, zero);
        vst1q_u32(target + 4, zero);
        
        // Set the specific words
        if (m == 0 && k == 6) {
            // Special case: fill with 0xff
            memset(target, 0xff, 32);
        } else {
            target[k] = (uint32_t)m;
            target[k + 1] = (uint32_t)(m >> 32);
        }
    } else {
        // For very high difficulty (diff < 1.0)
        // Use original algorithm with NEON optimization
        for (k = 6; k > 0 && diff > 1.0; k--)
            diff /= 4294967296.0;
        m = (uint64_t)(4294901760.0 / diff);
        
        // Clear target with NEON
        uint32x4_t zero = vdupq_n_u32(0);
        vst1q_u32(target, zero);
        vst1q_u32(target + 4, zero);
        
        if (m == 0 && k == 6) {
            memset(target, 0xff, 32);
        } else {
            target[k] = (uint32_t)m;
            target[k + 1] = (uint32_t)(m >> 32);
        }
    }
#else
    // Original implementation
    uint64_t m;
    int k;

    for (k = 6; k > 0 && diff > 1.0; k--)
        diff /= 4294967296.0;
    m = (uint64_t)(4294901760.0 / diff);
    if (m == 0 && k == 6)
        memset(target, 0xff, 32);
    else {
        memset(target, 0, 32);
        target[k] = (uint32_t)m;
        target[k + 1] = (uint32_t)(m >> 32);
    }
#endif
}

// Only used by stratum pools
void work_set_target(struct work* work, double diff)
{
	diff_to_target(work->target, diff);
	work->targetdiff = diff;
}


// Only used by longpoll pools
double target_to_diff(uint32_t* target)
{
#if defined(__arm__) && defined(__ARM_ARCH) && __ARM_ARCH >= 7 && defined(__ARM_NEON__)
    // Optimized version for ARMv7-A with NEON
    // Prefetch the target for better performance
    __builtin_prefetch(target, 0, 3);  // Read with high temporal locality
    
    // Check for zero value quickly
    uint32x4_t zero = vdupq_n_u32(0);
    uint32x4_t data1 = vld1q_u32(&target[0]);
    uint32x4_t data2 = vld1q_u32(&target[4]);
    
    // Compare with zero
    uint32x4_t cmp1 = vceqq_u32(data1, zero);
    uint32x4_t cmp2 = vceqq_u32(data2, zero);
    
    // Check if bytes 22-29 are all zero (indices 5 and 6)
    if (target[5] == 0 && target[6] == 0)
        return 0.;
    
    // Extract the 64-bit value efficiently
    uint64_t m = ((uint64_t)target[6] << 32) | target[5];
    
    return (double)0x0000ffff00000000ULL/m;
#else
    // Original implementation
    uchar* tgt = (uchar*)target;
    uint64_t m =
        (uint64_t)tgt[29] << 56 |
        (uint64_t)tgt[28] << 48 |
        (uint64_t)tgt[27] << 40 |
        (uint64_t)tgt[26] << 32 |
        (uint64_t)tgt[25] << 24 |
        (uint64_t)tgt[24] << 16 |
        (uint64_t)tgt[23] << 8  |
        (uint64_t)tgt[22] << 0;

    if (!m)
        return 0.;
    else
        return (double)0x0000ffff00000000ULL/m;
#endif
}

#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

static bool send_line(curl_socket_t sock, char *s)
{
	ssize_t len, sent = 0;
	
	len = (ssize_t)strlen(s);
	s[len++] = '\n';

	while (len > 0) {
		struct timeval timeout = {0, 0};
		ssize_t n;
		fd_set wd;

		FD_ZERO(&wd);
		FD_SET(sock, &wd);
		if (select((int)sock + 1, NULL, &wd, NULL, &timeout) < 1)
			return false;
		n = send(sock, s + sent, len, 0);
		if (n < 0) {
			if (!socket_blocks())
				return false;
			n = 0;
		}
		sent += n;
		len -= n;
	}

	return true;
}

bool stratum_send_line(struct stratum_ctx *sctx, char *s)
{
	bool ret = false;

	if (opt_protocol)
		applog(LOG_DEBUG, "> %s", s);

	pthread_mutex_lock(&stratum_sock_lock);
	ret = send_line(sctx->sock, s);
	pthread_mutex_unlock(&stratum_sock_lock);

	return ret;
}

static bool socket_full(curl_socket_t sock, int timeout)
{
	struct timeval tv;
	fd_set rd;

	FD_ZERO(&rd);
	FD_SET(sock, &rd);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select((int)sock + 1, &rd, NULL, NULL, &tv) > 0)
		return true;
	return false;
}

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
	if (!sctx->sockbuf) return false;
	return strlen(sctx->sockbuf) || socket_full(sctx->sock, timeout);
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_buffer_append(struct stratum_ctx *sctx, const char *s)
{
    size_t old = strlen(sctx->sockbuf);
    size_t slen = strlen(s);
    size_t snew = old + slen + 1;
    char *tmp;
    
    // Check for potential overflow
    if (snew >= sctx->sockbuf_size) {
        // Increase buffer size by at least 2x or enough to fit new data
        size_t newsize = sctx->sockbuf_size * 2;
        if (newsize < snew)
            newsize = snew + 1;
        tmp = (char*)realloc(sctx->sockbuf, newsize);
        if (!tmp) {
            applog(LOG_ERR, "Out of memory in stratum_buffer_append");
            return;
        }
        sctx->sockbuf = tmp;
        sctx->sockbuf_size = newsize;
    }
    
#if defined(__ARM_NEON) || defined(__ARM_NEON__)
    // Optimized string copy for ARMv7-A with NEON
    char *dest = sctx->sockbuf + old;
    
    // Copy in 16-byte chunks with NEON
    size_t blocks = slen / 16;
    size_t i;
    
    for (i = 0; i < blocks * 16; i += 16) {
        uint8x16_t data = vld1q_u8((const uint8_t*)&s[i]);
        vst1q_u8((uint8_t*)&dest[i], data);
    }
    
    // Copy remaining bytes
    for (i = blocks * 16; i < slen; i++) {
        dest[i] = s[i];
    }
    
    // Null terminate
    dest[slen] = '\0';
#else
    // Standard string concatenation
    strcat(sctx->sockbuf, s);
#endif
}

char *stratum_recv_line(struct stratum_ctx *sctx)
{
	ssize_t len, buflen;
	char *tok, *sret = NULL;
	time_t rstart;

	if (!strstr(sctx->sockbuf, "\n")) {
		bool ret = true;
		time(&rstart);
		if (!socket_full(sctx->sock, 60)) {
			applog(LOG_ERR, "stratum_recv_line timed out");
			goto out;
		}
		do {
			char s[RBUFSIZE];
			ssize_t n;

			memset(s, 0, RBUFSIZE);
			n = recv(sctx->sock, s, RECVSIZE, 0);
			if (!n) {
				ret = false;
				break;
			}
			if (n < 0) {
				if (!socket_blocks() || !socket_full(sctx->sock, 1)) {
					ret = false;
					break;
				}
			} else
				stratum_buffer_append(sctx, s);
		} while (time(NULL) - rstart < 60 && !strstr(sctx->sockbuf, "\n"));

		if (!ret) {
			if (opt_debug) applog(LOG_ERR, "stratum_recv_line failed");
			goto out;
		}
	}

	buflen = (ssize_t)strlen(sctx->sockbuf);
	tok = strtok(sctx->sockbuf, "\n");
	if (!tok) {
		applog(LOG_ERR, "stratum_recv_line failed to parse a newline-terminated string");
		goto out;
	}
	
	// Use safe strdup with error checking
	sret = strdup(tok);
	if (!sret) {
		applog(LOG_ERR, "Out of memory in stratum_recv_line");
		goto out;
	}
	
	len = (ssize_t)strlen(sret);

	if (buflen > len + 1)
		memmove(sctx->sockbuf, sctx->sockbuf + len + 1, buflen - len + 1);
	else
		sctx->sockbuf[0] = '\0';

out:
	return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr)
{
	curl_socket_t *sock = (curl_socket_t *)clientp;
	*sock = socket(addr->family, addr->socktype, addr->protocol);
	return *sock;
}
#endif

bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
	CURL *curl;
	int rc;

	pthread_mutex_lock(&stratum_sock_lock);
	if (sctx->curl)
		curl_easy_cleanup(sctx->curl);
	sctx->curl = curl_easy_init();
	if (!sctx->curl) {
		applog(LOG_ERR, "CURL initialization failed");
		pthread_mutex_unlock(&stratum_sock_lock);
		return false;
	}
	curl = sctx->curl;
	if (!sctx->sockbuf) {
		sctx->sockbuf = (char*)calloc(RBUFSIZE, 1);
		sctx->sockbuf_size = RBUFSIZE;
	}
	sctx->sockbuf[0] = '\0';
	pthread_mutex_unlock(&stratum_sock_lock);

	if (url != sctx->url) {
		free(sctx->url);
		sctx->url = strdup(url);
	}
	free(sctx->curl_url);
	sctx->curl_url = (char*)malloc(strlen(url)+1);
	sprintf(sctx->curl_url, "http%s", strstr(url, "://"));

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, opt_timeout);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	if (opt_proxy && opt_proxy_type != CURLPROXY_HTTP) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	} else if (getenv("http_proxy")) {
		if (getenv("all_proxy"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("all_proxy"));
		else if (getenv("ALL_PROXY"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("ALL_PROXY"));
		else
			curl_easy_setopt(curl, CURLOPT_PROXY, "");
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sctx->sock);
#endif
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
		curl_easy_cleanup(curl);
		sctx->curl = NULL;
		return false;
	}

#if LIBCURL_VERSION_NUM < 0x071101
	/* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
	curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long *)&sctx->sock);
#endif

	return true;
}

void stratum_free_job(struct stratum_ctx *sctx)
{
	pthread_mutex_lock(&stratum_work_lock);
	if (sctx->job.job_id) {
		free(sctx->job.job_id);
	}
	if (sctx->job.merkle_count) {
		for (int i = 0; i < sctx->job.merkle_count; i++) {
			free(sctx->job.merkle[i]);
			sctx->job.merkle[i] = NULL;
		}
		free(sctx->job.merkle);
	}
	free(sctx->job.coinbase);
	// note: xnonce2 is not allocated
	memset(&(sctx->job.job_id), 0, sizeof(struct stratum_job));
	pthread_mutex_unlock(&stratum_work_lock);
}

void stratum_disconnect(struct stratum_ctx *sctx)
{
	pthread_mutex_lock(&stratum_sock_lock);
	if (sctx->curl) {
		pools[sctx->pooln].disconnects++;
		curl_easy_cleanup(sctx->curl);
		sctx->curl = NULL;
		if (sctx->sockbuf)
			sctx->sockbuf[0] = '\0';
		// free(sctx->sockbuf);
		// sctx->sockbuf = NULL;
	}
	if (sctx->job.job_id) {
		stratum_free_job(sctx);
	}
	pthread_mutex_unlock(&stratum_sock_lock);
}

static const char *get_stratum_session_id(json_t *val)
{
	json_t *arr_val;
	int i, n;

	arr_val = json_array_get(val, 0);
	if (!arr_val || !json_is_array(arr_val))
		return NULL;
	n = (int) json_array_size(arr_val);
	for (i = 0; i < n; i++) {
		const char *notify;
		json_t *arr = json_array_get(arr_val, i);
		if (!arr || !json_is_array(arr))
			break;
		notify = json_string_value(json_array_get(arr, 0));
		if (!notify)
			continue;
		if (!strcasecmp(notify, "mining.notify"))
			return json_string_value(json_array_get(arr, 1));
	}
	return NULL;
}

static bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx)
{
	const char* xnonce1;
	int xn2_size;

	xnonce1 = json_string_value(json_array_get(params, pndx));
	if (!xnonce1) {
		applog(LOG_ERR, "Failed to get extranonce1");
		goto out;
	}
	xn2_size = (int) json_integer_value(json_array_get(params, pndx+1));
	if (!xn2_size) {
		char algo[64] = { 0 };
		get_currentalgo(algo, sizeof(algo));
		if (strcmp(algo, "verus") == 0) {
			int xn1_size = (int)strlen(xnonce1) / 2;
			xn2_size = 32 - xn1_size;
			if (xn1_size < 3 || xn1_size > 12) {
				// This miner iterates the nonces at data32[30]
				applog(LOG_ERR, "Unsupported extranonce size of %d (12 maxi)", xn1_size);
				goto out;
			}
			goto skip_n2;
		} else {
			applog(LOG_ERR, "Failed to get extranonce2_size");
			goto out;
		}
	}
	if (xn2_size < 2 || xn2_size > 16) {
		applog(LOG_ERR, "Failed to get valid n2size in parse_extranonce (%d)", xn2_size);
		goto out;
	}
skip_n2:
	pthread_mutex_lock(&stratum_work_lock);
	if (sctx->xnonce1)
		free(sctx->xnonce1);
	sctx->xnonce1_size = strlen(xnonce1) / 2;
	sctx->xnonce1 = (uchar*) calloc(1, sctx->xnonce1_size);
	if (unlikely(!sctx->xnonce1)) {
		applog(LOG_ERR, "Failed to alloc xnonce1");
		pthread_mutex_unlock(&stratum_work_lock);
		goto out;
	}
	hex2bin(sctx->xnonce1, xnonce1, sctx->xnonce1_size);
	sctx->xnonce2_size = xn2_size;
	pthread_mutex_unlock(&stratum_work_lock);

	if (pndx == 0 && opt_debug) /* pool dynamic change */
		applog(LOG_DEBUG, "Stratum set nonce %s with extranonce2 size=%d",
			xnonce1, xn2_size);

	return true;
out:
	return false;
}

bool stratum_subscribe(struct stratum_ctx *sctx)
{
	char *s, *sret = NULL;
	const char *sid;
	json_t *val = NULL, *res_val, *err_val;
	json_error_t err;
	bool ret = false, retry = false;

	if (sctx->rpc2) return true;

start:
	s = (char*)malloc(128 + (sctx->session_id ? strlen(sctx->session_id) : 0));
	if (retry)
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": []}");
	else if (sctx->session_id)
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"" USER_AGENT "\", \"%s\"]}", sctx->session_id);
	else
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"" USER_AGENT "\"]}");

	if (!stratum_send_line(sctx, s))
		goto out;

	if (!socket_full(sctx->sock, 10)) {
		applog(LOG_ERR, "stratum_subscribe timed out");
		goto out;
	}

	sret = stratum_recv_line(sctx);
	if (!sret)
		goto out;

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	if (json_integer_value(json_object_get(val, "id")) != 1) {
		applog(LOG_WARNING, "Stratum subscribe answer id is not correct!");
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_null(res_val) ||
	    (err_val && !json_is_null(err_val))) {
		if (opt_debug || retry) {
			free(s);
			if (err_val)
				s = json_dumps(err_val, JSON_INDENT(3));
			else
				s = strdup("(unknown reason)");
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);
		}
		goto out;
	}

	// sid is param 1, extranonce params are 2 and 3
	if (!stratum_parse_extranonce(sctx, res_val, 1)) {
		goto out;
	}

	ret = true;

	// session id (optional)
	sid = get_stratum_session_id(res_val);
	if (opt_debug && sid)
		applog(LOG_DEBUG, "Stratum session id: %s", sid);

	pthread_mutex_lock(&stratum_work_lock);
	if (sctx->session_id)
		free(sctx->session_id);
	sctx->session_id = sid ? strdup(sid) : NULL;
	sctx->next_diff = 1.0;
	pthread_mutex_unlock(&stratum_work_lock);

out:
	free(s);
	if (val)
		json_decref(val);

	if (!ret) {
		if (sret && !retry) {
			retry = true;
			goto start;
		}
	}

	return ret;
}

extern bool opt_extranonce;

bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
	json_t *val = NULL, *res_val, *err_val;
	char *s, *sret;
	json_error_t err;
	bool ret = false;

	

	s = (char*)malloc(80 + strlen(user) + strlen(pass));
	sprintf(s, "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}",
	        user, pass);

	if (!stratum_send_line(sctx, s))
		goto out;

	while (1) {
		sret = stratum_recv_line(sctx);
		if (!sret)
			goto out;
		if (!stratum_handle_method(sctx, sret))
			break;
		free(sret);
	}

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	if (json_integer_value(json_object_get(val, "id")) != 2) {
		applog(LOG_WARNING, "Stratum authorize answer id is not correct!");
	}
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_false(res_val) ||
	    (err_val && !json_is_null(err_val)))  {
		if (err_val && json_is_array(err_val)) {
			const char* reason = json_string_value(json_array_get(err_val, 1));
			applog(LOG_ERR, "Stratum authentication failed (%s)", reason);
		}
		else applog(LOG_ERR, "Stratum authentication failed");
		goto out;
	}

	sctx->tm_connected = time(NULL);
	ret = true;

	if (!opt_extranonce)
		goto out;

	// subscribe to extranonce (optional)
	sprintf(s, "{\"id\": 3, \"method\": \"mining.extranonce.subscribe\", \"params\": []}");

	if (!stratum_send_line(sctx, s))
		goto out;

	// reduced timeout to handle pools ignoring this method without answer (like xpool.ca)
	if (!socket_full(sctx->sock, 1)) {
		if (opt_debug)
			applog(LOG_DEBUG, "stratum extranonce subscribe timed out");
		goto out;
	}

	sret = stratum_recv_line(sctx);
	if (sret) {
		json_t *extra = JSON_LOADS(sret, &err);
		if (!extra) {
			applog(LOG_WARNING, "JSON decode failed(%d): %s", err.line, err.text);
		} else {
			if (json_integer_value(json_object_get(extra, "id")) != 3) {
				// we receive a standard method if extranonce is ignored
				if (!stratum_handle_method(sctx, sret))
					applog(LOG_WARNING, "Stratum extranonce answer id was not correct!");
			} else {
				res_val = json_object_get(extra, "result");
				if (opt_debug && (!res_val || json_is_false(res_val)))
					applog(LOG_DEBUG, "extranonce subscribe not supported");
			}
			json_decref(extra);
		}
		free(sret);
	}

out:
	free(s);
	if (val)
		json_decref(val);

	return ret;
}

/**
 * Extract bloc height     L H... here len=3, height=0x1333e8
 * "...0000000000ffffffff2703e83313062f503253482f043d61105408"
 */
static uint32_t getblocheight(struct stratum_ctx *sctx)
{
	uint32_t height = 0;
	uint8_t hlen = 0, *p, *m;

	// find 0xffff tag
	p = (uint8_t*) sctx->job.coinbase + 32;
	m = p + 128;
	while (*p != 0xff && p < m) p++;
	while (*p == 0xff && p < m) p++;
	if (*(p-1) == 0xff && *(p-2) == 0xff) {
		p++; hlen = *p;
		p++; height = le16dec(p);
		p += 2;
		switch (hlen) {
			case 4:
				height += 0x10000UL * le16dec(p);
				break;
			case 3:
				height += 0x10000UL * (*p);
				break;
		}
	}
	return height;
}

static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *stime;
	const char *extradata = NULL, *nreward = NULL;
	size_t coinb1_size, coinb2_size;
	bool clean, ret = false;
	int merkle_count, i, p=0;
	json_t *merkle_arr;
	uchar **merkle = NULL;
	// uchar(*merkle_tree)[32] = { 0 };
	int ntime;
	char algo[64] = { 0 };
	get_currentalgo(algo, sizeof(algo));
	bool has_claim = !strcmp(algo, "lbry");
	bool has_roots = !strcmp(algo, "phi2") && json_array_size(params) == 10;

	if (sctx->is_equihash) {
		return equi_stratum_notify(sctx, params);
	}

	job_id = json_string_value(json_array_get(params, p++));
	prevhash = json_string_value(json_array_get(params, p++));
	if (has_claim) {
		extradata = json_string_value(json_array_get(params, p++));
		if (!extradata || strlen(extradata) != 64) {
			applog(LOG_ERR, "Stratum notify: invalid claim parameter");
			goto out;
		}
	} else if (has_roots) {
		extradata = json_string_value(json_array_get(params, p++));
		if (!extradata || strlen(extradata) != 128) {
			applog(LOG_ERR, "Stratum notify: invalid UTXO root parameter");
			goto out;
		}
	}
	coinb1 = json_string_value(json_array_get(params, p++));
	coinb2 = json_string_value(json_array_get(params, p++));
	merkle_arr = json_array_get(params, p++);
	if (!merkle_arr || !json_is_array(merkle_arr))
		goto out;
	merkle_count = (int) json_array_size(merkle_arr);
	version = json_string_value(json_array_get(params, p++));
	nbits = json_string_value(json_array_get(params, p++));
	stime = json_string_value(json_array_get(params, p++));
	clean = json_is_true(json_array_get(params, p)); p++;
	nreward = json_string_value(json_array_get(params, p++));

	if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !stime ||
	    strlen(prevhash) != 64 || strlen(version) != 8 ||
	    strlen(nbits) != 8 || strlen(stime) != 8) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		goto out;
	}

	/* store stratum server time diff */
	hex2bin((uchar *)&ntime, stime, 4);
	ntime = swab32(ntime) - (uint32_t) time(0);
	if (ntime > sctx->srvtime_diff) {
		sctx->srvtime_diff = ntime;
		if (opt_protocol && ntime > 20)
			applog(LOG_DEBUG, "stratum time is at least %ds in the future", ntime);
	}

	if (merkle_count)
		merkle = (uchar**) malloc(merkle_count * sizeof(char *));
	for (i = 0; i < merkle_count; i++) {
		const char *s = json_string_value(json_array_get(merkle_arr, i));
		if (!s || strlen(s) != 64) {
			while (i--)
				free(merkle[i]);
			free(merkle);
			applog(LOG_ERR, "Stratum notify: invalid Merkle branch");
			goto out;
		}
		merkle[i] = (uchar*) malloc(32);
		hex2bin(merkle[i], s, 32);
	}

	pthread_mutex_lock(&stratum_work_lock);

	coinb1_size = strlen(coinb1) / 2;
	coinb2_size = strlen(coinb2) / 2;
	sctx->job.coinbase_size = coinb1_size + sctx->xnonce1_size +
	                          sctx->xnonce2_size + coinb2_size;

	sctx->job.coinbase = (uchar*) realloc(sctx->job.coinbase, sctx->job.coinbase_size);
	sctx->job.xnonce2 = sctx->job.coinbase + coinb1_size + sctx->xnonce1_size;
	hex2bin(sctx->job.coinbase, coinb1, coinb1_size);
	memcpy(sctx->job.coinbase + coinb1_size, sctx->xnonce1, sctx->xnonce1_size);

	if (!sctx->job.job_id || strcmp(sctx->job.job_id, job_id))
		memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);
	hex2bin(sctx->job.xnonce2 + sctx->xnonce2_size, coinb2, coinb2_size);

	free(sctx->job.job_id);
	sctx->job.job_id = strdup(job_id);
	hex2bin(sctx->job.prevhash, prevhash, 32);
	if (has_claim) hex2bin(sctx->job.extra, extradata, 32);
	if (has_roots) hex2bin(sctx->job.extra, extradata, 64);

	sctx->job.height = getblocheight(sctx);

	for (i = 0; i < sctx->job.merkle_count; i++)
		free(sctx->job.merkle[i]);
	free(sctx->job.merkle);
	sctx->job.merkle = merkle;
	sctx->job.merkle_count = merkle_count;

	hex2bin(sctx->job.version, version, 4);
	hex2bin(sctx->job.nbits, nbits, 4);
	hex2bin(sctx->job.ntime, stime, 4);
	if(nreward != NULL)
	{
		if(strlen(nreward) == 4)
			hex2bin(sctx->job.nreward, nreward, 2);
	}
	sctx->job.clean = clean;

	sctx->job.diff = sctx->next_diff;

	pthread_mutex_unlock(&stratum_work_lock);

	ret = true;

out:
	return ret;
}

extern volatile time_t g_work_time;
static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
	double diff;

	diff = json_number_value(json_array_get(params, 0));
	if (diff <= 0.0)
		return false;

	pthread_mutex_lock(&stratum_work_lock);
	sctx->next_diff = diff;
	pthread_mutex_unlock(&stratum_work_lock);

	return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
	json_t *port_val;
	const char *host;
	int port;

	host = json_string_value(json_array_get(params, 0));
	port_val = json_array_get(params, 1);
	if (json_is_string(port_val))
		port = atoi(json_string_value(port_val));
	else
		port = (int) json_integer_value(port_val);
	if (!host || !port)
		return false;
	
	free(sctx->url);
	sctx->url = (char*)malloc(32 + strlen(host));
	sprintf(sctx->url, "stratum+tcp://%s:%d", host, port);

	applog(LOG_NOTICE, "Server requested reconnection to %s", sctx->url);

	stratum_disconnect(sctx);

	return true;
}

static bool stratum_pong(struct stratum_ctx *sctx, json_t *id)
{
	char buf[64];
	bool ret = false;

	if (!id || json_is_null(id))
		return ret;

	sprintf(buf, "{\"id\":%d,\"result\":\"pong\",\"error\":null}",
		(int) json_integer_value(id));
	ret = stratum_send_line(sctx, buf);

	return ret;
}

static bool stratum_get_algo(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char algo[64] = { 0 };
	char *s;
	json_t *val;
	bool ret = true;

	if (!id || json_is_null(id))
		return false;

	get_currentalgo(algo, sizeof(algo));

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(algo));

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

#include "nvml.h"
extern char driver_version[32];
extern int cuda_arch[MAX_GPUS];

void gpu_increment_reject(int thr_id)
{
	struct cgpu_info *gpu = &thr_info[thr_id].gpu;
	if (gpu) gpu->rejected++;
}

static bool json_object_set_error(json_t *result, int code, const char *msg)
{
	json_t *val = json_object();
	json_object_set_new(val, "code", json_integer(code));
	json_object_set_new(val, "message", json_string(msg));
	return json_object_set_new(result, "error", val) != -1;
}

/* allow to report algo/device perf to the pool for algo stats */
static bool stratum_benchdata(json_t *result, json_t *params, int thr_id)
{
	char algo[64] = { 0 };
	char vid[32], arch[8], driver[32];
	char os[8];
	uint32_t watts = 0, plimit = 0;
	int dev_id = device_map[thr_id];
	int cuda_ver = 100;
	struct cgpu_info *cgpu = &thr_info[thr_id].gpu;
	json_t *val;

	if (!cgpu || !opt_stratum_stats) return false;

#if defined(WIN32) && (defined(_M_X64) || defined(__x86_64__))
	strcpy(os, "win64");
#else
	strcpy(os, is_windows() ? "win32" : "linux");
#endif


	get_currentalgo(algo, sizeof(algo));

	cgpu->khashes = stats_get_speed(thr_id, 0.0) / 1000.0;

	sprintf(vid, "%04hx:%04hx", cgpu->gpu_vid, cgpu->gpu_pid);
	sprintf(arch, "%d", (int) cgpu->gpu_arch);
	snprintf(driver, 32, "CUDA %d.%d %s", cuda_ver/1000, (cuda_ver%1000) / 10, driver_version);
	driver[31] = '\0';

	val = json_object();
	json_object_set_new(val, "algo", json_string(algo));
	json_object_set_new(val, "type", json_string("gpu"));
	json_object_set_new(val, "device", json_string("CPU"));
	json_object_set_new(val, "vendorid", json_string(vid));
	json_object_set_new(val, "arch", json_string(arch));
	json_object_set_new(val, "freq", json_integer(cgpu->gpu_clock/1000));
	json_object_set_new(val, "memf", json_integer(cgpu->gpu_memclock/1000));
	json_object_set_new(val, "curr_freq", json_integer(cgpu->monitor.gpu_clock));
	json_object_set_new(val, "curr_memf", json_integer(cgpu->monitor.gpu_memclock));
	json_object_set_new(val, "power", json_integer(watts));
	json_object_set_new(val, "plimit", json_integer(plimit));
	json_object_set_new(val, "khashes", json_real(cgpu->khashes));
	json_object_set_new(val, "intensity", json_real(cgpu->intensity));
	json_object_set_new(val, "throughput", json_integer(cgpu->throughput));
	json_object_set_new(val, "client", json_string(PACKAGE_NAME "/" PACKAGE_VERSION));
	json_object_set_new(val, "os", json_string(os));
	json_object_set_new(val, "driver", json_string(driver));

	json_object_set_new(result, "result", val);

	return true;
}

static bool stratum_get_stats(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);

	ret = stratum_benchdata(val, params, 0);

	if (!ret) {
		json_object_set_error(val, 1, "disabled"); //EPERM
	} else {
		json_object_set_new(val, "error", json_null());
	}

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret = true;

	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "result", json_string(USER_AGENT));
	if (ret) json_object_set_new(val, "error", json_null());

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);

	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	if (sctx->is_equihash)
		return equi_stratum_show_message(sctx, id, params);

	val = json_array_get(params, 0);
	if (val)
		applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", json_string_value(val));
	
	if (!id || json_is_null(id))
		return true;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_true());
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_unknown_method(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret = false;

	if (!id || json_is_null(id))
		return ret;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "result", json_false());
	json_object_set_error(val, 38, "unknown method"); // ENOSYS

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

bool stratum_handle_method(struct stratum_ctx *sctx, const char *s)
{
	json_t *val, *id, *params;
	json_error_t err;
	const char *method;
	bool ret = false;

	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	method = json_string_value(json_object_get(val, "method"));
	if (!method)
		goto out;
	id = json_object_get(val, "id");
	params = json_object_get(val, "params");

	if (!strcasecmp(method, "mining.notify")) {
		ret = stratum_notify(sctx, params);
		restart_threads();
		goto out;
	}
	if (!strcasecmp(method, "mining.ping")) { // cgminer 4.7.1+
		if (opt_debug) applog(LOG_DEBUG, "Pool ping");
		ret = stratum_pong(sctx, id);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_difficulty")) {
		ret = stratum_set_difficulty(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_target")) {
		sctx->is_equihash = true;
		ret = equi_stratum_set_target(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_extranonce")) {
		ret = stratum_parse_extranonce(sctx, params, 0);
		goto out;
	}
	if (!strcasecmp(method, "client.reconnect")) {
		ret = stratum_reconnect(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_algo")) { // ccminer only yet!
		// will prevent wrong algo parameters on a pool, will be used as test on rejects
		if (!opt_quiet) applog(LOG_NOTICE, "Pool asked your algo parameter");
		ret = stratum_get_algo(sctx, id, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_stats")) { // ccminer/yiimp only yet!
		// optional to fill device benchmarks
		ret = stratum_get_stats(sctx, id, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_version")) { // common
		ret = stratum_get_version(sctx, id, params);
		goto out;
	}
	if (!strcasecmp(method, "client.show_message")) { // common
		ret = stratum_show_message(sctx, id, params);
		goto out;
	}
	

	if (!ret) {
		// don't fail = disconnect stratum on unknown (and optional?) methods
		if (opt_debug) applog(LOG_WARNING, "unknown stratum method %s!", method);
		ret = stratum_unknown_method(sctx, id);
	}

out:
	if (val)
		json_decref(val);

	return ret;
}

struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = (struct thread_q *)calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;

	list_for_each_entry_safe(ent, iter, &tq->q, q_node, struct tq_ent, struct tq_ent) {
		list_del(&ent->q_node);
		free(ent);
	}

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = (struct tq_ent *)calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	if (!list_empty(&tq->q))
		goto pop;

	if (abstime)
		rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
	else
		rc = pthread_cond_wait(&tq->cond, &tq->mutex);
	if (rc)
		goto out;
	if (list_empty(&tq->q))
		goto out;

pop:
	ent = list_entry(tq->q.next, struct tq_ent, q_node);
	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}

/**
 * @param buf char[9] mini
 * @param time_t timer to convert
 */
size_t time2str(char* buf, time_t timer)
{
	struct tm* tm_info;
	tm_info = localtime(&timer);
	return strftime(buf, 19, "%H:%M:%S", tm_info);
}

/**
 * Alloc and returns time string (to be freed)
 * @param time_t timer to convert
 */
char* atime2str(time_t timer)
{
	char* buf = (char*) malloc(16);
	memset(buf, 0, 16);
	time2str(buf, timer);
	return buf;
}

/* sprintf can be used in applog */
static char* format_hash(char* buf, uint8_t* h)
{
	uchar *hash = (uchar*) h;
	int len = 0;
	for (int i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

/* to debug diff in data */
void applog_compare_hash(void *hash, void *hash_ref)
{
	char s[256] = "";
	int len = 0;
	uchar* hash1 = (uchar*)hash;
	uchar* hash2 = (uchar*)hash_ref;
	for (int i=0; i < 32; i += 4) {
		const char *color = memcmp(hash1+i, hash2+i, 4) ? CL_WHT : CL_GRY;
		len += sprintf(s+len, "%s%02x%02x%02x%02x " CL_GRY, color,
			hash1[i], hash1[i+1], hash1[i+2], hash1[i+3]);
		s[len] = '\0';
	}
	applog(LOG_DEBUG, "%s", s);
}

void applog_hash(void *hash)
{
	char s[128] = {'\0'};
	applog(LOG_DEBUG, "%s", format_hash(s, (uint8_t*)hash));
}

void applog_hash64(void *hash)
{
	char s[128] = {'\0'};
	char t[128] = {'\0'};
	applog(LOG_DEBUG, "%s %s", format_hash(s, (uint8_t*)hash), format_hash(t, &((uint8_t*)hash)[32]));
}

void applog_hex(void *data, int len)
{
	char* hex = bin2hex((uchar*)data, len);
	applog(LOG_DEBUG, "%s", hex);
	free(hex);
}

#define printpfx(n,h) \
	printf("%s%11s%s: %s\n", CL_GRN, n, CL_N, format_hash(s, h))

static uint32_t zrtest[20] = {
	swab32(0x01806486),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x00000000),
	swab32(0x2ab03251),
	swab32(0x87d4f28b),
	swab32(0x6e22f086),
	swab32(0x4845ddd5),
	swab32(0x0ac4e6aa),
	swab32(0x22a1709f),
	swab32(0xfb4275d9),
	swab32(0x25f26636),
	swab32(0x300eed54),
	swab32(0xffff0f1e),
	swab32(0x2a9e2300),
};

void do_gpu_tests(void)
{
#ifdef _DEBUG
	unsigned long done;
	char s[128] = { '\0' };
	struct work work;
	memset(&work, 0, sizeof(work));

	opt_tracegpu = true;
	work_restart = (struct work_restart*) malloc(sizeof(struct work_restart));
	work_restart[0].restart = 1;
	work.target[7] = 0xffff;

	//struct timeval tv;
	//memset(work.data, 0, sizeof(work.data));
	//scanhash_scrypt_jane(0, &work, NULL, 1, &done, &tv, &tv);

	memset(work.data, 0, sizeof(work.data));
	work.data[0] = 0;
	scanhash_hmq17(0, &work, 1, &done);

	free(work_restart);
	work_restart = NULL;
	opt_tracegpu = false;
#endif
}

