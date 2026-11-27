/* pshs -- request handlers
 * (c) 2011-2024 Michał Górny
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <algorithm>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <stdint.h>
#include <inttypes.h>

#include <event2/buffer.h>
#include <event2/event.h>

#include "handlers.h"
#include "content-type.h"
#include "index.h"
#include "network.h"

char ct_buf[80];

/**
 * init_charset
 * @charset: new charset or %NULL
 *
 * Set the new charset (file name encoding).
 */
void init_charset(const char* charset)
{
	strcpy(ct_buf, "text/html"); /* 9b */
	if (charset && strlen(charset) < sizeof(ct_buf) - 20)
	{
		strcpy(&ct_buf[9], "; charset=");
		strcpy(&ct_buf[19], charset);
	}
}

/**
 * has_file
 * @path: requested path
 * @served: null-terminated served file list
 *
 * Check whether requested @path is on the @served list.
 *
 * Returns: 1 if it is, 0 otherwise
 */
static int has_file(const char* path, char* const* served)
{
	for (; *served; served++)
	{
		if (!strcmp(path, *served))
			return 1;
	}

	return 0;
}

/**
 * print_req
 * @req: the request object
 *
 * Log the request source and the requested path to stdout.
 */
static void print_req(struct evhttp_request* req)
{
	const char* uri = evhttp_request_get_uri(req);
	struct evhttp_connection* conn = evhttp_request_get_connection(req);

#if LIBEVENT_VERSION_NUMBER >= 0x02020000
	const char* addr;
#else
	char* addr;
#endif
	ev_uint16_t port;

	assert(conn);
	evhttp_connection_get_peer(conn, &addr, &port);
	std::cout << '[' << IPAddrPrinter(addr, port) << "] "
		<< uri << std::endl;
}

/**
 * handle_close
 * @conn: the connection
 * @data: unused
 *
 * Handle the connection close event.
 */
void handle_close(struct evhttp_connection* conn, void* data)
{
#if LIBEVENT_VERSION_NUMBER >= 0x02020000
	const char* addr;
#else
	char* addr;
#endif
	ev_uint16_t port;

	assert(conn);
	evhttp_connection_get_peer(conn, &addr, &port);
	std::cout << '[' << IPAddrPrinter(addr, port)
		<< "] connection closed" << std::endl;
}

/**
 * handle_file
 * @req: the request object
 * @data: served file list
 *
 * Handle the request for regular file. Check whether the file is served, get
 * its type, send correct headers and the file contents.
 *
 * If file is not served, 404 is sent back. If file is unreadable somehow, 500
 * is sent instead.
 */
void handle_file(struct evhttp_request* req, void* data)
{
	const struct callback_data* cb_data = static_cast<callback_data*>(data);
	const char* vpath = evhttp_request_get_uri(req);
	struct evhttp_connection* conn = evhttp_request_get_connection(req);

	assert(vpath);
	assert(conn);

	/* Report connection being closed. */
	evhttp_connection_set_closecb(conn, handle_close, 0);

	/* Collapse repeated slashes (//file -> /file).  Done before decoding,
	 * so that encoded slashes (%2F, used by the index for absolute paths)
	 * are preserved. */
	std::string npath{vpath};
	npath.erase(std::unique(npath.begin(), npath.end(),
				[](char a, char b) { return (a == '/') && (b == '/'); }),
			npath.end());
	vpath = npath.c_str();

	/* Chop the leading slash. */
	assert(vpath[0] == '/');
	vpath++;

	print_req(req);

	std::unique_ptr<char, std::function<void(char*)>>
		dpath{evhttp_decode_uri(vpath), free};

	if (!dpath)
	{
		std::cerr << "Unable to decode URI: " << vpath << std::endl;
		evhttp_send_error(req, 500, "Internal Server Error");
		return;
	}

	vpath = dpath.get();
	if (cb_data->prefix)
	{
		if (strncmp(vpath, cb_data->prefix, cb_data->prefix_len)
				|| vpath[cb_data->prefix_len] != '/')
		{
			evhttp_send_error(req, 404, "Not Found");
			return;
		}
		vpath += cb_data->prefix_len + 1;
	}

	if (!has_file(vpath, cb_data->files))
		evhttp_send_error(req, 404, "Not Found");
	else
	{
		int fd = open(vpath, O_RDONLY);

		if (fd == -1)
			std::cerr << "open() failed for " << vpath << ": "
				<< strerror(errno) << std::endl;
		else
		{
			struct stat st;

			/* we need to have a regular file here,
			 * with static Content-Length */
			if (fstat(fd, &st))
				std::cerr << "fstat() failed for " << vpath << ": "
					<< strerror(errno) << std::endl;
			else if (!S_ISREG(st.st_mode))
				std::cerr << "fstat() says that " << vpath
					<< "is not a regular file" << std::endl;
			else
			{
				struct evbuffer* buf = evbuffer_new();
				struct evkeyvalq* inhead = evhttp_request_get_input_headers(req);
				struct evkeyvalq* headers = evhttp_request_get_output_headers(req);

				const char* range;
				intmax_t first = 0, last = -1;
				ev_off_t size = st.st_size;

				assert(inhead);
				assert(headers);

				range = evhttp_find_header(inhead, "Range");
				if (range)
				{
					/* We support only single byte range,
					 * so fail on ',' or invalid bytes=%d-%d */
					if (strchr(range, ',') || sscanf(range,
								"bytes = %" SCNdMAX " - %" SCNdMAX,
								&first, &last) < 1)
					{
						evhttp_send_error(req, 501, "Not Implemented");
						close(fd);
						return;
					}
				}

				if (first < 0)
					first += size;
				if (last < 0)
					last += size;

				if (range && first > last)
				{
					evhttp_send_error(req, 416, "Requested Range Not Satisfiable");
					close(fd);
					return;
				}

				/* Advertise range support */
				evhttp_add_header(headers, "Accept-Ranges", "bytes");
				/* Be proud! */
				evhttp_add_header(headers, "Server", PACKAGE_NAME "/" PACKAGE_VERSION);

				/* Good Content-Type is nice for users. */
				if (evhttp_add_header(headers, "Content-Type",
							cb_data->ct->guess(fd)))
					throw std::bad_alloc();

				/* Send the file. */
#if 0 /* breaks ssl support */
				evbuffer_set_flags(buf, EVBUFFER_FLAG_DRAINS_TO_FD);
#endif
				if (size != 0)
					evbuffer_add_file(buf, fd, first, last - first + 1);
				if (range)
				{
					std::stringstream rangebuf;
					rangebuf << "bytes " << first << '-' << last << '/' << size;

					if (evhttp_add_header(headers, "Content-Range", rangebuf.str().c_str()))
						throw std::bad_alloc();
					evhttp_send_reply(req, 206, "Partial Content", buf);
				} else
					evhttp_send_reply(req, 200, "OK", buf);

				evbuffer_free(buf);
				return;
			}

			close(fd);
		}
		evhttp_send_error(req, 500, "Internal Server Error");
	}
}

/**
 * handle_index
 * @req: the request object
 * @data: served filelist
 *
 * Handle index (/) request. Send back the HTML filelist.
 */
void handle_index_with_list(struct evhttp_request* req, void* data)
{
	const struct callback_data* cb_data = static_cast<callback_data*>(data);
	struct evbuffer* buf = evbuffer_new();
	struct evkeyvalq* headers = evhttp_request_get_output_headers(req);

	print_req(req);

	assert(headers);
	evhttp_add_header(headers, "Server", PACKAGE_NAME "/" PACKAGE_VERSION);
	if (evhttp_add_header(headers, "Content-Type",
				"text/html; charset=utf-8"))
		throw std::bad_alloc();

	generate_index(buf, cb_data->files);

	evhttp_send_reply(req, 200, "OK", buf);
	evbuffer_free(buf);
}

/**
 * handle_index_with_redirect
 * @req: the request object
 * @data: served filelist
 *
 * Handle index (/) request.  Redirects to the only file in the file list.
 */
void handle_index_with_redirect(struct evhttp_request* req, void* data)
{
	const struct callback_data* cb_data = static_cast<callback_data*>(data);
	struct evbuffer* buf = evbuffer_new();
	struct evkeyvalq* headers = evhttp_request_get_output_headers(req);

	print_req(req);

	assert(headers);
	evhttp_add_header(headers, "Server", PACKAGE_NAME "/" PACKAGE_VERSION);
	evhttp_add_header(headers, "Location", cb_data->files[0]);

	evhttp_send_reply(req, 302, "Found", buf);
	evbuffer_free(buf);
}
