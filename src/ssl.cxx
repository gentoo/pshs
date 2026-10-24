/* pshs -- SSL/TLS support
 * (c) 2014 Michał Górny
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ssl.h"

#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <assert.h>
#include <stdio.h>
#include <time.h>

#ifdef HAVE_LIBSSL
#	include <event2/bufferevent.h>
#	include <event2/bufferevent_ssl.h>

#	include <openssl/asn1.h>
#	include <openssl/bn.h>
#	include <openssl/evp.h>
#	include <openssl/rsa.h>
#	include <openssl/ssl.h>
#	include <openssl/x509.h>

#	if OPENSSL_VERSION_NUMBER >= 0x30000000L
#		define HAVE_OPENSSL3
#	endif
#endif

#ifdef HAVE_LIBSSL
static std::unique_ptr<SSL_CTX, std::function<void(SSL_CTX*)>> ssl;

#ifndef HAVE_OPENSSL3
static int key_progress_cb(int p, int n, BN_GENCB* cb)
{
	int rc = 1;
	char c;

	switch (p)
	{
		case 0: c = '.'; break;
		case 1: c = '+'; break;
		case 2: c = '*'; break;
		case 3: c = '\n'; break;
		default:
			c = '?';
			rc = 0;
	}

	fputc(c, stderr);

	return rc;
}
#endif

static struct bufferevent* https_bev_callback(struct event_base* evb, void* data)
{
	SSL_CTX* ctx = static_cast<SSL_CTX*>(data);

	return bufferevent_openssl_socket_new(evb, -1, SSL_new(ctx),
			BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
}
#endif

SSLMod::SSLMod(evhttp* http, const char* extip, bool enable)
	: enabled(false)
{
	if (!enable)
		return;

#ifdef HAVE_LIBSSL

	unsigned char sha256_buf[32];
	unsigned int i;

	std::unique_ptr<X509, std::function<void(X509*)>>
		x509{X509_new(), X509_free};

	std::unique_ptr<X509_NAME, std::function<void(X509_NAME*)>>
		name{X509_NAME_new(), X509_NAME_free};

	if (!x509 || !name)
		throw std::bad_alloc();

#ifdef HAVE_OPENSSL3
	std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>
		pkey{EVP_RSA_gen(2048), EVP_PKEY_free};

	if (!pkey)
		throw std::bad_alloc();
#else
	std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>
		pkey{EVP_PKEY_new(), EVP_PKEY_free};
	std::unique_ptr<RSA, std::function<void(RSA*)>>
		rsa{RSA_new(), RSA_free};
	std::unique_ptr<BIGNUM, std::function<void(BIGNUM*)>>
		e{BN_new(), BN_free};
	std::unique_ptr<BN_GENCB, std::function<void(BN_GENCB*)>>
		cb{BN_GENCB_new(), BN_GENCB_free};

	if (!pkey || !rsa || !e || !cb)
		throw std::bad_alloc();

	if (!BN_set_word(e.get(), RSA_F4))
		throw std::runtime_error("BN_set_word() failed");

	BN_GENCB_set(cb.get(), key_progress_cb, NULL);

	if (!RSA_generate_key_ex(rsa.get(), 2048, e.get(), cb.get()))
		throw std::runtime_error("RSA_generate_key_ex() failed");

	if (!EVP_PKEY_set1_RSA(pkey.get(), rsa.get()))
		throw std::runtime_error("EVP_PKEY_set1_RSA() failed");
#endif

	if (!X509_set_pubkey(x509.get(), pkey.get()))
		throw std::runtime_error("X509_set_pubkey() failed");

	/* X509v3 */
	X509_set_version(x509.get(), 2);
	/* Semi-random serial number to avoid repetitions */
	ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), time(NULL));
	/* Valid for 24 hours */
	X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(x509.get()), 60*60*24);

	/* Set subject & issuer; OpenSSL 4 returns the subject name as const,
	 * so build a fresh name instead of modifying it in place */
	X509_NAME_add_entry_by_txt(name.get(), "O", MBSTRING_ASC,
			static_cast<const unsigned char*>(
				static_cast<const void*>("pshs")), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC,
			static_cast<const unsigned char*>(
				static_cast<const void*>(extip)), -1, -1, 0);

	X509_set_subject_name(x509.get(), name.get());
	/* Self-signed => issuer = subject */
	X509_set_issuer_name(x509.get(), name.get());

	if (!X509_sign(x509.get(), pkey.get(), EVP_sha512()))
		throw std::runtime_error("X509_sign() failed");

	ssl = {SSL_CTX_new(TLS_server_method()), SSL_CTX_free};
	if (!ssl)
		throw std::bad_alloc();

	if (!SSL_CTX_use_certificate(ssl.get(), x509.get()))
		throw std::runtime_error("SSL_CTX_use_certificate() failed");

	if (!SSL_CTX_use_PrivateKey(ssl.get(), pkey.get()))
		throw std::runtime_error("SSL_CTX_use_PrivateKey() failed");

	evhttp_set_bevcb(http, https_bev_callback, ssl.get());

	/* print fingerprint */
	if (!X509_digest(x509.get(), EVP_sha256(), sha256_buf, &i))
		throw std::runtime_error("X509_digest() failed");

	assert(i == sizeof(sha256_buf));
	std::cerr << "Certificate fingerprint:\n"
		<< std::setfill('0') << std::hex << std::uppercase;
	for (i = 0; i < sizeof(sha256_buf); ++i)
	{
		std::cerr << std::setw(2) << static_cast<int>(sha256_buf[i])
			<< ((-i % (sizeof(sha256_buf) / 2) == 1) ? '\n' : ' ');
	}
	std::cerr << std::dec;

	enabled = true;

#else

	std::cerr << "SSL/TLS support disabled at build time." << std::endl;

#endif
}

SSLMod::~SSLMod()
{
	if (!enabled)
		return;

#ifdef HAVE_LIBSSL
	ssl.reset(nullptr);
#endif
}
