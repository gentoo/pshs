/* pshs -- network interfaces support
 * (c) 2011-2024 Michał Górny
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <iostream>
#include <string>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_LIBMINIUPNPC
#	include <miniupnpc/miniupnpc.h>
#	include <miniupnpc/upnpcommands.h>
#	include <miniupnpc/upnperrors.h>
#	include <netinet/in.h>
#endif

#include "network.h"

#ifdef HAVE_LIBMINIUPNPC
static const int discovery_delay = 1000; /* [ms] */

static struct UPNPUrls upnp_urls;
static struct IGDdatas upnp_data;

static char lan_addr[MINIUPNPC_URL_MAXSIZE];

static int upnp_enabled;
static bool upnp_urls_ready;
static bool upnp_ipv6_pinhole;
static char upnp_pinhole_id[9];
#endif

/**
 * ExternalIP::ExternalIP
 * @port: listening port
 * @bindip: IP the server is bound to
 * @use_upnp: whether UPnP is enabled via config
 *
 * Try to set up port forwardings and get the external IP. This tries to use
 * UPnP first, then falls back to bound IP or searching interfaces via netlink.
 */
ExternalIP::ExternalIP(unsigned int port, const char* bindip, bool use_upnp)
	: _port(port), addr(NULL)
{
#ifdef HAVE_LIBMINIUPNPC
	/* use UPnP only if user wants to */
	if (use_upnp)
	{
		upnp_enabled = 0;
		upnp_urls_ready = false;
		upnp_ipv6_pinhole = false;
		upnp_pinhole_id[0] = '\0';

		const bool bind_is_ipv6 = (bindip && strchr(bindip, ':'));
		const bool bind_is_unspecified_v6 = bind_is_ipv6 && (strcmp(bindip, "::") == 0);
		const bool bind_is_unspecified_v4 = (!bind_is_ipv6) && (!bindip || strcmp(bindip, "0.0.0.0") == 0);

		const char* multicast_if_v4 = (!bind_is_ipv6 && !bind_is_unspecified_v4) ? bindip : NULL;
		struct UPNPDev* devlist = upnpDiscover(discovery_delay, multicast_if_v4, NULL, 0, 0, 2, NULL);
		if (!devlist && bind_is_ipv6)
		{
			const char* multicast_if_v6 = bind_is_unspecified_v6 ? NULL : bindip;
			devlist = upnpDiscover(discovery_delay, multicast_if_v6, NULL, 0, 1, 2, NULL);
		}

		if (devlist)
		{
			static char extip[64];
#if MINIUPNPC_API_VERSION >= 18
			int igd_status = UPNP_GetValidIGD(devlist, &upnp_urls, &upnp_data,
					lan_addr, sizeof(lan_addr), extip, sizeof(extip));
#else
			int igd_status = UPNP_GetValidIGD(devlist, &upnp_urls, &upnp_data,
					lan_addr, sizeof(lan_addr));
#endif
			freeUPNPDevlist(devlist);

			if (igd_status == UPNP_CONNECTED_IGD || igd_status == UPNP_PRIVATEIP_IGD)
			{
				upnp_urls_ready = true;

				std::string strport{std::to_string(port)};
				int add_ret = UPNP_AddPortMapping(
						upnp_urls.controlURL,
						upnp_data.first.servicetype,
						strport.c_str(), strport.c_str(), lan_addr,
						"Pretty small HTTP server",
						"TCP",
						NULL,
						NULL);
				if (add_ret != UPNPCOMMAND_SUCCESS)
				{
					std::cerr << "UPNP_AddPortMapping() failed: " << strupnperror(add_ret)
						<< std::endl;
					FreeUPNPUrls(&upnp_urls);
					upnp_urls_ready = false;
				}
				else
				{
					upnp_enabled = 1;

#if MINIUPNPC_API_VERSION < 18
					if (UPNP_GetExternalIPAddress(
							upnp_urls.controlURL,
							upnp_data.first.servicetype,
							extip) != UPNPCOMMAND_SUCCESS)
					{
						extip[0] = '\0';
					}
#endif
					if (igd_status == UPNP_CONNECTED_IGD && extip[0] != '\0')
					{
						addr = extip;
					}

					if (bind_is_ipv6
						&& upnp_urls.controlURL_6FC && upnp_urls.controlURL_6FC[0] != '\0'
						&& upnp_data.IPv6FC.servicetype[0] != '\0')
					{
						int firewall_enabled = 0;
						int inbound_allowed = 0;
						const int firewall_status = UPNP_GetFirewallStatus(
								upnp_urls.controlURL_6FC,
								upnp_data.IPv6FC.servicetype,
								&firewall_enabled,
								&inbound_allowed);
						if (firewall_status == UPNPCOMMAND_SUCCESS && firewall_enabled && inbound_allowed)
						{
							const char* candidate_ipv6 = (!bind_is_unspecified_v6)
								? bindip
								: get_rtnl_external_ip("::");
							std::string local_ipv6;
							if (candidate_ipv6 && strchr(candidate_ipv6, ':'))
								local_ipv6 = candidate_ipv6;

							if (!local_ipv6.empty())
							{
								char proto_buf[4];
								snprintf(proto_buf, sizeof(proto_buf), "%d", IPPROTO_TCP);
								char unique_id[sizeof(upnp_pinhole_id)] = { 0 };
								int pinhole_ret = UPNP_AddPinhole(
										upnp_urls.controlURL_6FC,
										upnp_data.IPv6FC.servicetype,
										"",
										"0",
										local_ipv6.c_str(),
										strport.c_str(),
										proto_buf,
										"0",
										unique_id);
								if (pinhole_ret == UPNPCOMMAND_SUCCESS)
								{
									upnp_ipv6_pinhole = true;
									snprintf(upnp_pinhole_id, sizeof(upnp_pinhole_id), "%s", unique_id);
									std::cerr << "Opened IPv6 UPnP pinhole for "
											<< local_ipv6 << ':' << port << std::endl;
								}
								else
								{
									std::cerr << "UPNP_AddPinhole() failed: "
										<< strupnperror(pinhole_ret) << std::endl;
								}
							}
						}
						else if (firewall_status != UPNPCOMMAND_SUCCESS)
						{
							std::cerr << "UPNP_GetFirewallStatus() failed: "
								<< strupnperror(firewall_status) << std::endl;
						}
					}

					if (addr)
						return;
				}
			}
			else if (igd_status > 0)
			{
				FreeUPNPUrls(&upnp_urls);
				upnp_urls_ready = false;
			}
		}
	}
#endif

	/* Fallback to bindip or netlink */
	const char* fallback_bindip = bindip ? bindip : "0.0.0.0";
	if (!bindip || !strcmp(fallback_bindip, "0.0.0.0") || !strcmp(fallback_bindip, "::"))
		addr = get_rtnl_external_ip(fallback_bindip);
	else
		addr = fallback_bindip;
}

/**
 * ExternalIP::~ExternalIP
 *
 * Cleanup after ExternalIP. If UPnP was used, remove the port
 * forwarding established then.
 */
ExternalIP::~ExternalIP()
{
#ifdef HAVE_LIBMINIUPNPC
	if (upnp_urls_ready)
	{
		int ret;

		if (upnp_ipv6_pinhole && upnp_pinhole_id[0])
		{
			ret = UPNP_DeletePinhole(
					upnp_urls.controlURL_6FC,
					upnp_data.IPv6FC.servicetype,
					upnp_pinhole_id);
			if (ret != UPNPCOMMAND_SUCCESS)
				std::cerr << "UPNP_DeletePinhole() failed: " << strupnperror(ret)
					<< std::endl;
		}
		upnp_ipv6_pinhole = false;
		upnp_pinhole_id[0] = '\0';

		if (upnp_enabled)
		{
			std::string strport{std::to_string(_port)};

			/* Remove the port forwarding when done. */
			ret = UPNP_DeletePortMapping(
					upnp_urls.controlURL,
					upnp_data.first.servicetype,
					strport.c_str(), "TCP", NULL);
			if (ret != UPNPCOMMAND_SUCCESS)
				std::cerr << "UPNP_DeletePortMapping() failed: " << strupnperror(ret)
					<< std::endl;
			upnp_enabled = 0;
		}
		FreeUPNPUrls(&(upnp_urls));
		upnp_urls_ready = false;
	}
#endif
}

std::ostream& operator<<(std::ostream& os, const IPAddrPrinter& addr)
{
	bool ipv6 = !!strchr(addr.addr, ':');
	if (ipv6)
		os << '[';
	os << addr.addr;
	if (ipv6)
		os << ']';
	os << ':' << addr.port;
	return os;
}
