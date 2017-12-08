#pragma once

#include <windivert.h>

#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
typedef struct arphdr {
	uint16_t htype;    /* Hardware Type           */
	uint16_t ptype;    /* Protocol Type           */
	u_char hlen;        /* Hardware Address Length */
	u_char plen;        /* Protocol Address Length */
	uint16_t oper;     /* Operation Code          */
	u_char sha[6];      /* Sender hardware address */
	u_char spa[4];      /* Sender IP address       */
	u_char tha[6];      /* Target hardware address */
	u_char tpa[4];      /* Target IP address       */
}arphdr_t;

namespace network
{
	class sniffer;

	class packet
	{
	public:
		sniffer* sniffer;
		WINDIVERT_ADDRESS address;

		network::address source;
		network::address target;

		std::string_view data;

		bool drop;
	};

	class sniffer
	{
	public:
		using packet_callback = std::function<void(network::packet* packet)>;

		sniffer();
		~sniffer();

		bool send(network::packet* packet);
		void on_packet(packet_callback callback);

		void run();
		void stop();
		bool is_running();

	private:
		HANDLE handle;
		packet_callback callback;
		utils::nt::module divert;

		bool stopped;

		void extract_ressources();
	};
}