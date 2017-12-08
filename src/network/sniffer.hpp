#pragma once

#include <windivert.h>

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
		std::string_view raw_data;

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