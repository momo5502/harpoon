#pragma once

#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */

namespace network
{
	class sniffer;

	class packet
	{
	public:
		sniffer* sniffer;

		const struct pcap_pkthdr* pkthdr;
		const u_char* data;
	};

	class sniffer
	{
	public:
		using packet_callback = std::function<void(network::packet* packet)>;

		sniffer();
		~sniffer();

		bool create_arp_packet(network::address source_ip, network::address dest_ip);

		bool send();
		void on_packet(packet_callback callback);

		void run();
		void stop();
		bool is_running();

		libnet_t* get_handle();

	private:
		pcap_t* descr;
		libnet_t* handle;
		char errbuf[LIBNET_ERRBUF_SIZE];

		packet_callback callback;
		bool stopped;

		void process_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet);
		static void forward_packet(u_char* s, const struct pcap_pkthdr* pkthdr, const u_char* packet);
	};
}