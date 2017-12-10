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

	class client
	{
	public:
		network::address addr;
		std::string hostname;
		int enabled;

		std::string to_string()
		{
			if (!hostname.empty()) return hostname;
			else return addr.to_string();
		}
	};

	class sniffer
	{
	public:
		using packet_callback = std::function<void(network::packet* packet)>;

		sniffer();
		~sniffer();

		void on_packet(packet_callback callback);

		void run();
		void stop();
		bool is_running();

		bool forward_packets(bool forward);

		void set_dumping(bool dumping);

		network::address get_gateway_address();
		std::vector<std::string> get_local_address();

		libnet_t* get_handle();

		std::vector<std::shared_ptr<client>> get_clients();

		void scan_network();

		uint64_t get_sniffed_packets();

	private:
		pcap_t* descr;
		pcap_dumper_t* dumper;

		libnet_t* handle;
		char errbuf[LIBNET_ERRBUF_SIZE];

		packet_callback callback;
		bool stopped;

		std::optional<network::address> gateway_address;

		std::mutex client_mutex;
		std::atomic<bool> scanning;
		std::vector<std::shared_ptr<client>> clients;
		std::thread scan_thread;
		std::thread arp_thread;

		uint64_t sniffed_packets;

		bool send_arp_packet(network::address dest_ip = network::address{ "255.255.255.255" });

		void scan_runner();
		void arp_runner();

		bool get_adapter_info(PIP_ADAPTER_INFO adapter_info);

		void process_packet(const struct pcap_pkthdr* pkthdr, const u_char* packet);
		static void forward_packet(u_char* s, const struct pcap_pkthdr* pkthdr, const u_char* packet);

		static std::string get_device_uuid(std::string device);
	};
}