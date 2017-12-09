#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

namespace network
{
	libnet_t* sniffer::get_handle()
	{
		return this->handle;
	}

	bool sniffer::is_running()
	{
		return this->handle && !this->stopped;
	}

	void sniffer::stop()
	{
		this->stopped = true;

		if (this->descr)
		{
			pcap_breakloop(this->descr);
			this->descr = nullptr;
		}

		if (this->handle)
		{
			libnet_destroy(this->handle);
			this->handle = nullptr;
		}
	}

	void sniffer::process_packet(const struct pcap_pkthdr* pkthdr, const u_char* data)
	{
		packet p;
		p.sniffer = this;
		p.pkthdr = pkthdr;
		p.data = data;

		if (this->callback) this->callback(&p);
	}

	void sniffer::forward_packet(u_char* s, const struct pcap_pkthdr* pkthdr, const u_char* packet)
	{
		sniffer* _sniffer = reinterpret_cast<sniffer*>(s);
		_sniffer->process_packet(pkthdr, packet);
	}

	void sniffer::run()
	{
		if (!this->handle) return;

		utils::logger::info("Initializing sniffer");

		this->descr = pcap_open_live(libnet_getdevice(this->handle), 2048, 0, 512, this->errbuf);
		if (!this->descr)
		{
			utils::logger::error("Failed to initialize sniffer: %s", this->errbuf);
			return;
		}
		else
		{
			utils::logger::success("Sniffer successfully initialized");
		}

		// #nofilter, yet!

		utils::logger::info("Starting sniffer");

		pcap_loop(this->descr, -1, sniffer::forward_packet, PBYTE(this));

		this->stopped = true;
		utils::logger::info("Sniffer stopped");
	}

	bool sniffer::create_arp_packet(network::address source_ip, network::address dest_ip)
	{
		if (!this->handle) return false;

		uint8_t sha[6], spa[4], tha[6], tpa[4];
		std::memcpy(sha, libnet_get_hwaddr(this->handle), sizeof(sha));
		std::memcpy(tha, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(tha));

		std::memcpy(spa, source_ip.get_ipv4_bytes(), sizeof(spa));
		std::memcpy(tpa, dest_ip.get_ipv4_bytes(), sizeof(tpa));

		libnet_ptag_t arp_tag = libnet_build_arp(1, 0x0800, 6, 4, ARP_REPLY, sha, spa, tha, tpa, NULL, 0, this->handle, 0);
		if (arp_tag == -1)
		{
			utils::logger::error("Failed to build arp tag");
			return false;
		}

		libnet_ptag_t eth_tag = libnet_build_ethernet(tha, sha, 0x0806, NULL, 0, this->handle, 0);
		if (eth_tag == -1)
		{
			utils::logger::error("Failed to build eth tag");
			return false;
		}

		return true;
	}

	bool sniffer::send()
	{
		if (!this->handle) return false;
		return libnet_write(this->handle) != -1;
	}

	void sniffer::on_packet(packet_callback _callback)
	{
		this->callback = _callback;
	}

	sniffer::sniffer() : descr(nullptr), handle(nullptr), stopped(false)
	{
		utils::logger::info("Initializing libnet");

		this->handle = libnet_init(LIBNET_LINK, nullptr, this->errbuf);
		if (!this->handle)
		{
			utils::logger::error("Failed to initialize libnet: %s", this->errbuf);
		}
		else
		{
			utils::logger::success("Libnet successfully initialized");
		}
	}

	sniffer::~sniffer()
	{
		this->stop();
		utils::logger::info("Libnet closed");
	}
}
