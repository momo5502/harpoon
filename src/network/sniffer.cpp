#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

namespace network
{
	std::vector<client>& sniffer::get_clients()
	{
		return this->clients;
	}

	libnet_t* sniffer::get_handle()
	{
		return this->handle;
	}

	bool sniffer::is_running()
	{
		return this->handle && !this->stopped;
	}

	bool sniffer::forward_packets(bool forward)
	{
		utils::logger::info("%s packet forwarding", forward ? "Enabling" : "Disabling");

#ifdef _WIN32
		// 'Routing and Remote Access' service is responsible for forwarding packets
		// Stopping that service disables forwarding, enabling it enables it, obv.

		bool result = false;
		SC_HANDLE sc_handle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (sc_handle)
		{
			SC_HANDLE ras = OpenServiceA(sc_handle, "RemoteAccess", SC_MANAGER_ALL_ACCESS);
			if (ras)
			{
				SERVICE_STATUS status;
				if (QueryServiceStatus(ras, &status) != FALSE)
				{
					// Wait as long as the service is in a pending state
					auto wait_for_service = [&]()
					{
						while (QueryServiceStatus(ras, &status) != FALSE)
						{
							if (status.dwCurrentState == SERVICE_PAUSED) break;
							if (status.dwCurrentState == SERVICE_RUNNING) break;
							if (status.dwCurrentState == SERVICE_STOPPED) break;

							std::this_thread::sleep_for(100ms);
						}
					};

					wait_for_service();
					ChangeServiceConfig(ras, status.dwServiceType, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);
					wait_for_service();

					if (forward)
					{
						if (status.dwCurrentState == SERVICE_PAUSED)
						{
							result = ControlService(ras, SERVICE_CONTROL_CONTINUE, &status) != FALSE;
						}
						else
						{
							result = StartService(ras, 0, nullptr) != FALSE;
						}
					}
					else
					{
						result = ControlService(ras, SERVICE_CONTROL_STOP, &status) != FALSE;
					}
				}

				CloseServiceHandle(ras);
			}

			CloseServiceHandle(sc_handle);
		}

		return result;

#elif _POSIX
		int state = forward;
		return sysctlbyname("net.inet.ip.forwarding", NULL, NULL, &state, sizeof(state)) != -1;
#else
		#error "Unsupported architecture"
#endif
	}

	std::string sniffer::get_device_uuid(std::string device)
	{
		static std::regex device_regex("\\\\[dD][eE][vV][iI][cC][eE]\\\\.*_(\\{.*\\})");

		std::smatch match;
		if (std::regex_search(device, match, device_regex) && match.size() >= 2)
		{
			device = match[1];
		}

		return device;
	}

	network::address sniffer::get_gateway_address()
	{
#ifdef _WIN32
		utils::memory::allocator allocator;
		PIP_ADAPTER_INFO  adapter_info = allocator.allocate<IP_ADAPTER_INFO>();
		DWORD size = sizeof(IP_ADAPTER_INFO);

		if (GetAdaptersInfo(adapter_info, &size) == ERROR_BUFFER_OVERFLOW)
		{
			allocator.free(adapter_info);
			adapter_info = PIP_ADAPTER_INFO(allocator.allocate_array<char>(size));
		}

		if (GetAdaptersInfo(adapter_info, &size) == NO_ERROR)
		{
			const char* dev_name = libnet_getdevice(this->handle);
			std::string device_uuid = sniffer::get_device_uuid(dev_name);

			while(adapter_info)
			{
				if (device_uuid == adapter_info->AdapterName)
				{
					return network::address{ adapter_info->GatewayList.IpAddress.String };
				}

				adapter_info = adapter_info->Next;
			}
		}

		return network::address{ "0.0.0.0" };
#elif _POSIX
		// Use getifaddr()
		#error "Not supported yet!"
#else
		#error "Unsupported architecture"
#endif
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

	void sniffer::scan_network()
	{
		if (!this->handle || this->scanning) return;
		if (this->scan_thread.joinable()) this->scan_thread.join();
		this->scan_thread = std::thread(std::bind(&sniffer::scan_runner, this));
	}

	void sniffer::scan_runner()
	{
		if (!this->handle) return;
		this->scanning = true;

		network::address target = sniffer::get_gateway_address();

		network::client client;
		client.enabled = false;
		client.hostname = "Everyone";
		client.addr = network::address{ "255.255.255.255" };

		auto oldClients = this->clients;

		for (auto& oldClient : oldClients)
		{
			if (oldClient.addr == client.addr)
			{
				client.enabled = oldClient.enabled;
				break;
			}
		}

		this->clients.clear();
		this->clients.push_back(client);

		std::mutex mutex;
		std::vector<std::thread> threads;

		for (unsigned int i = 0; i < 256 && !this->stopped; ++i)
		{
			threads.push_back(std::thread([&oldClients, &mutex, i, target, this]()
			{
				network::address targetIp = target;
				targetIp.get_ipv4_bytes()[3] = UCHAR(i);

				network::client client;
				client.enabled = false;

				ULONG addr[4];
				DWORD size = sizeof(addr);
				if (SendARP(targetIp.get_ipv4(), INADDR_ANY, addr, &size) == NO_ERROR)
				{
					char hostname[260];
					char service[260];

					client.hostname.clear();
					if (!getnameinfo(targetIp.get_addr(), sizeof(sockaddr_in), hostname, 260, service, 260, 0))
					{
						client.hostname = hostname;
					}

					client.addr = targetIp;

					std::lock_guard<std::mutex> _(mutex);

					for (auto& oldClient : oldClients)
					{
						if (oldClient.addr == client.addr)
						{
							client.enabled = oldClient.enabled;
							break;
						}
					}

					this->clients.push_back(client);
				}
			}));

			if (i % 5 == 0) std::this_thread::sleep_for(100ms);
		}

		for (auto& t : threads)
		{
			if (t.joinable())
			{
				t.join();
			}
		}

		this->scanning = false;
	}

	void sniffer::run()
	{
		if (!this->handle) return;

		utils::logger::info("Initializing sniffer");

		this->scan_network();
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

	bool sniffer::create_arp_packet(network::address dest_ip)
	{
		if (!this->handle) return false;

		uint8_t sha[6], spa[4], tha[6], tpa[4];
		std::memcpy(sha, libnet_get_hwaddr(this->handle), sizeof(sha));
		std::memcpy(tha, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(tha));

		std::memcpy(spa, this->get_gateway_address().get_ipv4_bytes(), sizeof(spa));
		std::memcpy(tpa, dest_ip.get_ipv4_bytes(), sizeof(tpa));

		libnet_ptag_t arp_tag = libnet_build_arp(1, 0x0800, 6, 4, ARP_REPLY, sha, spa, tha, tpa, NULL, 0, this->handle, 0);
		if (arp_tag == -1)
		{
			utils::logger::error("Failed to build ARP tag");
			return false;
		}

		libnet_ptag_t eth_tag = libnet_build_ethernet(tha, sha, 0x0806, NULL, 0, this->handle, 0);
		if (eth_tag == -1)
		{
			utils::logger::error("Failed to build ETH tag");
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

	sniffer::sniffer() : descr(nullptr), handle(nullptr), stopped(false), scanning(false)
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
		if (this->scan_thread.joinable()) this->scan_thread.join();
		utils::logger::info("Libnet closed");
	}
}
