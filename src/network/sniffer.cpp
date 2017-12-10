#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

namespace network
{
	std::vector<std::shared_ptr<client>> sniffer::get_clients()
	{
		std::lock_guard<std::mutex> _(this->client_mutex);
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

	void sniffer::set_dumping(bool dumping)
	{
		if (this->dumper)
		{
			auto old_dumper = this->dumper;
			this->dumper = nullptr;
			pcap_dump_close(old_dumper);
		}

		if(dumping) this->dumper = pcap_dump_open(this->descr, "sniff.pcap");
	}

	bool sniffer::forward_packets(bool forward)
	{
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

	bool sniffer::get_adapter_info(PIP_ADAPTER_INFO adapter_info)
	{
		if (!this->handle) return false;

#ifdef _WIN32
		utils::memory::allocator allocator;
		PIP_ADAPTER_INFO adapter_infos = allocator.allocate<IP_ADAPTER_INFO>();
		DWORD size = sizeof(IP_ADAPTER_INFO);

		if (GetAdaptersInfo(adapter_infos, &size) == ERROR_BUFFER_OVERFLOW)
		{
			allocator.free(adapter_infos);
			adapter_infos = PIP_ADAPTER_INFO(allocator.allocate_array<char>(size));
		}

		if (GetAdaptersInfo(adapter_infos, &size) == NO_ERROR)
		{
			const char* dev_name = libnet_getdevice(this->handle);
			std::string device_uuid = sniffer::get_device_uuid(dev_name);

			while (adapter_infos)
			{
				if (device_uuid == adapter_infos->AdapterName)
				{
					std::memcpy(adapter_info, adapter_infos, sizeof(*adapter_info));
					return true;
				}

				adapter_infos = adapter_infos->Next;
			}
		}
#endif
		adapter_info;
		return false;
	}

	std::vector<std::string> sniffer::get_local_address()
	{
		std::vector<std::string> addresses;
		if (!this->handle) return addresses;

#ifdef _WIN32
		utils::memory::allocator allocator;
		PIP_ADAPTER_ADDRESSES addrs = allocator.allocate<IP_ADAPTER_ADDRESSES>();
		DWORD size = sizeof(IP_ADAPTER_INFO);

		if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &size) == ERROR_BUFFER_OVERFLOW)
		{
			allocator.free(addrs);
			addrs = PIP_ADAPTER_ADDRESSES(allocator.allocate_array<char>(size));
		}

		if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, addrs, &size) == NO_ERROR)
		{
			const char* dev_name = libnet_getdevice(this->handle);
			std::string device_uuid = sniffer::get_device_uuid(dev_name);

			while (addrs)
			{
				if (device_uuid == addrs->AdapterName)
				{
					auto addr = addrs->FirstUnicastAddress;
					while (addr)
					{
						char buffer[MAX_PATH] = { 0 };

						if (addr->Address.lpSockaddr->sa_family == AF_INET)
						{
							sockaddr_in *sa_in = reinterpret_cast<sockaddr_in*>(addr->Address.lpSockaddr);
							inet_ntop(addr->Address.lpSockaddr->sa_family, &sa_in->sin_addr, buffer, sizeof(buffer));
						}
						else if (addr->Address.lpSockaddr->sa_family == AF_INET6)
						{
							sockaddr_in6 *sa_in6 = reinterpret_cast<sockaddr_in6 *>(addr->Address.lpSockaddr);
							inet_ntop(addr->Address.lpSockaddr->sa_family, &sa_in6->sin6_addr, buffer, sizeof(buffer));
						}
						else
						{
							addr = addr->Next;
							continue;
						}

						addresses.push_back(buffer);
						addr = addr->Next;
					}

					break;
				}

				addrs = addrs->Next;
			}
		}
#else
#error "Unsupported architecture"
#endif
		return addresses;
	}

	network::address sniffer::get_gateway_address()
	{
		if(!this->handle) return network::address{ "0.0.0.0" };
		if (this->gateway_address.has_value()) return this->gateway_address.value();
		this->gateway_address.emplace(network::address{ "0.0.0.0" });

#ifdef _WIN32
		IP_ADAPTER_INFO info;
		if (sniffer::get_adapter_info(&info))
		{
			this->gateway_address.emplace(network::address{ info.GatewayList.IpAddress.String });
		}

		return this->gateway_address.value();
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

		++this->sniffed_packets;
		if(this->dumper) pcap_dump(PBYTE(this->dumper), pkthdr, data);
		if (this->callback) this->callback(&p);
	}

	void sniffer::forward_packet(u_char* s, const struct pcap_pkthdr* pkthdr, const u_char* packet)
	{
		sniffer* _sniffer = reinterpret_cast<sniffer*>(s);
		_sniffer->process_packet(pkthdr, packet);
	}

	void sniffer::arp_runner()
	{
		if (!this->handle) return;

		while (!this->stopped)
		{
			std::unique_lock<std::mutex> lock(this->client_mutex);

			for (auto& client : this->clients)
			{
				if (client->enabled)
				{
					this->send_arp_packet(client->addr);
				}
			}

			lock.unlock();
			std::this_thread::sleep_for(5ms);
		}
	}

	void sniffer::scan_network()
	{
		if (!this->handle || this->scanning) return;
		if (this->scan_thread.joinable()) this->scan_thread.join();
		this->scan_thread = std::thread(std::bind(&sniffer::scan_runner, this));
	}

	uint64_t sniffer::get_sniffed_packets()
	{
		return this->sniffed_packets;
	}

	void sniffer::scan_runner()
	{
		if (!this->handle) return;
		this->scanning = true;

		network::address target = sniffer::get_gateway_address();

		auto client = std::make_shared<network::client>();
		client->enabled = false;
		client->hostname = "Everyone";
		client->addr = network::address{ "255.255.255.255" };

		std::unique_lock<std::mutex> lock(this->client_mutex);
		auto oldClients = this->clients;

		for (auto& oldClient : oldClients)
		{
			if (oldClient->addr == client->addr)
			{
				client->enabled = oldClient->enabled;
				break;
			}
		}

		this->clients.clear();
		this->clients.push_back(client);
		lock.unlock();

		std::mutex mutex;
		std::vector<std::thread> threads;

		for (unsigned int i = 0; i < 256 && !this->stopped; ++i)
		{
			threads.push_back(std::thread([&oldClients, &mutex, i, target, this]()
			{
				network::address targetIp = target;
				targetIp.get_ipv4_bytes()[3] = UCHAR(i);

				auto client = std::make_shared<network::client>();
				client->enabled = false;
				client->addr = targetIp;

				ULONG addr[4];
				DWORD size = sizeof(addr);
				if (SendARP(targetIp.get_ipv4(), INADDR_ANY, addr, &size) == NO_ERROR)
				{
					char hostname[260];
					char service[260];

					if (!getnameinfo(targetIp.get_addr(), sizeof(sockaddr_in), hostname, 260, service, 260, 0))
					{
						client->hostname = hostname;
					}

					std::lock_guard<std::mutex> _(this->client_mutex);

					for (auto& oldClient : oldClients)
					{
						if (oldClient->addr == client->addr)
						{
							client->enabled = oldClient->enabled;
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

		this->scan_network();
		this->arp_thread = std::thread(std::bind(&sniffer::arp_runner, this));

		const char* dev = libnet_getdevice(this->handle);
		this->descr = pcap_open_live(dev, 2048, 0, 512, this->errbuf);
		if (!this->descr) return;

		char filter[500];
		libnet_ether_addr* addr = libnet_get_hwaddr(this->handle);

		auto ips = this->get_local_address();
		std::string ip_filter;

		for (auto& ip : ips)
		{
			ip_filter.append(" and (not host ");
			ip_filter.append(ip);
			ip_filter.append(")");
		}

		_snprintf_s(filter, sizeof(filter), "(tcp or udp) and (not broadcast) and (not multicast) and (ether dst %02X:%02X:%02X:%02X:%02X:%02X) %s",
			addr->ether_addr_octet[0],
			addr->ether_addr_octet[1],
			addr->ether_addr_octet[2],
			addr->ether_addr_octet[3],
			addr->ether_addr_octet[4],
			addr->ether_addr_octet[5], ip_filter.data());

		bpf_u_int32 mask, net;
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) return;

		bpf_program fp;
		if (pcap_compile(this->descr, &fp, filter, 0, net) == -1) return;
		if (pcap_setfilter(this->descr, &fp) == -1)  return;

		pcap_loop(this->descr, -1, sniffer::forward_packet, PBYTE(this));

		this->stopped = true;
	}

	bool sniffer::send_arp_packet(network::address dest_ip)
	{
		if (!this->handle || this->stopped) return false;
		libnet_clear_packet(this->handle);

		uint8_t sha[6], spa[4], tha[6], tpa[4];
		std::memcpy(sha, libnet_get_hwaddr(this->handle), sizeof(sha));
		std::memcpy(tha, "\xFF\xFF\xFF\xFF\xFF\xFF", sizeof(tha));

		std::memcpy(spa, this->get_gateway_address().get_ipv4_bytes(), sizeof(spa));
		std::memcpy(tpa, dest_ip.get_ipv4_bytes(), sizeof(tpa));

		libnet_ptag_t arp_tag = libnet_build_arp(1, 0x0800, 6, 4, ARP_REPLY, sha, spa, tha, tpa, NULL, 0, this->handle, 0);
		if (arp_tag == -1) return false;

		libnet_ptag_t eth_tag = libnet_build_ethernet(tha, sha, 0x0806, NULL, 0, this->handle, 0);
		if (eth_tag == -1) return false;

		return libnet_write(this->handle) != -1;
	}

	void sniffer::on_packet(packet_callback _callback)
	{
		this->callback = _callback;
	}

	sniffer::sniffer() : descr(nullptr), handle(nullptr), stopped(false), scanning(false), sniffed_packets(0), dumper(nullptr)
	{
		this->handle = libnet_init(LIBNET_LINK, nullptr, this->errbuf);
	}

	sniffer::~sniffer()
	{
		this->stop();
		if (this->scan_thread.joinable()) this->scan_thread.join();
		if (this->arp_thread.joinable()) this->arp_thread.join();
	}
}
