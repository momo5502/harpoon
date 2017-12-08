#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

namespace network
{
	bool sniffer::is_running()
	{
		return this->handle != INVALID_HANDLE_VALUE && !this->stopped;
	}

	void sniffer::stop()
	{
		this->stopped = true;

		if (this->handle != INVALID_HANDLE_VALUE)
		{
			this->divert.invoke_pascal<BOOL>("WinDivertClose", this->handle);
			this->handle = INVALID_HANDLE_VALUE;
		}
	}

	void sniffer::run()
	{
		utils::memory::allocator allocator;

		u_int size = 0;
		const u_int maxSize = 0x10000;
		u_char* buffer = allocator.allocate_array<u_char>(maxSize);

		auto win_diver_send = this->divert.get<BOOL(__stdcall)(HANDLE, PVOID, UINT, PWINDIVERT_ADDRESS, UINT*)>("WinDivertSend");
		auto win_diver_receive = this->divert.get<BOOL(__stdcall)(HANDLE, PVOID, UINT, PWINDIVERT_ADDRESS, UINT*)>("WinDivertRecv");

		packet packet;
		while (!this->stopped && this->handle != INVALID_HANDLE_VALUE)
		{
			if (win_diver_receive(this->handle, buffer, maxSize, &packet.address, &size) == TRUE)
			{
				PWINDIVERT_IPHDR ipHeader = PWINDIVERT_IPHDR(buffer);
				PWINDIVERT_UDPHDR udpHeader = PWINDIVERT_UDPHDR(buffer + (ipHeader->HdrLength * 4));

				packet.drop = false;
				packet.sniffer = this;
				packet.raw_data = std::string_view(LPSTR(buffer), size);
				packet.data = std::string_view(LPSTR(udpHeader) + sizeof(WINDIVERT_UDPHDR), ntohs(udpHeader->Length) - sizeof(WINDIVERT_UDPHDR));

				if (udpHeader->Length <= sizeof(WINDIVERT_UDPHDR) || packet.data.size() > maxSize) packet.data = std::string_view(LPSTR(udpHeader), 0);

				IN_ADDR addr;
				addr.S_un.S_addr = ipHeader->SrcAddr;
				packet.source.set_ipv4(addr);

				addr.S_un.S_addr = ipHeader->DstAddr;
				packet.target.set_ipv4(addr);

				packet.source.set_port(ntohs(udpHeader->SrcPort));
				packet.target.set_port(ntohs(udpHeader->DstPort));

				if (this->callback) this->callback(&packet);
				if (!packet.drop) win_diver_send(this->handle, PVOID(packet.raw_data.data()), UINT(packet.raw_data.size()), &packet.address, &size);
			}
			else
			{
				std::this_thread::yield();
			}
		}
	}

	bool sniffer::send(network::packet* packet)
	{
		this->divert.invoke_pascal<BOOL>("WinDivertHelperCalcChecksums", PVOID(packet->raw_data.data()), UINT(packet->raw_data.size()), 0ui64);

		u_int size = 0;
		BOOL result = this->divert.invoke_pascal<BOOL>("WinDivertSend", this->handle, PVOID(packet->raw_data.data()), UINT(packet->raw_data.size()), &packet->address, &size) == TRUE;
		return (result && size == packet->raw_data.size());
	}

	void sniffer::on_packet(packet_callback _callback)
	{
		this->callback = _callback;
	}

	void sniffer::extract_ressources()
	{
#ifndef _WIN64
		BOOL is64Bit = FALSE;
		IsWow64Process(GetCurrentProcess(), &is64Bit);

		if (is64Bit)
		{
#endif
			std::ofstream driver("WinDivert64.sys", std::ios::binary | std::ofstream::out);
			driver << utils::load_resource(WINDIVERT_DRIVER_x64);
			driver.close();
#ifndef _WIN64
		}
		else
		{
			std::ofstream driver("WinDivert32.sys", std::ios::binary | std::ofstream::out);
			driver << utils::load_resource(WINDIVERT_DRIVER_x86);
			driver.close();
		}
#endif

		std::ofstream library("WinDivert.dll", std::ios::binary | std::ofstream::out);
		library <<utils::load_resource(WINDIVERT_DLL);
		library.close();
	}

	sniffer::sniffer() : stopped(false), handle(INVALID_HANDLE_VALUE)
	{
		this->extract_ressources();

		this->divert = utils::nt::module::load("WinDivert.dll");
		if (this->divert.is_valid())
		{
			this->handle = this->divert.invoke_pascal<HANDLE>("WinDivertOpen", "ip", WINDIVERT_LAYER_NETWORK, -1000i16, 0ui64);
		}
	}

	sniffer::~sniffer()
	{
		this->stop();
	}
}
