#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

int main(int /*argc*/, char** /*argv*/)
{
	SetConsoleTitleA("Harpoon");
	utils::set_environment();

	network::sniffer sniffer;

	utils::signal_handler sig_handler([&sniffer]()
	{
		sniffer.stop();
	});

	bool available = false;

	std::thread worker([&]()
	{
// 		arphdr_t header;
// 		header.htype = 1;
// 		header.ptype = 0x0800;
// 		header.hlen = 6;
// 		header.plen = 4;
// 		header.oper = ARP_REPLY;
// 
// 		std::memcpy(header.sha, "\xFF\xFF\xFF\xFF\xFF\xFF", header.hlen);
// 		std::memcpy(header.spa, &network::address("192.168.0.1").get_in_addr()->sin_addr.S_un.S_addr, header.plen);
// 
// 		std::memcpy(header.tha, "\xFF\xFF\xFF\xFF\xFF\xFF", header.hlen);
// 		std::memcpy(header.tpa, &network::address("192.168.0.234").get_in_addr()->sin_addr.S_un.S_addr, header.plen);

		network::packet packet;
		//packet.data = std::string_view(LPSTR(&header), sizeof(header));

		while (sniffer.is_running())
		{
			if (available)
			{
				sniffer.send(&packet);
			}

			std::this_thread::sleep_for(10ms);
		}
	});

	// Simply drop every 10th packet, as a test
	sniffer.on_packet([&](network::packet* packet)
	{
		available = true;
	});

	sniffer.run();

	if (worker.joinable()) worker.join();
	return 0;
}
