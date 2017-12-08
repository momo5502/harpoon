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

	std::thread worker([&]()
	{
		while (sniffer.is_running())
		{
			std::this_thread::sleep_for(10ms);
		}
	});

	// Simply drop every 10th packet, as a test
	sniffer.on_packet([&](network::packet* packet)
	{
		static int i = 0;
		if (i++ % 10 == 0)
		{
			packet->drop = true;
		}
	});

	sniffer.run();

	if (worker.joinable()) worker.join();
	return 0;
}
