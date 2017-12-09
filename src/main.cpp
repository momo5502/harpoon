#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

static utils::static_initializer $([]()
{
	// Before application initialization
	utils::logger::reset_color();
}, []()
{
	// After application termination
	utils::logger::reset_color();
});

int main(int /*argc*/, char** /*argv*/)
{
	utils::set_environment();
	utils::logger::set_title("Harpoon");

#ifdef DEBUG
	utils::logger::set_verbose(true);
#else
	utils::logger::set_verbose(false);
#endif

	network::sniffer sniffer;
	utils::signal_handler sig_handler([&sniffer]()
	{
		sniffer.stop();
	});

	std::thread worker([&]()
	{
		sniffer.create_arp_packet();

		utils::logger::info("Starting ARP poisoning");

		while (sniffer.is_running())
		{
			if (!sniffer.send())
			{
				utils::logger::warn("Failed to send packet");
			}

			std::this_thread::sleep_for(10ms);
		}
	});

	/*sniffer.on_packet([&](network::packet* packet)
	{

	});*/

	sniffer.run();

	if (worker.joinable()) worker.join();
	return 0;
}
