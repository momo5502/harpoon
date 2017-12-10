#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

#include "ui/window.hpp"

int CALLBACK WinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, LPSTR /*lpCmdLine*/, int /*nCmdShow*/)
{
	utils::set_environment();

	network::sniffer sniffer;
	ui::window window(&sniffer);

	sniffer.forward_packets(false);

	sniffer.run();

	sniffer.forward_packets(false);
	return 0;
}
