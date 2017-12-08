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

	}

	void sniffer::run()
	{

	}

	bool sniffer::send(network::packet* packet)
	{
		return false;
	}

	void sniffer::on_packet(packet_callback _callback)
	{
		this->callback = _callback;
	}

	sniffer::sniffer() : stopped(false), handle(INVALID_HANDLE_VALUE)
	{

	}

	sniffer::~sniffer()
	{
		this->stop();
	}
}
