#include "std_include.hpp"

#include "network/address.hpp"

namespace network
{
	address::address()
	{
		ZeroMemory(&this->sock_address, sizeof(this->sock_address));
	}

	address::address(std::string addr) : address()
	{
		this->parse(addr);
	}

	address::address(sockaddr_in* addr)
	{
		this->sock_address = *addr;
	}

	bool address::operator==(const address &obj) const
	{
		return !std::memcmp(&this->sock_address, &obj.sock_address, sizeof(this->sock_address));
	}

	void address::set_ipv4(in_addr addr)
	{
		this->sock_address.sin_family = AF_INET;
		this->sock_address.sin_addr = addr;
	}

	void address::set_port(unsigned short port)
	{
		this->sock_address.sin_port = htons(port);
	}

	unsigned short address::getPort()
	{
		return ntohs(this->sock_address.sin_port);
	}

	std::string address::to_string()
	{
		char buffer[MAX_PATH] = { 0 };
		inet_ntop(this->sock_address.sin_family, &this->sock_address.sin_addr, buffer, sizeof(buffer));
		_snprintf_s(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), sizeof(buffer) - strlen(buffer), "%hu", this->getPort());
		return buffer;
	}

	bool address::is_local()
	{
		// According to: https://en.wikipedia.org/wiki/Private_network

		// 10.X.X.X
		if (this->sock_address.sin_addr.S_un.S_un_b.s_b1 == 10) return true;

		// 192.168.X.X
		if (this->sock_address.sin_addr.S_un.S_un_b.s_b1 == 192 && this->sock_address.sin_addr.S_un.S_un_b.s_b2 == 168) return true;

		// 172.16.X.X - 172.31.X.X
		if (this->sock_address.sin_addr.S_un.S_un_b.s_b1 == 172 && (this->sock_address.sin_addr.S_un.S_un_b.s_b2 >= 16) && (this->sock_address.sin_addr.S_un.S_un_b.s_b2 < 32)) return true;

		// 127.0.0.1
		if (this->sock_address.sin_addr.S_un.S_addr == 0x0100007F) return true;

		// TODO: Maybe check for matching localIPs and subnet mask

		return false;
	}

	sockaddr* address::get_addr()
	{
		return reinterpret_cast<sockaddr*>(this->get_in_addr());
	}

	sockaddr_in* address::get_in_addr()
	{
		return &this->sock_address;
	}

	void address::parse(std::string addr)
	{
		auto pos = addr.find_last_of(":");
		if (pos != std::string::npos)
		{
			std::string port = addr.substr(pos + 1);
			this->set_port(USHORT(atoi(port.data())));

			addr = addr.substr(0, pos);
		}

		this->resolve(addr);
	}

	void address::resolve(std::string hostname)
	{
		addrinfo *result = nullptr;
		if (!getaddrinfo(hostname.data(), nullptr, nullptr, &result))
		{
			unsigned short port = this->getPort();
			std::memcpy(&this->sock_address, result->ai_addr, sizeof(this->sock_address));
			this->set_port(port);

			freeaddrinfo(result);
		}
	}
}
