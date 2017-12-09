#pragma once

namespace network
{
	class address
	{
	public:
		address();
		address(std::string addr);
		address(sockaddr_in* addr);

		void set_ipv4(in_addr addr);
		void set_port(unsigned short port);
		unsigned short get_port();
		unsigned char* get_ipv4_bytes();

		sockaddr* get_addr();
		sockaddr_in* get_in_addr();

		bool is_local();

		std::string to_string();

		bool operator!=(const address &obj) const { return !(*this == obj); };
		bool operator==(const address &obj) const;

	private:
		sockaddr_in sock_address;

		void parse(std::string addr);
		void resolve(std::string hostname);
	};
}
