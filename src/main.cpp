#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

#include "ui/window.hpp"

void parse_oui_data()
{
	std::ifstream t("oui.txt");
	std::string str;

	t.seekg(0, std::ios::end);
	str.reserve(t.tellg());
	t.seekg(0, std::ios::beg);

	str.assign((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());

	std::vector<std::pair<uint8_t[3], std::string>> ouis;

	std::regex test(".*([A-Fa-f0-9][A-Fa-f0-9])-([A-Fa-f0-9][A-Fa-f0-9])-([A-Fa-f0-9][A-Fa-f0-9])\\s*\\(hex\\)\\s*(.*)\\n");
	std::sregex_iterator iter(str.begin(), str.end(), test);
	std::sregex_iterator end;

	while (iter != end)
	{
		if (iter->size() == 5)
		{
			std::string byte1 = (*iter)[1];
			std::string byte2 = (*iter)[2];
			std::string byte3 = (*iter)[3];

			std::pair<uint8_t[3], std::string> mac_info;
			mac_info.first[0] = uint8_t(strtoul(byte1.data(), nullptr, 16));
			mac_info.first[1] = uint8_t(strtoul(byte2.data(), nullptr, 16));
			mac_info.first[2] = uint8_t(strtoul(byte3.data(), nullptr, 16));

			mac_info.second = (*iter)[2];

			ouis.push_back(mac_info);
		}

		++iter;
	}
}

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
