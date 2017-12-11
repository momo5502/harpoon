#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

#include "ui/window.hpp"

int CALLBACK WinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/, LPSTR /*lpCmdLine*/, int /*nCmdShow*/)
{
	utils::set_environment();

	{
		std::ifstream t("oui.txt");
		std::string str;

		t.seekg(0, std::ios::end);
		str.reserve(t.tellg());
		t.seekg(0, std::ios::beg);

		str.assign((std::istreambuf_iterator<char>(t)),
			std::istreambuf_iterator<char>());

		std::vector<std::pair<uint8_t[3], std::string>> ouis;

		std::regex test(".*([A-Fa-f0-9][A-Fa-f0-9])-([A-Fa-f0-9][A-Fa-f0-9])-([A-Fa-f0-9][A-Fa-f0-9])\\s*\\(hex\\)\\s*(.*)\\n");
		std::sregex_iterator iter(str.begin(), str.end(), test);
		std::sregex_iterator end;

		while (iter != end)
		{
			if (iter->size() == 5)
			{
				ouis.push_back({ (*iter)[1], (*iter)[2] });
			}
			
			++iter;
		}
	}

	network::sniffer sniffer;
	ui::window window(&sniffer);

	sniffer.forward_packets(false);

	sniffer.run();

	sniffer.forward_packets(false);
	return 0;
}
