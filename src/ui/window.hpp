#pragma once

namespace ui
{
	class window
	{
	public:
		window();
		~window();

	private:
		std::thread thread;
		void runner();
	};
}
