#pragma once

#define CINTERFACE
#define D3D11_NO_HELPERS
#include <d3d11.h>

namespace ui
{
	class window
	{
	public:
		window();
		~window();

		bool is_running();
		void stop();

	private:
		bool running;
		std::thread thread;

		HWND hwnd;
		WNDCLASSW wc;

		IDXGISwapChain *swap_chain;
		ID3D11Device *device;
		ID3D11DeviceContext *context;
		ID3D11RenderTargetView* rt_view;

		struct nk_context* ctx;

		void init_d3d11();
		void uninit_d3d11();

		void runner();

		void msg_loop();
		void nk_frame();
		void present();

		void resize(int width, int height);

		LRESULT window_handler(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam);
		static LRESULT CALLBACK window_proc(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam);
	};
}
