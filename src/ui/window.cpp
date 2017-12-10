#include "std_include.hpp"

#pragma warning(push)
#pragma warning(disable: 4067)
#pragma warning(disable: 4127)
#pragma warning(disable: 4244)
#pragma warning(disable: 4456)
#pragma warning(disable: 4996)

#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#define NK_IMPLEMENTATION
#define NK_D3D11_IMPLEMENTATION
#define CINTERFACE
#define D3D11_NO_HELPERS
#include <nuklear.h>
#include <nuklear_d3d11.h>#pragma warning(pop)
#include "ui/window.hpp"

#define WINDOW_WIDTH 800
#define WINDOW_HEIGHT 600

#define MAX_VERTEX_BUFFER 512 * 1024
#define MAX_INDEX_BUFFER 128 * 1024

namespace ui
{
	bool window::is_running()
	{
		return this->running;
	}

	void window::stop()
	{
		this->running = false;
	}

	void window::init_d3d11()
	{
		RECT rect = { 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT };
		DWORD style = WS_OVERLAPPEDWINDOW;
		DWORD exstyle = WS_EX_APPWINDOW;

		HRESULT hr;
		D3D_FEATURE_LEVEL feature_level;
		DXGI_SWAP_CHAIN_DESC swap_chain_desc;

		ZeroMemory(&this->wc, sizeof(this->wc));
		this->wc.style = CS_DBLCLKS;
		this->wc.lpfnWndProc = window::window_proc;
		this->wc.hInstance = GetModuleHandleW(0);
		this->wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
		this->wc.hCursor = LoadCursor(NULL, IDC_ARROW);
		this->wc.lpszClassName = L"HarpoonWindowClass";
		RegisterClassW(&wc);

		AdjustWindowRectEx(&rect, style, FALSE, exstyle);

		this->hwnd = CreateWindowExW(exstyle, wc.lpszClassName, L"Harpoon",
			style | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
			rect.right - rect.left, rect.bottom - rect.top,
			NULL, NULL, wc.hInstance, NULL);

		SetWindowLongPtrA(this->hwnd, GWLP_USERDATA, LONG_PTR(this));

		ZeroMemory(&swap_chain_desc, sizeof(swap_chain_desc));
		swap_chain_desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		swap_chain_desc.BufferDesc.RefreshRate.Numerator = 60;
		swap_chain_desc.BufferDesc.RefreshRate.Denominator = 1;
		swap_chain_desc.SampleDesc.Count = 1;
		swap_chain_desc.SampleDesc.Quality = 0;
		swap_chain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		swap_chain_desc.BufferCount = 1;
		swap_chain_desc.OutputWindow = this->hwnd;
		swap_chain_desc.Windowed = TRUE;
		swap_chain_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
		swap_chain_desc.Flags = 0;

		if (FAILED(D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE,
			NULL, 0, NULL, 0, D3D11_SDK_VERSION, &swap_chain_desc,
			&this->swap_chain, &this->device, &feature_level, &this->context)))
		{
			/* if hardware device fails, then try WARP high-performance
			software rasterizer, this is useful for RDP sessions */
			hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP,
				NULL, 0, NULL, 0, D3D11_SDK_VERSION, &swap_chain_desc,
				&this->swap_chain, &this->device, &feature_level, &this->context);
			assert(SUCCEEDED(hr));
		}

		this->resize(WINDOW_WIDTH, WINDOW_HEIGHT);

		this->ctx = nk_d3d11_init(device, WINDOW_WIDTH, WINDOW_HEIGHT, MAX_VERTEX_BUFFER, MAX_INDEX_BUFFER);
	}

	void window::uninit_d3d11()
	{
		ID3D11DeviceContext_ClearState(this->context);
		nk_d3d11_shutdown();
		ID3D11ShaderResourceView_Release(this->rt_view);
		ID3D11DeviceContext_Release(this->context);
		ID3D11Device_Release(this->device);
		IDXGISwapChain_Release(this->swap_chain);
		UnregisterClassW(this->wc.lpszClassName, this->wc.hInstance);
	}

	void window::msg_loop()
	{
		nk_input_begin(this->ctx);

		MSG msg;
		while (this->running && PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE))
		{
			if (msg.message == WM_QUIT) this->running = 0;
			TranslateMessage(&msg);
			DispatchMessageA(&msg);
		}

		nk_input_end(this->ctx);
	}

	void window::nk_frame()
	{
		if (nk_begin(ctx, "Demo", nk_rect(50, 50, 230, 250), NK_WINDOW_BORDER | NK_WINDOW_MOVABLE | NK_WINDOW_SCALABLE | NK_WINDOW_MINIMIZABLE | NK_WINDOW_TITLE))
		{
			enum { EASY, HARD };
			static int op = EASY;
			static int property = 20;

			nk_layout_row_static(ctx, 30, 80, 1);
			if (nk_button_label(ctx, "button"))
			{
				utils::logger::info("Button pressed\n");
			}

			nk_layout_row_dynamic(ctx, 30, 2);
			if (nk_option_label(ctx, "easy", op == EASY)) op = EASY;
			if (nk_option_label(ctx, "hard", op == HARD)) op = HARD;
			nk_layout_row_dynamic(ctx, 22, 1);
			nk_property_int(ctx, "Compression:", 0, &property, 100, 10, 1);

			nk_layout_row_dynamic(ctx, 20, 1);
			nk_label(ctx, "background:", NK_TEXT_LEFT);
			nk_layout_row_dynamic(ctx, 25, 1);

			auto background = nk_rgb(0, 0, 0);
			if (nk_combo_begin_color(ctx, background, nk_vec2(nk_widget_width(ctx), 400)))
			{
				nk_layout_row_dynamic(ctx, 120, 1);
				background = nk_color_picker(ctx, background, NK_RGBA);
				nk_layout_row_dynamic(ctx, 25, 1);
				background.r = (nk_byte)nk_propertyi(ctx, "#R:", 0, background.r, 255, 1, 1);
				background.g = (nk_byte)nk_propertyi(ctx, "#G:", 0, background.g, 255, 1, 1);
				background.b = (nk_byte)nk_propertyi(ctx, "#B:", 0, background.b, 255, 1, 1);
				background.a = (nk_byte)nk_propertyi(ctx, "#A:", 0, background.a, 255, 1, 1);
				nk_combo_end(ctx);
			}
		}

		nk_end(ctx);
	}

	void window::present()
	{
		float bg[4];
		nk_color_fv(bg, nk_rgb(200, 200, 200));

		ID3D11DeviceContext_ClearRenderTargetView(context, rt_view, bg);
		ID3D11DeviceContext_OMSetRenderTargets(context, 1, &rt_view, NULL);

		nk_d3d11_render(context, NK_ANTI_ALIASING_ON);

		HRESULT hr = IDXGISwapChain_Present(swap_chain, 1, 0);
		if (hr == DXGI_ERROR_DEVICE_RESET || hr == DXGI_ERROR_DEVICE_REMOVED)
		{
			MessageBoxW(NULL, L"D3D11 device is lost or removed!", L"Error", 0);
			this->running = false;
		}
		else if (hr == DXGI_STATUS_OCCLUDED)
		{
			std::this_thread::sleep_for(10ms);
		}

		assert(SUCCEEDED(hr));
	}

	void window::resize(int width, int height)
	{
		ID3D11Texture2D* back_buffer;
		D3D11_RENDER_TARGET_VIEW_DESC desc;
		HRESULT hr;

		if (this->rt_view) ID3D11RenderTargetView_Release(this->rt_view);
		ID3D11DeviceContext_OMSetRenderTargets(this->context, 0, NULL, NULL);

		hr = IDXGISwapChain_ResizeBuffers(this->swap_chain, 0, width, height, DXGI_FORMAT_UNKNOWN, 0);
		if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET || hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR)
		{
			/* to recover from this, you'll need to recreate device and all the resources */
			MessageBoxW(NULL, L"DXGI device is removed or reset!", L"Error", 0);
			exit(0);
		}
		assert(SUCCEEDED(hr));

		ZeroMemory(&desc, sizeof(desc));
		desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;

		assert(SUCCEEDED(IDXGISwapChain_GetBuffer(this->swap_chain, 0, IID_ID3D11Texture2D, reinterpret_cast<void**>(&back_buffer))));
		assert(SUCCEEDED(ID3D11Device_CreateRenderTargetView(this->device, reinterpret_cast<ID3D11Resource *>(back_buffer), &desc, &this->rt_view)));

		ID3D11Texture2D_Release(back_buffer);
	}

	LRESULT window::window_handler(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam)
	{
		switch (msg)
		{
		case WM_DESTROY:
			PostQuitMessage(0);
			this->running = false;
			return 0;

		case WM_CLOSE:
			this->running = false;
			break;

		case WM_SIZE:
			if (this->swap_chain)
			{
				int width = LOWORD(lparam);
				int height = HIWORD(lparam);
				this->resize(width, height);
				nk_d3d11_resize(context, width, height);
			}
			break;
		}

		if (nk_d3d11_handle_event(wnd, msg, wparam, lparam)) return 0;
		return DefWindowProcW(wnd, msg, wparam, lparam);
	}

	LRESULT CALLBACK window::window_proc(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam)
	{
		window* ui = reinterpret_cast<window*>(GetWindowLongPtr(wnd, GWLP_USERDATA));
		if (ui) return ui->window_handler(wnd, msg, wparam, lparam);
		return DefWindowProc(wnd, msg, wparam, lparam);
	}

	void window::runner()
	{
		this->running = true;
		this->init_d3d11();

		nk_font_atlas *atlas;
		nk_d3d11_font_stash_begin(&atlas);

		nk_font *droid = nk_font_atlas_add_from_file(atlas, "DroidSans.ttf", 13, 0);
		nk_d3d11_font_stash_end();
		nk_style_set_font(ctx, &droid->handle);

		while (this->running)
		{
			if (IsWindow(this->hwnd) == FALSE) this->running = false;

			this->msg_loop();
			this->nk_frame();
			this->present();
		}

		this->uninit_d3d11();
		this->running = false;
	}

	window::window() : running(true), swap_chain(nullptr), device(nullptr), context(nullptr), rt_view(nullptr), ctx(nullptr)
	{
		this->thread = std::thread(std::bind(&window::runner, this));
	}

	window::~window()
	{
		this->running = false;
		if (this->thread.joinable()) this->thread.join();
	}
}
