#include "std_include.hpp"

#include "network/address.hpp"
#include "network/sniffer.hpp"

#pragma warning(push)
#pragma warning(disable: 4067)
#pragma warning(disable: 4127)
#pragma warning(disable: 4244)
#pragma warning(disable: 4456)
#pragma warning(disable: 4701)
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
#include <nuklear_d3d11.h>

#pragma warning(pop)
#include "ui/window.hpp"

#define WINDOW_WIDTH 500
#define WINDOW_HEIGHT 300

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
		ZeroMemory(&this->wc, sizeof(this->wc));
		this->wc.style = CS_DBLCLKS;
		this->wc.lpfnWndProc = window::window_proc;
		this->wc.hInstance = GetModuleHandleW(0);
		this->wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
		this->wc.hCursor = LoadCursor(NULL, IDC_ARROW);
		this->wc.lpszClassName = L"HarpoonWindowClass";
		RegisterClassW(&wc);

		DWORD exstyle = WS_EX_APPWINDOW;
		DWORD style = WS_OVERLAPPEDWINDOW & ~(WS_MAXIMIZEBOX | WS_THICKFRAME);
		RECT rect = { 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT };
		AdjustWindowRectEx(&rect, style, FALSE, exstyle);

		this->hwnd = CreateWindowExW(exstyle, wc.lpszClassName, L"Harpoon",
			style | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
			rect.right - rect.left, rect.bottom - rect.top,
			NULL, NULL, wc.hInstance, NULL);

		SetWindowLongPtrA(this->hwnd, GWLP_USERDATA, LONG_PTR(this));

		DXGI_SWAP_CHAIN_DESC swap_chain_desc;
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

		D3D_FEATURE_LEVEL feature_level;
		if (FAILED(D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE,
			NULL, 0, NULL, 0, D3D11_SDK_VERSION, &swap_chain_desc,
			&this->swap_chain, &this->device, &feature_level, &this->context)))
		{
			/* if hardware device fails, then try WARP high-performance
			software rasterizer, this is useful for RDP sessions */
			BOOL s = SUCCEEDED(D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP,
				NULL, 0, NULL, 0, D3D11_SDK_VERSION, &swap_chain_desc,
				&this->swap_chain, &this->device, &feature_level, &this->context));
			assert(s); s;
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
		if (nk_begin(this->ctx, "Harpoon", nk_rect(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT), NK_WINDOW_NO_SCROLLBAR))
		{
			nk_layout_row_dynamic(this->ctx, WINDOW_HEIGHT - 9, 2); // wrapping row

			if (nk_group_begin(this->ctx, "column1", NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR))
			{
				nk_layout_row_begin(this->ctx, NK_STATIC, 0, 2);
				{
					// Make sure to store a copy of all clients, so that the 'enabled' ptr passed to nuklear
					// stays alive until the next frame (due to the stored shared_ptrs)
					this->client_copy = sniffer->get_clients();
					for (auto& client : this->client_copy)
					{
						nk_layout_row_push(this->ctx, 100);
						nk_label(this->ctx, client->to_string().data(), NK_TEXT_LEFT);

						nk_checkbox_label(this->ctx, "Poison", &client->enabled);
					}
				}
				nk_layout_row_end(this->ctx);

				nk_group_end(this->ctx);
			}

			if (nk_group_begin(this->ctx, "column2", NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR))
			{
				nk_layout_row_dynamic(this->ctx, 0, 1);
				if (nk_button_label(ctx, "Refresh"))
				{
					this->sniffer->scan_network();
				}

				nk_layout_row_dynamic(ctx, 30, 2);
				if (nk_option_label(ctx, "Forward Packets", this->forward_packets))
				{
					if (!this->forward_packets)
					{
						this->sniffer->forward_packets(true);
					}

					this->forward_packets = true;
				}
				if (nk_option_label(this->ctx, "Drop Packets", !this->forward_packets))
				{
					if (this->forward_packets)
					{
						this->sniffer->forward_packets(false);
					}

					this->forward_packets = false;
				}

				nk_layout_row_dynamic(this->ctx, 0, 1);
				if (nk_checkbox_label(this->ctx, "Dump packets", &this->dump_packets))
				{
					this->sniffer->set_dumping(this->dump_packets != 0);
				}

				nk_layout_row_dynamic(this->ctx, 0, 1);

				char str[100];
				_snprintf_s(str, sizeof(str), "Sniffed packets: %lld", this->sniffer->get_sniffed_packets());
				nk_label(ctx, str, NK_TEXT_LEFT);

				nk_group_end(this->ctx);
			}
		}

		nk_end(this->ctx);
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
		if (this->rt_view) ID3D11RenderTargetView_Release(this->rt_view);
		ID3D11DeviceContext_OMSetRenderTargets(this->context, 0, NULL, NULL);

		HRESULT hr = IDXGISwapChain_ResizeBuffers(this->swap_chain, 0, width, height, DXGI_FORMAT_UNKNOWN, 0);
		if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET || hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR)
		{
			/* to recover from this, you'll need to recreate device and all the resources */
			MessageBoxW(NULL, L"DXGI device is removed or reset!", L"Error", 0);
			exit(0);
		}
		assert(SUCCEEDED(hr));

		D3D11_RENDER_TARGET_VIEW_DESC desc;
		ZeroMemory(&desc, sizeof(desc));
		desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;

		ID3D11Texture2D* back_buffer = nullptr;
		hr = IDXGISwapChain_GetBuffer(this->swap_chain, 0, IID_ID3D11Texture2D, reinterpret_cast<void**>(&back_buffer));
		assert(SUCCEEDED(hr));

		hr = ID3D11Device_CreateRenderTargetView(this->device, reinterpret_cast<ID3D11Resource *>(back_buffer), &desc, &this->rt_view);
		assert(SUCCEEDED(hr));

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

		std::string font = utils::load_resource(DROID_SANS_FONT);
		nk_font *droid = nk_font_atlas_add_from_memory(atlas, const_cast<char*>(font.data()), font.size(), 13, 0);
		nk_d3d11_font_stash_end();
		nk_style_set_font(ctx, &droid->handle);

		while (this->running && this->sniffer->is_running())
		{
			if (IsWindow(this->hwnd) == FALSE) this->running = false;

			this->msg_loop();
			this->nk_frame();
			this->present();
		}

		this->uninit_d3d11();
		this->client_copy.clear();
		this->running = false;

		this->sniffer->stop();
	}

	window::window(network::sniffer* _sniffer) : running(true), swap_chain(nullptr), device(nullptr), context(nullptr), rt_view(nullptr), ctx(nullptr), sniffer(_sniffer), forward_packets(false), dump_packets(0)
	{
		this->thread = std::thread(std::bind(&window::runner, this));
	}

	window::~window()
	{
		this->running = false;
		if (this->thread.joinable()) this->thread.join();
	}
}
