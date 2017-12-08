#pragma once

#ifndef STD_INCLUDED
#error "Missing standard header"
#endif

namespace utils
{
	namespace nt
	{
		class module
		{
		public:
			static module load(std::string module);
			static module get_by_address(void* address);
			static void add_load_path(std::string path);

			module();
			module(std::string name, bool load = false);
			module(HMODULE handle);

			module(const module& a) : module(a.handle) {}

			bool operator!=(const module &obj) const { return !(*this == obj); };
			bool operator==(const module &obj) const;

			void unprotect();
			void* get_entry_point();
			size_t get_relative_entry_point();

			bool is_valid();
			std::string get_name();
			std::string get_path();
			std::string get_folder();
			std::uint8_t* get_ptr();
			void free();

			HMODULE get_handle();

			template <typename T>
			T getProc(std::string process)
			{
				if (!this->is_valid()) nullptr;
				return reinterpret_cast<T>(GetProcAddress(this->handle, process.data()));
			}

			template <typename T>
			std::function<T> get(std::string process)
			{
				if (!this->is_valid()) std::function<T>();
				return reinterpret_cast<T*>(this->getProc<void*>(process));
			}

			template<typename T, typename... Args>
			T invoke(std::string process, Args... args)
			{
				auto method = this->get<T(__cdecl)(Args...)>(process);
				if (method) return method(args...);
				return T();
			}

			template<typename T, typename... Args>
			T invoke_pascal(std::string process, Args... args)
			{
				auto method = this->get<T(__stdcall)(Args...)>(process);
				if (method) return method(args...);
				return T();
			}

			template<typename T, typename... Args>
			T invoke_this(std::string process, void* thisPtr, Args... args)
			{
				auto method = this->get<T(__thiscall)(void*, Args...)>(thisPtr, process);
				if (method) return method(args...);
				return T();
			}

			std::vector<PIMAGE_SECTION_HEADER> get_section_headers();

			PIMAGE_NT_HEADERS get_nt_headers();
			PIMAGE_DOS_HEADER get_dos_header();
			PIMAGE_OPTIONAL_HEADER get_optional_header();

			size_t get_code_size();
			void* get_code_start();

			void** get_iat_entry(std::string moduleName, std::string procName);

#ifdef _DELAY_IMP_VER
			bool delay_import();
#endif

		private:
			HMODULE handle;
		};

		void raise_hard_error();
	}
}
