#include "std_include.hpp"

namespace utils
{
	memory::allocator memory::mem_allocator;

	void* memory::allocate_align(size_t length, size_t alignment)
	{
		void* data = _aligned_malloc(length, alignment);
		assert(data != nullptr);
		if (data) ZeroMemory(data, length);
		return data;
	}

	void* memory::allocate(size_t length)
	{
		void* data = calloc(length, 1);
		assert(data != nullptr);
		return data;
	}

	char* memory::duplicate_string(std::string string)
	{
		char* newString = memory::allocate_array<char>(string.size() + 1);
		std::memmove(newString, string.data(), string.size());
		return newString;
	}

	void memory::free(void* data)
	{
		if (data)
		{
			::free(data);
		}
	}

	void memory::free(const void* data)
	{
		memory::free(const_cast<void*>(data));
	}

	void memory::free_align(void* data)
	{
		if (data)
		{
			_aligned_free(data);
		}
	}

	void memory::free_align(const void* data)
	{
		memory::free_align(const_cast<void*>(data));
	}

	// Complementary function for memset, which checks if memory is filled with a char
	bool memory::is_set(void* mem, char chr, size_t length)
	{
		char* memArr = reinterpret_cast<char*>(mem);

		for (size_t i = 0; i < length; ++i)
		{
			if (memArr[i] != chr)
			{
				return false;
			}
		}

		return true;
	}

	bool memory::is_bad_read_ptr(const void* ptr)
	{
		MEMORY_BASIC_INFORMATION mbi = { nullptr };
		if (VirtualQuery(ptr, &mbi, sizeof(mbi)))
		{
			DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
			bool b = !(mbi.Protect & mask);
			// check the page is not a guard page
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

			return b;
		}
		return true;
	}

	bool memory::is_bad_code_ptr(const void* ptr)
	{
		MEMORY_BASIC_INFORMATION mbi = { nullptr };
		if (VirtualQuery(ptr, &mbi, sizeof(mbi)))
		{
			DWORD mask = (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
			bool b = !(mbi.Protect & mask);
			// check the page is not a guard page
			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) b = true;

			return b;
		}
		return true;
	}

	memory::allocator* memory::get_allocator()
	{
		return &memory::mem_allocator;
	}
}
