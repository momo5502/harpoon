#pragma once

#ifndef STD_INCLUDED
#error "Missing standard header"
#endif

namespace utils
{
	class memory
	{
	public:
		class allocator
		{
		public:
			allocator()
			{
				this->pool.clear();
			}
			~allocator()
			{
				this->clear();
			}

			void clear()
			{
				std::lock_guard<std::mutex> _(this->mutex);

				for (auto& data : this->pool)
				{
					memory::free(data);
				}

				this->pool.clear();
			}

			void free(void* data)
			{
				std::lock_guard<std::mutex> _(this->mutex);

				auto j = std::find(this->pool.begin(), this->pool.end(), data);
				if (j != this->pool.end())
				{
					memory::free(data);
					this->pool.erase(j);
				}
			}

			void free(const void* data)
			{
				this->free(const_cast<void*>(data));
			}

			void* allocate(size_t length)
			{
				std::lock_guard<std::mutex> _(this->mutex);

				void* data = memory::allocate(length);
				this->pool.push_back(data);
				return data;
			}
			template <typename T> inline T* allocate()
			{
				return this->allocate_array<T>(1);
			}
			template <typename T> inline T* allocate_array(size_t count = 1)
			{
				return static_cast<T*>(this->allocate(count * sizeof(T)));
			}

			bool empty()
			{
				return this->pool.empty();
			}

			char* duplicateString(std::string string)
			{
				std::lock_guard<std::mutex> _(this->mutex);

				char* data = memory::duplicate_string(string);
				this->pool.push_back(data);
				return data;
			}

		private:
			std::mutex mutex;
			std::vector<void*> pool;
		};

		static void* allocate_align(size_t length, size_t alignment);
		static void* allocate(size_t length);
		template <typename T> static inline T* allocate()
		{
			return allocate_array<T>(1);
		}
		template <typename T> static inline T* allocate_array(size_t count = 1)
		{
			return static_cast<T*>(allocate(count * sizeof(T)));
		}

		static char* duplicate_string(std::string string);

		static void free(void* data);
		static void free(const void* data);

		static void free_align(void* data);
		static void free_align(const void* data);

		static bool is_set(void* mem, char chr, size_t length);

		static bool is_bad_read_ptr(const void* ptr);
		static bool is_bad_code_ptr(const void* ptr);

		static allocator* get_allocator();

	private:
		static allocator mem_allocator;
	};
}
