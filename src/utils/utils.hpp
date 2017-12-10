#pragma once

namespace utils
{
	class static_initializer
	{
	public:
		static_initializer(std::function<void()> init, std::function<void()> _uninit = std::function<void()>())
		{
			if (init) init();
			this->uninit = _uninit;
		}

		~static_initializer()
		{
			if (this->uninit) this->uninit();
		}

	private:
		std::function<void()> uninit;
	};

	class buffer : public std::string
	{
	public:
		buffer() : std::string() {}
		buffer(std::string data) : buffer()
		{
			this->append(data);
		}

		template <typename T> void write(T data)
		{
			this->append(reinterpret_cast<char*>(&data), sizeof T);
		}

		template <typename T> T read()
		{
			T data;
			if (!this->read(&data)) throw std::runtime_error("Buffer overflow");
			return data;
		}

		template <typename T> bool read(T* data)
		{
			if (this->size() < sizeof T) return false;

			std::memmove(data, this->data(), sizeof T);
			this->erase(this->begin(), this->begin() + sizeof T);

			return true;
		}
	};

	template <typename T> inline void merge(std::vector<T>* target, T* source, size_t length)
	{
		if (source)
		{
			target->reserve(target->size() + length);
			for (size_t i = 0; i < length; ++i)
			{
				target->push_back(source[i]);
			}
		}
	}

	template <typename T> inline void merge(std::vector<T>* target, std::vector<T> source)
	{
		target->reserve(target->size() + source.size());
		for (auto &entry : source)
		{
			target->push_back(entry);
		}
	}

	void set_environment();

#ifdef _WIN32
	std::string load_resource(int resId);
#endif
}