#pragma once

namespace krypto::pad {

	namespace internal {

		constexpr static std::array<unsigned char, 32> compute_zero_padding() noexcept
		{
			std::array<unsigned char, 32> data{};
			data.fill(0);
			return data;
		}

		constexpr static std::array<unsigned char, 32> compute_x_padding(int x) noexcept
		{
			std::array<unsigned char, 32> data{};
			std::fill(data.begin(), data.end(), x);
			return data;
		}

	}

	struct ansix923 {
		/**
		 * Detect number of padding bytes
		 * It must be an iterator to contiguous data with padding at end
		 */
		template <typename It>
		static void apply(It it, uint8_t pad_size) noexcept;

		template <typename It>
		static uint8_t detect(It it) noexcept;
	};

	struct pkcs7 {

		template <typename It>
		static void apply(It it, uint8_t pad_size) noexcept;

		/**
		 * Detect number of padding bytes
		 * It must be an iterator to contiguous data with padding at end
		 */
		template <typename It>
		static uint8_t detect(It it) noexcept;
	};

	template <typename It>
	inline void ansix923::apply(It it, uint8_t pad_size) noexcept
	{
		const auto padding = internal::compute_zero_padding();

		// Pad first N-1 bytes with 0
		std::copy(padding.begin(), padding.begin() + (pad_size - 1), it);
		// Last pad byte is N
		auto last_pad = std::next(it, pad_size - 1);
		*last_pad = pad_size;
	}

	template <typename It>
	inline uint8_t ansix923::detect(It it) noexcept
	{
		const auto pad_size = *it;

		// Make sure padding is valid
		const auto to = std::prev(it, pad_size - 1);
		it--;
		for (; it != to; it--) {
			if (*it != 0)
				return 0;
		}

		return pad_size;
	}

	template <typename It>
	inline void pkcs7::apply(It it, uint8_t pad_size) noexcept
	{
		const auto padding = internal::compute_x_padding(pad_size);

		// Pad first N bytes with pad_size
		std::copy(padding.begin(), padding.begin() + pad_size, it);
	}

	template <typename It>
	inline uint8_t pkcs7::detect(It it) noexcept
	{
		const auto pad_size = *it;

		// Make sure padding is valid
		const auto to = std::prev(it, pad_size - 1);
		it--;
		for (; it != to; it--) {
			if (*it != pad_size)
				return 0;
		}

		return pad_size;
	}


}
