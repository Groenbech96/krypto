#pragma once
#include <array>

#ifdef WIN32
#include <immintrin.h>
#endif

namespace krypto {

	/**
	 * Compute secure random number.
	 * https://en.wikipedia.org/wiki/RDRAND
	 */
	inline uint64_t get_srandom_u64() noexcept {
#ifdef WIN32

		int ready = 0;
		uint64_t val;
		while (!ready) {
			ready = _rdrand64_step(&val);
		}
		return val;

#else 
		uint64_t val;
		unsigned char ready = 0;

		while ((int)ready == 0) {
			asm volatile ("rdrand %0; setc %1"
				: "=r" (val), "=qm" (ready));
		}

		return val;
#endif
	}

	template <size_t bytes>
	inline std::array<unsigned char, bytes> get_srandom_bytes() noexcept {

		std::array<unsigned char, bytes> data;

		const auto total = data.size() >> 3; // size / 8
		for (size_t i = 0; i < total; i++) {
			const uint64_t random = get_srandom_u64();
			auto* pchar = reinterpret_cast<const char*>(&random);
			std::memcpy(&data[(i * 8)], pchar, 8);
		}
		const auto rest = data.size() - (total << 3); // total * 8
		if (rest) {
			const uint64_t random = get_srandom_u64();
			auto* pchar = reinterpret_cast<const char*>(&random);
			std::memcpy(&data[(total << 3)], pchar, rest);
		}

		return data;
	}











}
