#pragma once

#include <cstdint>
#include <array>
#include <span>


namespace krypto::math {

	/**
	 * AES Log and Anti log lookup tables
	 * Anti log table is large enough to contain the sum of 255+255
	 */
	struct aes_log_tables {
		std::array<uint8_t, 256> log{};
		std::array<uint8_t, 510> anti_log{};
	};

	/**
	 * AES substitution tables
	 */
	struct aes_sub_tables {
		std::array<uint8_t, 256> sbox{};
		std::array<uint8_t, 256> inv_sbox{};
	};

	/**
	 * RCon table
	 */
	using aes_rcon = std::array<uint8_t, 14>;


	// Adding in GF(2^8) is implemented using XOR
	constexpr uint8_t add256(uint8_t x, uint8_t y) {
		return x ^ y;
	}

	// Multiplication in GF(2^8) by Russian Peasant Multiplication algorithm
	// https://en.wikipedia.org/wiki/Finite_field_arithmetic
	constexpr uint8_t mult256(uint8_t x, uint8_t y) {

		uint8_t res = 0;
		while (x && y) {

			if (y & 0x00000001) // Is right most bit set
				res ^= x;

			const auto carry = x & 0b10000000;
			y >>= 1;	// Shift one bit to the (half)
			x <<= 1;	// Shift one bit to left (double)

			if (carry) { // Is rightmost bit set
				x ^= 0x1b;
			}
		}
		return res;
	}


	// Compute log tables
	// From https://crypto.stackexchange.com/questions/12956/multiplicative-inverse-in-operatornamegf28/40140#40140
	constexpr aes_log_tables compute_aes_log_tables() {
		aes_log_tables t{};
		constexpr auto generator = 3;

		t.log[0] = 0;

		// x = mult(x, generator); 
		int x = 1;
		for (int i = 0; i < 255; i++) {
			t.log[x] = i;	// Get exponent from number
			t.anti_log[i] = x; // Get number from exponent 

			x = mult256(x, generator); // g^1, g^2, g^3 
		}
		for (int i = 255; i < 510; i++) {
			t.anti_log[i] = x; // Get number from exponent 
			x = mult256(x, generator); // g^1, g^2, g^3 
		}

		return t;
	}

	// Log and anti log tables
	// Used to do fast mult and inverse calculations
	inline constexpr aes_log_tables LOG_TABLES = compute_aes_log_tables();
	
	/**
	 * Compute multiplication in GF(2^8) using lookup tables
	 */
	constexpr uint8_t fast_mult256(uint8_t a, uint8_t b) {
		if (a == 0 || b == 0) return 0;

		const auto x = LOG_TABLES.log[a];
		const auto y = LOG_TABLES.log[b];
		// Anti log table is 510 elements to support the overflow when adding two
		const auto log_mult = (x + y); 

		return LOG_TABLES.anti_log[log_mult];
	}

	/**
	 * Compute inverse in GF(2^8)
	 */
	constexpr uint8_t fast_inv256(uint8_t a) {

		if (a == 0) return 0;

		const auto x = LOG_TABLES.log[a];
		const auto inv = 255 - x;

		return LOG_TABLES.anti_log[inv];
	}

	// Circular shift 
	// https://en.wikipedia.org/wiki/Circular_shift
	constexpr uint8_t rotl8(uint8_t value, unsigned int count) {
		return value << count | value >> (8 - count);
	}

	// Compute SBox anmd InvSBox for AES 
	// https://en.wikipedia.org/wiki/Rijndael_S-box
	constexpr aes_sub_tables compute_aes_sub_tables() {

		aes_sub_tables tables{};

		// SBox
		for (size_t i = 1; i < tables.sbox.size(); i++) {
			auto inv = fast_inv256(static_cast<uint8_t>(i));
			tables.sbox[i] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63;
		}

		tables.sbox[0] = 0x63;
		
		// Inv Sbox
		for (int i = 0; i < tables.inv_sbox.size(); i++) {
			auto b = rotl8(i, 1) ^ rotl8(i, 3) ^ rotl8(i, 6) ^ 5;
			tables.inv_sbox[i] = fast_inv256(b);
		}

		return tables;
	}

	/**
	 * Compute round constants for AES 
	 * https://en.wikipedia.org/wiki/AES_key_schedule
	 */
	constexpr aes_rcon compute_aes_rcon() {

		aes_rcon values{};

		uint8_t val = 1;
		values[0] = 1;

		for (size_t i = 1; i < values.size(); i++) {
			val = fast_mult256(val, 2);
			values[i] = val;
		}

		return values;
	}


	constexpr void xor_block(std::span<unsigned char> left, 
							 std::span<unsigned char> right) noexcept {
		for (int i = 0; i < left.size(); i++) {
			left[i] ^= right[i];
		}
	}

	constexpr void xor_word(std::span<unsigned char, 4> data, 
							std::span<unsigned char, 4> right) noexcept
	{
		// Todo can we do this in one line? XOR 32 bit value
		data[0] ^= right[0];
		data[1] ^= right[1];
		data[2] ^= right[2];
		data[3] ^= right[3];
	}

	constexpr void rot_word(std::span<unsigned char, 4> data) noexcept
	{
		// Todo: Can we do this in one line? Shift 32 byte integer?
		const auto temp = data[0];
		data[0] = data[1];
		data[1] = data[2];
		data[2] = data[3];
		data[3] = temp;
	}

	
	template <size_t S>
	constexpr void sub_bytes(std::span<unsigned char, S> data, std::span<const unsigned char> sbox) noexcept
	{
		for (size_t i = 0; i < S; i++) {
			data[i] = sbox[data[i]];
		}
	}

	template <size_t S>
	constexpr void inv_sub_bytes(std::span<unsigned char, S> data, std::span<const unsigned char> inv_sbox) noexcept
	{
		for (size_t i = 0; i < S; i++) {
			data[i] = inv_sbox[data[i]];
		}
	}







}

