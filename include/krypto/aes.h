#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <span>
#include <execution>

#include "internal/util.h"

namespace krypto {

	using byte_array = std::vector<unsigned char>;

	template <size_t extend = std::dynamic_extent>
	using byte_view = std::span<unsigned char, extend>;

	template <size_t extend = std::dynamic_extent>
	using const_byte_view = std::span<const unsigned char, extend>;

	namespace pad {

		namespace detail {
			constexpr static std::array<unsigned char, 32> compute_zero_padding() noexcept
			{
				std::array<unsigned char, 32> data{};
				return data;
			}

			static std::array<unsigned char, 32> compute_x_padding(int x) noexcept
			{
				std::array<unsigned char, 32> data{};
				std::fill(data.begin(), data.end(), x);
				return data;
			}

		}

		class ansix923 {
		public:
			template <typename It>
			static void apply(It it, uint8_t pad_size) noexcept;

			template <typename It>
			static uint8_t detect(It it) noexcept;

		private:
			static constexpr std::array<unsigned char, 32> padding = detail::compute_zero_padding();
		};


		class pkcs7 {
		public:
			template <typename It>
			static void apply(It it, uint8_t pad_size) noexcept;

			template <typename It>
			static uint8_t detect(It it) noexcept;
		};



	}


	namespace modes {

		// Electronic code book 
		class ecb {
		public:

			template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
			static void encrypt(T<size, mode, pad>* instance, byte_array& data) noexcept;

			template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
			static void decrypt(T<size, mode, pad>* instance, byte_array& data) noexcept;

		};

		class cbc {
		public:

			template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
			static void encrypt(T<size, mode, pad>* instance, byte_array& data) noexcept;

			template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
			static void decrypt(T<size, mode, pad>* instance, byte_array& data) noexcept;

		};

		



	}

	template <size_t size, typename mode, typename padding>
	class aes {
	private:
		static_assert(size == 128 || size == 194 || size == 256, "Invalid key size");
		constexpr static uint8_t NB = 4;
		constexpr static uint8_t NK = size / 32;
		constexpr static uint8_t NR = (NK)+6;

		friend class modes::ecb;
		friend class modes::cbc;

	public:
		/**
		 * Construct an AES encryption object
		 * Set key used for encryption
		 */
		constexpr aes(const_byte_view<NK * 4> key) noexcept;

		/**
		 * Encrypt data passed to function
		 */

		byte_array encrypt(const_byte_view<> data) noexcept;
		byte_array decrypt(const_byte_view<> data) noexcept;

		// Key
		std::array<unsigned char, NB* (NR + 1) * 4> expanded_key{};

	private:


		constexpr static util::aes_sub_tables sub_tables = util::compute_sub_tables();
		constexpr static util::aes_rcon rcon = util::compute_rcon();


		// Helper functions

		/**
		 * Expand Key Algorithm based on spec
		 */
		constexpr void expand_key(const_byte_view<NK * 4> key) noexcept;

		void do_encrypt(byte_view<NB * 4 > data) noexcept;
		void do_decrypt(byte_view<NB * 4> data) noexcept;

		constexpr void add_round_key(byte_view<NB * 4> data, uint8_t key_pos) noexcept;
		constexpr void sub_bytes(byte_view<NB * 4> data) noexcept;
		constexpr void shift_rows(byte_view<NB * 4 > data) noexcept;
		constexpr void mix_columns(byte_view<NB * 4 > data) noexcept;

		constexpr void inv_sub_bytes(byte_view<NB * 4 > data) noexcept;
		constexpr void inv_shift_rows(byte_view<NB * 4 > data) noexcept;
		constexpr void inv_mix_columns(byte_view<NB * 4 > data) noexcept;

		constexpr void sub_word(byte_view<4> data) noexcept;
		constexpr void rot_word(byte_view<4> data) noexcept;
		constexpr void xor_word(byte_view<4> data, byte_view<4> right) noexcept;

	};

	/// 
	// Implementation
	///


	template<size_t size, typename mode, typename padding>
	inline constexpr aes<size, mode, padding>::aes(const_byte_view<NK * 4> key) noexcept
	{
		expand_key(key);
	}

	template<size_t size, typename mode, typename padding>
	inline byte_array aes<size, mode, padding>::encrypt(const_byte_view<> data) noexcept
	{
		byte_array cipher_text;

		// Add minimum 16 bytes of padding.
		const uint8_t pad_size = (data.size() % 16 == 0 ? 0 : 16 - (data.size() % 16)) + 16;
		
		cipher_text.resize(data.size() + pad_size);
		std::copy(data.begin(), data.end(), cipher_text.begin());

		// Add padding to end of plain_text
		if (pad_size > 0)
			padding::apply(cipher_text.begin() + data.size(), pad_size);
		
		mode::encrypt(this, cipher_text);

		return cipher_text;
	}

	template<size_t size, typename mode, typename padding>
	inline byte_array aes<size, mode, padding>::decrypt(const_byte_view<> data) noexcept
	{
		byte_array plain_text;
		plain_text.resize(data.size());

		// Copy data to plain array
		std::copy(data.begin(), data.end(), plain_text.begin());
		mode::decrypt(this, plain_text);

		const auto s = padding::detect(plain_text.end() - 1);
		plain_text.resize(plain_text.size() - s);
		
		return plain_text;
	}

	template<size_t size, typename mode, typename padding>
	inline void aes<size, mode, padding>::do_encrypt(byte_view<NB * 4> data) noexcept
	{
		add_round_key(data, 0);

		for (int i = 1; i < NR; i++) {
			sub_bytes(data);
			shift_rows(data);
			mix_columns(data);
			add_round_key(data, i * (NB * 4));
		}

		sub_bytes(data);
		shift_rows(data);
		add_round_key(data, NR * (NB * 4));

	}

	template<size_t size, typename mode, typename padding>
	inline void aes<size, mode, padding>::do_decrypt(byte_view<NB * 4> data) noexcept
	{
		add_round_key(data, NR * (NB * 4));

		for (int i = NR - 1; i > 0; i--) {
			inv_shift_rows(data);
			inv_sub_bytes(data);
			add_round_key(data, i * (NB * 4));
			inv_mix_columns(data);
		}

		inv_shift_rows(data);
		inv_sub_bytes(data);
		add_round_key(data, 0);

	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::expand_key(const_byte_view<NK * 4> key) noexcept
	{

		// Copy key into first bytes of expanded key
		std::copy(key.begin(), key.end(), expanded_key.begin());

		// 1 word = 4 chars
		std::array<unsigned char, 4> temp{};
		std::array<unsigned char, 4> rcon = { 0,0,0,0 };

		size_t i = NK;
		while (i < NB * (NR + 1)) {

			auto key_it = expanded_key.begin() + (i * 4);
			std::span<unsigned char, 4> window(key_it - (NK * 4), 4);

			std::copy_n(key_it - 4, 4, temp.begin());

			if (i % NK == 0) {
				rcon[0] = this->rcon[(i / NK) - 1];

				rot_word(temp);
				sub_word(temp);
				xor_word(temp, rcon);
			}
			else if (NK > 6 && i % NK == 4) {
				sub_word(temp);
			}

			xor_word(temp, window);
			std::copy_n(temp.begin(), 4, key_it);

			i++;
		}
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::add_round_key(byte_view<NB * 4> data, uint8_t key_pos) noexcept
	{
		// Todo: Check with 4 element loop unrolling
		for (size_t i = 0; i < NB * 4; i++) {
			data[i] ^= expanded_key[key_pos + i];
		}
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::sub_bytes(byte_view<NB * 4> data) noexcept
	{
		for (size_t i = 0; i < NB * 4; i++) {
			data[i] = sub_tables.sbox[data[i]];
		}
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::shift_rows(byte_view<NB * 4> data) noexcept
	{
		// Todo: Improve this function 
		std::array<uint8_t, NB * 4> buf{};

		// No shift
		buf[0] = data[0];
		buf[4] = data[4];
		buf[8] = data[8];
		buf[12] = data[12];

		// cyclically shifts 1
		buf[1] = data[5];
		buf[5] = data[9];
		buf[9] = data[13];
		buf[13] = data[1];

		// cyclically shifts 2
		buf[2] = data[10];
		buf[6] = data[14];
		buf[10] = data[2];
		buf[14] = data[6];

		// cyclically shifts 3
		buf[3] = data[15];
		buf[7] = data[3];
		buf[11] = data[7];
		buf[15] = data[11];

		std::copy(buf.begin(), buf.end(), data.begin());
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::mix_columns(byte_view<NB * 4> data) noexcept
	{
		// Todo: Improve this function
		std::array<uint8_t, NB * 4> buf{};

		//// C1
		buf[0] = util::fast_mult(2, data[0]) ^ util::fast_mult(3, data[1]) ^ data[2] ^ data[3];
		buf[1] = data[0] ^ util::fast_mult(2, data[1]) ^ util::fast_mult(3, data[2]) ^ data[3];
		buf[2] = data[0] ^ data[1] ^ util::fast_mult(2, data[2]) ^ util::fast_mult(3, data[3]);
		buf[3] = util::fast_mult(3, data[0]) ^ data[1] ^ data[2] ^ util::fast_mult(2, data[3]);

		//// C2
		buf[4] = util::fast_mult(2, data[4]) ^ util::fast_mult(3, data[5]) ^ data[6] ^ data[7];
		buf[5] = data[4] ^ util::fast_mult(2, data[5]) ^ util::fast_mult(3, data[6]) ^ data[7];
		buf[6] = data[4] ^ data[5] ^ util::fast_mult(2, data[6]) ^ util::fast_mult(3, data[7]);
		buf[7] = util::fast_mult(3, data[4]) ^ data[5] ^ data[6] ^ util::fast_mult(2, data[7]);

		//// C3
		buf[8] = util::fast_mult(2, data[8]) ^ util::fast_mult(3, data[9]) ^ data[10] ^ data[11];
		buf[9] = data[8] ^ util::fast_mult(2, data[9]) ^ util::fast_mult(3, data[10]) ^ data[11];
		buf[10] = data[8] ^ data[9] ^ util::fast_mult(2, data[10]) ^ util::fast_mult(3, data[11]);
		buf[11] = util::fast_mult(3, data[8]) ^ data[9] ^ data[10] ^ util::fast_mult(2, data[11]);

		//// C4
		buf[12] = util::fast_mult(2, data[12]) ^ util::fast_mult(3, data[13]) ^ data[14] ^ data[15];
		buf[13] = data[12] ^ util::fast_mult(2, data[13]) ^ util::fast_mult(3, data[14]) ^ data[15];
		buf[14] = data[12] ^ data[13] ^ util::fast_mult(2, data[14]) ^ util::fast_mult(3, data[15]);
		buf[15] = util::fast_mult(3, data[12]) ^ data[13] ^ data[14] ^ util::fast_mult(2, data[15]);

		std::copy(buf.begin(), buf.end(), data.begin());
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::inv_sub_bytes(byte_view<NB * 4> data) noexcept
	{
		for (size_t i = 0; i < NB * 4; i++) {
			data[i] = sub_tables.inv_sbox[data[i]];
		}
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::inv_shift_rows(byte_view<NB * 4> data) noexcept
	{
		// Todo: Improve this function 
		std::array<uint8_t, 16> buf{};

		// No shift
		buf[0] = data[0];
		buf[4] = data[4];
		buf[8] = data[8];
		buf[12] = data[12];

		// cyclically shifts 1
		buf[1] = data[13];
		buf[5] = data[1];
		buf[9] = data[5];
		buf[13] = data[9];

		// cyclically shifts 2
		buf[2] = data[10];
		buf[6] = data[14];
		buf[10] = data[2];
		buf[14] = data[6];

		// cyclically shifts 3
		buf[3] = data[7];
		buf[7] = data[11];
		buf[11] = data[15];
		buf[15] = data[3];

		std::copy(buf.begin(), buf.end(), data.begin());
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::inv_mix_columns(byte_view<NB * 4> data) noexcept
	{
		// Todo: Improve this function
		std::array<uint8_t, 16> buf{};

		// C1
		buf[0] = util::fast_mult(0x0e, data[0]) ^ util::fast_mult(0x0b, data[1]) ^ util::fast_mult(0x0d, data[2]) ^ util::fast_mult(0x09, data[3]);
		buf[1] = util::fast_mult(0x09, data[0]) ^ util::fast_mult(0x0e, data[1]) ^ util::fast_mult(0x0b, data[2]) ^ util::fast_mult(0x0d, data[3]);
		buf[2] = util::fast_mult(0x0d, data[0]) ^ util::fast_mult(0x09, data[1]) ^ util::fast_mult(0x0e, data[2]) ^ util::fast_mult(0x0b, data[3]);
		buf[3] = util::fast_mult(0x0b, data[0]) ^ util::fast_mult(0x0d, data[1]) ^ util::fast_mult(0x09, data[2]) ^ util::fast_mult(0x0e, data[3]);

		//// C2
		buf[4] = util::fast_mult(0x0e, data[4]) ^ util::fast_mult(0x0b, data[5]) ^ util::fast_mult(0x0d, data[6]) ^ util::fast_mult(0x09, data[7]);
		buf[5] = util::fast_mult(0x09, data[4]) ^ util::fast_mult(0x0e, data[5]) ^ util::fast_mult(0x0b, data[6]) ^ util::fast_mult(0x0d, data[7]);
		buf[6] = util::fast_mult(0x0d, data[4]) ^ util::fast_mult(0x09, data[5]) ^ util::fast_mult(0x0e, data[6]) ^ util::fast_mult(0x0b, data[7]);
		buf[7] = util::fast_mult(0x0b, data[4]) ^ util::fast_mult(0x0d, data[5]) ^ util::fast_mult(0x09, data[6]) ^ util::fast_mult(0x0e, data[7]);

		//// C3
		buf[8] = util::fast_mult(0x0e, data[8]) ^ util::fast_mult(0x0b, data[9]) ^ util::fast_mult(0x0d, data[10]) ^ util::fast_mult(0x09, data[11]);
		buf[9] = util::fast_mult(0x09, data[8]) ^ util::fast_mult(0x0e, data[9]) ^ util::fast_mult(0x0b, data[10]) ^ util::fast_mult(0x0d, data[11]);
		buf[10] = util::fast_mult(0x0d, data[8]) ^ util::fast_mult(0x09, data[9]) ^ util::fast_mult(0x0e, data[10]) ^ util::fast_mult(0x0b, data[11]);
		buf[11] = util::fast_mult(0x0b, data[8]) ^ util::fast_mult(0x0d, data[9]) ^ util::fast_mult(0x09, data[10]) ^ util::fast_mult(0x0e, data[11]);

		//// C4
		buf[12] = util::fast_mult(0x0e, data[12]) ^ util::fast_mult(0x0b, data[13]) ^ util::fast_mult(0x0d, data[14]) ^ util::fast_mult(0x09, data[15]);
		buf[13] = util::fast_mult(0x09, data[12]) ^ util::fast_mult(0x0e, data[13]) ^ util::fast_mult(0x0b, data[14]) ^ util::fast_mult(0x0d, data[15]);
		buf[14] = util::fast_mult(0x0d, data[12]) ^ util::fast_mult(0x09, data[13]) ^ util::fast_mult(0x0e, data[14]) ^ util::fast_mult(0x0b, data[15]);
		buf[15] = util::fast_mult(0x0b, data[12]) ^ util::fast_mult(0x0d, data[13]) ^ util::fast_mult(0x09, data[14]) ^ util::fast_mult(0x0e, data[15]);

		std::copy(buf.begin(), buf.end(), data.begin());
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::sub_word(byte_view<4> data) noexcept
	{
		data[0] = sub_tables.sbox[data[0]];
		data[1] = sub_tables.sbox[data[1]];
		data[2] = sub_tables.sbox[data[2]];
		data[3] = sub_tables.sbox[data[3]];
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::rot_word(byte_view<4> data) noexcept
	{
		// Todo: Can we do this in one line? Shift 32 byte integer?
		const auto temp = data[0];
		data[0] = data[1];
		data[1] = data[2];
		data[2] = data[3];
		data[3] = temp;
	}

	template<size_t size, typename mode, typename padding>
	inline constexpr void aes<size, mode, padding>::xor_word(byte_view<4> data, byte_view<4> right) noexcept
	{
		// Todo can we do this in one line? XOR 32 bit value
		data[0] ^= right[0];
		data[1] ^= right[1];
		data[2] ^= right[2];
		data[3] ^= right[3];
	}

	/**
	 * Padding schemes
	 */


	template <typename It>
	inline void pad::ansix923::apply(It it, uint8_t pad_size) noexcept
	{
		// Pad first N-1 bytes with 0
		std::copy(padding.begin(), padding.begin() + (pad_size - 1), it);
		// Last pad byte is N
		auto last_pad = std::next(it, pad_size - 1);
		*last_pad = pad_size;
	}

	template <typename It>
	inline uint8_t pad::ansix923::detect(It it) noexcept
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
	inline void pad::pkcs7::apply(It it, uint8_t pad_size) noexcept
	{
		const auto padding = detail::compute_x_padding(pad_size);

		// Pad first N bytes with pad_size
		std::copy(padding.begin(), padding.begin() + pad_size, it);
	}

	template <typename It>
	inline uint8_t pad::pkcs7::detect(It it) noexcept
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


	/**
	 * Modes of operations
	 */

	template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
	inline void modes::ecb::encrypt(T<size, mode, pad>* instance, byte_array& data) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);
		std::span<unsigned char> data_view(data);

		#pragma omp parallel for
		for (int i = 0; i < data_view.size() / 16; i++) {
			instance->do_encrypt(data_view.subspan(i * 16).first<16>());
		}
			
	}

	template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
	inline void modes::ecb::decrypt(T<size, mode, pad>* instance, byte_array& data) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);
		std::span<unsigned char> data_view(data);
		
		#pragma omp parallel for
		for (int i = 0; i < data_view.size() / 16; i++) {
			instance->do_decrypt(data_view.subspan(i * 16).first<16>());
		}
	}

	

	template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
	inline void modes::cbc::encrypt(T<size, mode, pad>* instance, byte_array& data) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);
		auto iv = krypto::util::create_iv<16>();

		std::span<unsigned char> data_view(data);
		std::span<unsigned char, 16> iv_view(iv);

		for (size_t i = 0; i < data_view.size() / 16; i++) {
			auto block = data_view.subspan(i * 16).first<16>();
			krypto::util::xor_block(block, iv_view);
			instance->do_encrypt(block);
			iv_view = block;
		}

		data.resize(data.size() + iv.size());
		std::copy(iv.begin(), iv.end(), data.begin() + data.size() - iv.size());

	}

	template<template<size_t, typename, typename> typename T, size_t size, typename mode, typename pad>
	inline void modes::cbc::decrypt(T<size, mode, pad>* instance, byte_array& data) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);

		// Last bytes are IV
		std::span<unsigned char> data_view(data);
		std::array<unsigned char, 16> iv;
		std::array<unsigned char, 16> prev_iv;

		std::copy(data.begin() + (data_view.size() - 16), data.end(), prev_iv.begin());
		
		for (size_t i = 0; i < (data_view.size() / 16) - 1; i++) {
			
			// Current cipher text
			auto block = data_view.subspan(i * 16).first<16>();

			// Save iv from current cipher
			std::copy(block.begin(), block.end(), iv.begin());
			
			instance->do_decrypt(block);
			
			krypto::util::xor_block(block, prev_iv);
			std::copy(iv.begin(), iv.end(), prev_iv.begin());
		
		}
			
		data.resize(data.size() - 16);
		
	}


}

