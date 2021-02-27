#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <span>

#include "util.h"
#include "internal/math.h"
#include "internal/padding.h"

namespace krypto {

	using byte_array = std::vector<unsigned char>;

	template <size_t extend = std::dynamic_extent>
	using byte_view = std::span<unsigned char, extend>;

	template <size_t extend = std::dynamic_extent>
	using const_byte_view = std::span<const unsigned char, extend>;

	namespace internal {

		// Keep static tables for aes
		struct aes_base {
			constexpr static math::aes_sub_tables SUB_TABLES = math::compute_aes_sub_tables();
			constexpr static math::aes_mult_tables MULT_TABLES = math::compute_aes_mult_tables();
			constexpr static math::aes_rcon RCON = math::compute_aes_rcon();
		};

		// Implementation based on https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
		namespace aes {

			template <typename It>
			constexpr void add_round_key(byte_view<16> data, It key) noexcept;

			constexpr void shift_rows(byte_view<16> data) noexcept;
			constexpr void shift_rows_imp(byte_view<16> data) noexcept;
			constexpr void inv_shift_rows(byte_view<16> data) noexcept;
			constexpr void inv_shift_rows_imp(byte_view<16> data) noexcept;

			constexpr void mix_columns(byte_view<16> data) noexcept;
			constexpr void mix_columns_imp(byte_view<16> data) noexcept;
			constexpr void mix_columns_imp2(byte_view<16> data) noexcept;
			constexpr void inv_mix_columns(byte_view<16> data) noexcept;
			constexpr void inv_mix_columns_imp(byte_view<16> data) noexcept;

			template <size_t Size>
			constexpr void encrypt(byte_view<16> data, const_byte_view<Size> key) noexcept;

			template <size_t Size>
			constexpr void decrypt(byte_view<16> data, const_byte_view<Size> key) noexcept;

		}


	}

	namespace modes {

		// Electronic code book 
		class ecb {
		public:

			template <size_t KeySize>
			static void encrypt(byte_array& data, const_byte_view<KeySize> key) noexcept;

			template <size_t KeySize>
			static void decrypt(byte_array& data, const_byte_view<KeySize> key) noexcept;

		};

		class cbc {
		public:

			template <size_t KeySize>
			static void encrypt(byte_array& data, const_byte_view<KeySize> key) noexcept;

			template <size_t KeySize>
			static void decrypt(byte_array& data, const_byte_view<KeySize> key) noexcept;

		};

	}

	template <size_t Size, typename Mode, typename Pad>
	class aes {
	private:
		static_assert(Size == 128 || Size == 194 || Size == 256, "Invalid key size");
		constexpr static uint8_t NB = 4;
		constexpr static uint8_t NK = Size / 32;
		constexpr static uint8_t NR = (NK)+6;
		constexpr static size_t KEY_SIZE = NB * (NR + 1) * 4;

	public:
		/**
		 * Construct an AES encryption object
		 * Set key used for encryption
		 */
		constexpr aes(const_byte_view<Size / 8> key) noexcept;

		/**
		 * Encrypt data passed to function
		 */
		byte_array encrypt(const_byte_view<> data) noexcept;
		/**
		 * Decrypt data passed to function
		 */
		byte_array decrypt(const_byte_view<> data) noexcept;


	private:

		std::array<unsigned char, KEY_SIZE> expanded_key{};

	};

	/// 
	// Implementation
	///


	template<size_t Size, typename Mode, typename Pad>
	constexpr aes<Size, Mode, Pad>::aes(const_byte_view<Size / 8> key) noexcept
	{
		/**
		* Expand the input key
		*/

		// Copy key into first bytes of expanded key
		std::copy(key.begin(), key.end(), expanded_key.begin());

		// 1 word = 4 chars
		std::array<unsigned char, 4> temp{};
		std::array<unsigned char, 4> rcon_temp = { 0,0,0,0 };

		size_t i = NK;
		while (i < NB * (NR + 1)) {

			auto key_it = expanded_key.begin() + (i * 4);
			std::span<unsigned char, 4> window(key_it - (NK * 4), 4);

			std::copy_n(key_it - 4, 4, temp.begin());

			if (i % NK == 0) {
				rcon_temp[0] = internal::aes_base::RCON[(i / NK) - 1];

				math::rot_word(temp);
				math::sub_bytes<4>(temp, internal::aes_base::SUB_TABLES.sbox);
				math::xor_word(temp, rcon_temp);
			}
			else if (NK > 6 && i % NK == 4) {
				math::sub_bytes<4>(temp, internal::aes_base::SUB_TABLES.sbox); 
			}

			math::xor_word(temp, window);
			std::copy_n(temp.begin(), 4, key_it);

			i++;
		}

	}

	template<size_t Size, typename Mode, typename Pad>
	inline byte_array aes<Size, Mode, Pad>::encrypt(const_byte_view<> data) noexcept
	{
		byte_array cipher_text;

		// Add minimum 16 bytes of Pad.
		const uint8_t pad_size = (data.size() % 16 == 0 ? 0 : 16 - (data.size() % 16)) + 16;

		cipher_text.resize(data.size() + pad_size);
		std::copy(data.begin(), data.end(), cipher_text.begin());

		// Add Pad to end of plain_text
		if (pad_size > 0)
			Pad::apply(cipher_text.begin() + data.size(), pad_size);

		Mode::encrypt<KEY_SIZE>(cipher_text, expanded_key);

		return cipher_text;
	}

	template<size_t Size, typename Mode, typename Pad>
	inline byte_array aes<Size, Mode, Pad>::decrypt(const_byte_view<> data) noexcept
	{
		byte_array plain_text;
		plain_text.resize(data.size());

		// Copy data to plain array
		std::copy(data.begin(), data.end(), plain_text.begin());
		Mode::decrypt<KEY_SIZE>(plain_text, expanded_key);

		const auto s = Pad::detect(plain_text.end() - 1);
		plain_text.resize(plain_text.size() - s);

		return plain_text;
	}

	/**
	 * Modes of operations
	 */


	template <size_t KeySize>
	inline void modes::ecb::encrypt(byte_array& data, const_byte_view<KeySize> key) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);
		std::span<unsigned char> data_view(data);

		#pragma omp parallel for
		for (int64_t i = 0; i < data_view.size() / 16; i++) {
			internal::aes::encrypt(data_view.subspan(i * 16).first<16>(), key);
		}

	}

	template <size_t KeySize>
	inline void modes::ecb::decrypt(byte_array& data, const_byte_view<KeySize> key) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);
		std::span<unsigned char> data_view(data);

		#pragma omp parallel for
		for (int64_t i = 0; i < data_view.size() / 16; i++) {
			internal::aes::decrypt(data_view.subspan(i * 16).first<16>(), key);
		}
	}

	template <size_t KeySize>
	inline void modes::cbc::encrypt(byte_array& data, const_byte_view<KeySize> key) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);
		auto iv = krypto::get_srandom_bytes<16>();

		std::span<unsigned char> data_view(data);
		std::span<unsigned char, 16> iv_view(iv);

		for (size_t i = 0; i < data_view.size() / 16; i++) {
			auto block = data_view.subspan(i * 16).first<16>();
			krypto::math::xor_block(block, iv_view);
			
			internal::aes::encrypt(block, key);
			
			iv_view = block;
		}

		data.resize(data.size() + iv.size());
		std::copy(iv.begin(), iv.end(), data.begin() + data.size() - iv.size());

	}

	template <size_t KeySize>
	inline void modes::cbc::decrypt(byte_array& data, const_byte_view<KeySize> key) noexcept
	{
		assert(data.size() % 16 == 0 && data.size() >= 32);

		std::span<unsigned char> data_view(data);
		std::array<unsigned char, 16> iv;
		std::array<unsigned char, 16> prev_iv;

		// Last bytes are IV
		std::copy(data.begin() + (data_view.size() - 16), data.end(), prev_iv.begin());

		for (size_t i = 0; i < (data_view.size() / 16) - 1; i++) {

			// Current cipher text
			auto block = data_view.subspan(i * 16).first<16>();

			// Save iv from current cipher
			std::copy(block.begin(), block.end(), iv.begin());

			internal::aes::decrypt(block, key);

			krypto::math::xor_block(block, prev_iv);
			std::copy(iv.begin(), iv.end(), prev_iv.begin());

		}

		// remove iv from data as it is no longer needed
		data.resize(data.size() - 16);

	}

	namespace internal::aes {

		template <size_t Size>
		constexpr void encrypt(byte_view<16> data, const_byte_view<Size> key) noexcept
		{
			constexpr size_t NR = (Size / 16) - 1;
			
			add_round_key(data, key.begin());

			for (int i = 1; i < NR; i++) {
				math::sub_bytes(data, aes_base::SUB_TABLES.sbox);
				shift_rows_imp(data);
				mix_columns_imp(data);
				add_round_key(data, key.begin() + i * 16);
			}

			math::sub_bytes(data, aes_base::SUB_TABLES.sbox);
			shift_rows_imp(data);
			add_round_key(data, key.begin() + NR * 16);
		}

		template <size_t Size>
		constexpr void decrypt(byte_view<16> data, const_byte_view<Size> key) noexcept
		{
			constexpr size_t NR = (Size / 16) - 1;

			add_round_key(data, key.begin() + NR * 16);

			for (int i = NR - 1; i > 0; i--) {
				inv_shift_rows_imp(data);
				math::sub_bytes(data, aes_base::SUB_TABLES.inv_sbox);
				add_round_key(data, key.begin() + i * 16);
				inv_mix_columns(data);
			}

			inv_shift_rows_imp(data);
			math::sub_bytes(data, aes_base::SUB_TABLES.inv_sbox);
			add_round_key(data, key.begin());

		}

		constexpr void inv_mix_columns(byte_view<16> data) noexcept
		{
			std::array<uint8_t, 16> buf{};

			// C1
			buf[0] = math::fast_mult256(0x0e, data[0]) ^ math::fast_mult256(0x0b, data[1]) ^ math::fast_mult256(0x0d, data[2]) ^ math::fast_mult256(0x09, data[3]);
			buf[1] = math::fast_mult256(0x09, data[0]) ^ math::fast_mult256(0x0e, data[1]) ^ math::fast_mult256(0x0b, data[2]) ^ math::fast_mult256(0x0d, data[3]);
			buf[2] = math::fast_mult256(0x0d, data[0]) ^ math::fast_mult256(0x09, data[1]) ^ math::fast_mult256(0x0e, data[2]) ^ math::fast_mult256(0x0b, data[3]);
			buf[3] = math::fast_mult256(0x0b, data[0]) ^ math::fast_mult256(0x0d, data[1]) ^ math::fast_mult256(0x09, data[2]) ^ math::fast_mult256(0x0e, data[3]);

			//// C2
			buf[4] = math::fast_mult256(0x0e, data[4]) ^ math::fast_mult256(0x0b, data[5]) ^ math::fast_mult256(0x0d, data[6]) ^ math::fast_mult256(0x09, data[7]);
			buf[5] = math::fast_mult256(0x09, data[4]) ^ math::fast_mult256(0x0e, data[5]) ^ math::fast_mult256(0x0b, data[6]) ^ math::fast_mult256(0x0d, data[7]);
			buf[6] = math::fast_mult256(0x0d, data[4]) ^ math::fast_mult256(0x09, data[5]) ^ math::fast_mult256(0x0e, data[6]) ^ math::fast_mult256(0x0b, data[7]);
			buf[7] = math::fast_mult256(0x0b, data[4]) ^ math::fast_mult256(0x0d, data[5]) ^ math::fast_mult256(0x09, data[6]) ^ math::fast_mult256(0x0e, data[7]);

			//// C3
			buf[8] = math::fast_mult256(0x0e, data[8]) ^ math::fast_mult256(0x0b, data[9]) ^ math::fast_mult256(0x0d, data[10]) ^ math::fast_mult256(0x09, data[11]);
			buf[9] = math::fast_mult256(0x09, data[8]) ^ math::fast_mult256(0x0e, data[9]) ^ math::fast_mult256(0x0b, data[10]) ^ math::fast_mult256(0x0d, data[11]);
			buf[10] = math::fast_mult256(0x0d, data[8]) ^ math::fast_mult256(0x09, data[9]) ^ math::fast_mult256(0x0e, data[10]) ^ math::fast_mult256(0x0b, data[11]);
			buf[11] = math::fast_mult256(0x0b, data[8]) ^ math::fast_mult256(0x0d, data[9]) ^ math::fast_mult256(0x09, data[10]) ^ math::fast_mult256(0x0e, data[11]);

			//// C4
			buf[12] = math::fast_mult256(0x0e, data[12]) ^ math::fast_mult256(0x0b, data[13]) ^ math::fast_mult256(0x0d, data[14]) ^ math::fast_mult256(0x09, data[15]);
			buf[13] = math::fast_mult256(0x09, data[12]) ^ math::fast_mult256(0x0e, data[13]) ^ math::fast_mult256(0x0b, data[14]) ^ math::fast_mult256(0x0d, data[15]);
			buf[14] = math::fast_mult256(0x0d, data[12]) ^ math::fast_mult256(0x09, data[13]) ^ math::fast_mult256(0x0e, data[14]) ^ math::fast_mult256(0x0b, data[15]);
			buf[15] = math::fast_mult256(0x0b, data[12]) ^ math::fast_mult256(0x0d, data[13]) ^ math::fast_mult256(0x09, data[14]) ^ math::fast_mult256(0x0e, data[15]);

			std::copy(buf.begin(), buf.end(), data.begin());
		}

		constexpr void inv_mix_columns_imp(byte_view<16> data) noexcept
		{

			uint8_t a, b, c, d;
			for (size_t i = 0; i < 16; i = i + 4) {

				a = aes_base::MULT_TABLES.mult_14[data[i]] ^ aes_base::MULT_TABLES.mult_11[data[i + 1]] ^ aes_base::MULT_TABLES.mult_13[data[i + 2]] ^ aes_base::MULT_TABLES.mult_9[data[i + 3]];
				b = aes_base::MULT_TABLES.mult_9[data[i]] ^ aes_base::MULT_TABLES.mult_14[data[i + 1]] ^ aes_base::MULT_TABLES.mult_11[data[i + 2]] ^ aes_base::MULT_TABLES.mult_13[data[i + 3]];
				c = aes_base::MULT_TABLES.mult_13[data[i]] ^ aes_base::MULT_TABLES.mult_9[data[i + 1]] ^ aes_base::MULT_TABLES.mult_14[data[i + 2]] ^ aes_base::MULT_TABLES.mult_11[data[i + 3]];
				d = aes_base::MULT_TABLES.mult_11[data[i]] ^ aes_base::MULT_TABLES.mult_13[data[i + 1]] ^ aes_base::MULT_TABLES.mult_9[data[i + 2]] ^ aes_base::MULT_TABLES.mult_14[data[i + 3]];
				
				data[i] ^= a;
				data[i + 1] ^= b;
				data[i + 2] ^= c;
				data[i + 3] ^= d;
			}
		}

		constexpr void inv_shift_rows(byte_view<16> data) noexcept
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

		constexpr void inv_shift_rows_imp(byte_view<16> data) noexcept
		{
			uint8_t i, j, k, l;

			// cyclically shifts 1
			i = data[13];
			data[13] = data[9];
			data[9] = data[5];
			data[5] = data[1];
			data[1] = i;
			
			// cyclically shifts 2
			j = data[2];
			data[2] = data[10];
			data[10] = j;
			k = data[6];
			data[6] = data[14];
			data[14] = k;

			// cyclically shifts 3
			l = data[3];
			data[3] = data[7];
			data[7] = data[11];
			data[11] = data[15];
			data[15] = l;

		}

		constexpr void mix_columns_imp(byte_view<16> data) noexcept
		{
			for (size_t i = 0; i < 16; i = i + 4) {

				uint8_t a = data[i];
				uint8_t e = data[i] ^ data[i + 1] ^ data[i + 2] ^ data[i + 3];
				data[i] ^= e ^ math::fast_mult256(2, a ^ data[i + 1]);
				data[i+1] ^= e ^ math::fast_mult256(2, data[i+1] ^ data[i + 2]);
				data[i+2] ^= e ^ math::fast_mult256(2, data[i+2] ^ data[i + 3]);
				data[i+3] ^= e ^ math::fast_mult256(2, data[i + 3] ^ a );
			}
		}

		constexpr void mix_columns_imp2(byte_view<16> data) noexcept
		{
			for (size_t i = 0; i < 16; i = i + 4) {
				uint8_t a = data[i];
				uint8_t e = data[i] ^ data[i + 1] ^ data[i + 2] ^ data[i + 3];
				data[i] ^= e ^ aes_base::MULT_TABLES.mult_2[a ^ data[i + 1]]; //math::fast_mult256(2, a ^ data[i + 1]);
				data[i + 1] ^= e ^ aes_base::MULT_TABLES.mult_2[data[i + 1] ^ data[i + 2]]; // math::fast_mult256(2, data[i + 1] ^ data[i + 2]);
				data[i + 2] ^= e ^ aes_base::MULT_TABLES.mult_2[data[i + 2] ^ data[i + 3]]; // math::fast_mult256(2, data[i + 2] ^ data[i + 3]);
				data[i + 3] ^= e ^ aes_base::MULT_TABLES.mult_2[data[i + 3] ^ a]; // math::fast_mult256(2, data[i + 3] ^ a);
			}
		}


		constexpr void mix_columns(byte_view<16> data) noexcept
		{
			// Todo: Improve this function
			std::array<uint8_t, 16> buf{};

			//// C1
			buf[0] = math::fast_mult256(2, data[0]) ^ math::fast_mult256(3, data[1]) ^ data[2] ^ data[3];
			buf[1] = data[0] ^ math::fast_mult256(2, data[1]) ^ math::fast_mult256(3, data[2]) ^ data[3];
			buf[2] = data[0] ^ data[1] ^ math::fast_mult256(2, data[2]) ^ math::fast_mult256(3, data[3]);
			buf[3] = math::fast_mult256(3, data[0]) ^ data[1] ^ data[2] ^ math::fast_mult256(2, data[3]);

			//// C2
			buf[4] = math::fast_mult256(2, data[4]) ^ math::fast_mult256(3, data[5]) ^ data[6] ^ data[7];
			buf[5] = data[4] ^ math::fast_mult256(2, data[5]) ^ math::fast_mult256(3, data[6]) ^ data[7];
			buf[6] = data[4] ^ data[5] ^ math::fast_mult256(2, data[6]) ^ math::fast_mult256(3, data[7]);
			buf[7] = math::fast_mult256(3, data[4]) ^ data[5] ^ data[6] ^ math::fast_mult256(2, data[7]);

			//// C3
			buf[8] = math::fast_mult256(2, data[8]) ^ math::fast_mult256(3, data[9]) ^ data[10] ^ data[11];
			buf[9] = data[8] ^ math::fast_mult256(2, data[9]) ^ math::fast_mult256(3, data[10]) ^ data[11];
			buf[10] = data[8] ^ data[9] ^ math::fast_mult256(2, data[10]) ^ math::fast_mult256(3, data[11]);
			buf[11] = math::fast_mult256(3, data[8]) ^ data[9] ^ data[10] ^ math::fast_mult256(2, data[11]);

			//// C4
			buf[12] = math::fast_mult256(2, data[12]) ^ math::fast_mult256(3, data[13]) ^ data[14] ^ data[15];
			buf[13] = data[12] ^ math::fast_mult256(2, data[13]) ^ math::fast_mult256(3, data[14]) ^ data[15];
			buf[14] = data[12] ^ data[13] ^ math::fast_mult256(2, data[14]) ^ math::fast_mult256(3, data[15]);
			buf[15] = math::fast_mult256(3, data[12]) ^ data[13] ^ data[14] ^ math::fast_mult256(2, data[15]);

			std::copy(buf.begin(), buf.end(), data.begin());
		}

		constexpr void shift_rows(byte_view<16> data) noexcept
		{
			// Todo: Improve this function 
			std::array<uint8_t, 16> buf{};

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

		constexpr void shift_rows_imp(byte_view<16> data) noexcept
		{
			
			uint8_t i, j, k, l;

			// cyclically shifts 1
			i = data[1];
			data[1] = data[5];
			data[5] = data[9];
			data[9] = data[13];
			data[13] = i;

			// cyclically shifts 2
			j = data[2];
			data[2] = data[10];
			data[10] = j;
			k = data[6];
			data[6] = data[14];
			data[14] = k;
			
			// cyclically shifts 3
			l = data[15];
			data[15] = data[11];
			data[11] = data[7];
			data[7] = data[3];
			data[3] = l;

		}


		template <typename It>
		constexpr void add_round_key(byte_view<16> data, It it) noexcept
		{
			// Todo: Check with 4 element loop unrolling
			for (size_t i = 0; i < 16; i++) {
				data[i] ^= it[i];
			}
		}



	}



}

