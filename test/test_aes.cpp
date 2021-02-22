#include "gtest/gtest.h"
#include "krypto/aes.h"

#include <array>

class AesTest : public ::testing::Test {

protected:

	void SetUp() override {
	}

	std::array<unsigned char, 16> key_128 = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	std::array<unsigned char, 24> key_194 = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
												0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	std::array<unsigned char, 32> key_256 = {	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
												0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };



	/**
	 * ECB Mode Static data
	 */

	std::array<unsigned char, 16> plain_text		= { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };	
	std::array<unsigned char, 16> cipher_text_128	= { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
	std::array<unsigned char, 16> cipher_text_194	= { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
	std::array<unsigned char, 16> cipher_text_256	= { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };

};

/**
 * Padding Test
 */

TEST_F(AesTest, Padding_ANSIX923) {

	int size = 10;
	std::array<unsigned char, 16> data{};
	std::fill_n(data.begin(), 6, 1);

	auto it = std::next(data.begin(), 6);
	krypto::pad::ansix923::apply(it, size);

	ASSERT_EQ(data[data.size() - 1], size);
	for (size_t i = data.size() - 2; i >= size; i--) {
		ASSERT_EQ(data[i], 0);
	}

	ASSERT_EQ(krypto::pad::ansix923::calculate(data.end() - 1), 10);

}

TEST_F(AesTest, Padding_PKCS7) {

	int size = 10;
	std::array<unsigned char, 16> data{};
	std::fill_n(data.begin(), 6, 1);

	auto it = std::next(data.begin(), 6);
	krypto::pad::pkcs7::apply(it, size);

	ASSERT_EQ(data[data.size() - 1], size);
	for (size_t i = data.size() - 2; i >= size; i--) {
		ASSERT_EQ(data[i], size);
	}

	ASSERT_EQ(krypto::pad::pkcs7::calculate(data.end() - 1), 10);

}


TEST_F(AesTest, EncryptDecrypt_ECB_128_16BIT_NOPADDING) {

	krypto::aes<128, krypto::modes::ecb, krypto::pad::ansix923> aes(key_128);
	auto out = aes.encrypt(plain_text);
	
	krypto::aes<128, krypto::modes::ecb, krypto::pad::ansix923> aes2(key_128);
	auto out2 = aes2.decrypt(out);

	ASSERT_EQ(out2.size(), plain_text.size());
	for (int i = 0; i < out2.size(); i++) {
		ASSERT_EQ(out2[i], plain_text[i]);
	}

}

TEST_F(AesTest, EncryptDecrypt_ECB_194_16BIT_NOPADDING) {

	krypto::aes<194, krypto::modes::ecb, krypto::pad::ansix923> aes(key_194);
	auto out = aes.encrypt(plain_text);

	krypto::aes<194, krypto::modes::ecb, krypto::pad::ansix923> aes2(key_194);
	auto out2 = aes2.decrypt(out);

	ASSERT_EQ(out2.size(), plain_text.size());
	for (int i = 0; i < out2.size(); i++) {
		ASSERT_EQ(out2[i], plain_text[i]);
	}

}

TEST_F(AesTest, EncryptDecrypt_ECB_256_16BIT_NOPADDING) {

	krypto::aes<256, krypto::modes::ecb, krypto::pad::ansix923> aes(key_256);
	auto out = aes.encrypt(plain_text);

	krypto::aes<256, krypto::modes::ecb, krypto::pad::ansix923> aes2(key_256);
	auto out2 = aes2.decrypt(out);

	ASSERT_EQ(out2.size(), plain_text.size());
	for (int i = 0; i < out2.size(); i++) {
		ASSERT_EQ(out2[i], plain_text[i]);
	}

}

TEST_F(AesTest, EncryptDecrypt_ECB_ALL_1_to_256_BIT) {

	krypto::aes<128, krypto::modes::ecb, krypto::pad::ansix923> aes_128(key_128);
	krypto::aes<194, krypto::modes::ecb, krypto::pad::ansix923> aes_194(key_194);
	krypto::aes<256, krypto::modes::ecb, krypto::pad::ansix923> aes_256(key_256);
	

	for (int i = 1; i <= 1000; i++) {

		std::vector<unsigned char> data;
		for (int j = 0; j < i; j++) {
			data.push_back(rand() % 256);
		}

		{
			auto out = aes_128.encrypt(data);
			auto res = aes_128.decrypt(out);

			ASSERT_EQ(res.size(), data.size());
			for (int k = 0; k < res.size(); k++) {
				ASSERT_EQ(res[k], data[k]);
			}
		}

		{
			auto out = aes_194.encrypt(data);
			auto res = aes_194.decrypt(out);

			ASSERT_EQ(res.size(), data.size());
			for (int k = 0; k < res.size(); k++) {
				ASSERT_EQ(res[k], data[k]);
			}
		}

		{
			auto out = aes_256.encrypt(data);
			auto res = aes_256.decrypt(out);

			ASSERT_EQ(res.size(), data.size());
			for (int k = 0; k < res.size(); k++) {
				ASSERT_EQ(res[k], data[k]);
			}
		}

	}

}











