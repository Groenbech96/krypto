#include "benchmark/benchmark.h"
#include "krypto/util.h"
#include "krypto/internal/math.h"
#include "krypto/aes.h"

/**
 * Multiplication lookup
 */

static void BM_MULT(benchmark::State& state) {
	
	uint8_t x = 0x123;
	uint8_t y = 0x32;

	for (auto _ : state)
		benchmark::DoNotOptimize(krypto::math::mult256(x, y));

}
BENCHMARK(BM_MULT);

static void BM_FASTMULT(benchmark::State& state) {
	uint8_t x = 0x123;
	uint8_t y = 0x32;

	for (auto _ : state)
		benchmark::DoNotOptimize(krypto::math::fast_mult256(x, y));

}
BENCHMARK(BM_FASTMULT);

static void BM_SECURERANDOM(benchmark::State& state) {
	uint64_t x = 0x123;

	for (auto _ : state)
		benchmark::DoNotOptimize(x = krypto::get_srandom_u64());

}
BENCHMARK(BM_SECURERANDOM);

static void BM_COMPUTEIV(benchmark::State& state) {
	std::array<unsigned char, 16> data;

	for (auto _ : state)
		benchmark::DoNotOptimize(data = krypto::get_srandom_bytes<16>());

}
BENCHMARK(BM_COMPUTEIV);

static void BM_SHIFTROWS(benchmark::State& state) {
	std::array<unsigned char, 16> data;
	data.fill(1);

	for (auto _ : state)
		krypto::internal::aes::shift_rows(data);

}
BENCHMARK(BM_SHIFTROWS);

static void BM_SHIFTROWSINV(benchmark::State& state) {
	std::array<unsigned char, 16> data;
	data.fill(1);

	for (auto _ : state)
		krypto::internal::aes::inv_shift_rows(data);

}
BENCHMARK(BM_SHIFTROWSINV);


static void BM_MIXCOLUMN(benchmark::State& state) {
	std::array<unsigned char, 16> data;
	data.fill(1);

	for (auto _ : state)
		krypto::internal::aes::mix_columns(data);

}
BENCHMARK(BM_MIXCOLUMN);


static void BM_MIXCOLUMN_SLOW(benchmark::State& state) {
	std::array<unsigned char, 16> data;
	data.fill(1);

	for (auto _ : state)
		krypto::internal::aes::mix_columns_slow(data);

}
BENCHMARK(BM_MIXCOLUMN_SLOW);


static void BM_MIXCOLUMNINV(benchmark::State& state) {
	std::array<unsigned char, 16> data;
	data.fill(1);

	for (auto _ : state)
		krypto::internal::aes::inv_mix_columns(data);

}
BENCHMARK(BM_MIXCOLUMNINV);


static void BM_MIXCOLUMNINV_SLOW(benchmark::State& state) {
	std::array<unsigned char, 16> data;
	data.fill(1);

	for (auto _ : state)
		krypto::internal::aes::inv_mix_columns_slow(data);

}
BENCHMARK(BM_MIXCOLUMNINV_SLOW);

BENCHMARK_MAIN();