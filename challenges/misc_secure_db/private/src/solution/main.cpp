#include <fstream>
#include <iostream>
#include <thread>
#include <sstream>

#include <tfhe.h>
#include <tfhe_io.h>

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <db.hpp>


constexpr std::size_t LIMIT{4};

void panic(const std::string& msg)
{
	std::cerr << msg << std::endl;
	exit(1);
}

std::pair<char *, size_t> base64(const unsigned char *input, int length) {
	const auto pl = 4*((length+2)/3);
	auto output = reinterpret_cast<char *>(calloc(pl+1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
	const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
	if (pl != ol) { std::cerr << "Whoops, encode predicted " << pl << " but we got " << ol << "\n"; }
	return {output, pl};
}

std::pair<unsigned char *, size_t> decode64(const char *input, int length) {
	const auto pl = 3*length/4;
	auto output = reinterpret_cast<unsigned char *>(calloc(pl+1, 1));
	const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
	if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
	return {output, ol};
}

TFheGateBootstrappingCloudKeySet* load_key_set()
{
	std::ifstream cloud_key_file("cloud.key");
	if(!cloud_key_file)
	{
		panic("Cannot open private.key for reading!!!");
	}

	return new_tfheGateBootstrappingCloudKeySet_fromStream(cloud_key_file);
}

std::vector<db::EncryptedRow> load_db(const TFheGateBootstrappingParameterSet* params)
{
	std::ifstream db_file("0_db");
	if(!db_file)
	{
		panic("Cannot open db for reading!!!");
	}

	return db::import_encrypted_db(db_file, params);
}

void mux_value(LweSample* target, const LweSample* source, size_t size, const LweSample* predicate, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	for(size_t i = 0; i < size; ++i)
	{
		bootsMUX(&target[i], predicate, &source[i], &target[i], cloud_key_set);
	}
}

void mux_row(db::EncryptedRow& target, const db::EncryptedRow& source, const LweSample* predicate, const TFheGateBootstrappingCloudKeySet* cloud_key_set, std::size_t column_1, std::size_t column_2)
{
	switch(column_1)
	{
		case 0:
			mux_value(target.pulse_rate, source.pulse_rate, sizeof(db::PlaintextRow::pulse_rate) * 8, predicate, cloud_key_set);
			break;
		case 1:
			mux_value(target.systolic_pressure, source.systolic_pressure, sizeof(db::PlaintextRow::systolic_pressure) * 8, predicate, cloud_key_set);
			break;
		case 2:
			mux_value(target.diastolic_pressure, source.diastolic_pressure, sizeof(db::PlaintextRow::diastolic_pressure) * 8, predicate, cloud_key_set);
			break;
		case 3:
			mux_value(target.oxygen_saturation, source.oxygen_saturation, sizeof(db::PlaintextRow::oxygen_saturation) * 8, predicate, cloud_key_set);
			break;
	}

	switch(column_2)
	{
		case 0:
			mux_value(target.pulse_rate, source.pulse_rate, sizeof(db::PlaintextRow::pulse_rate) * 8, predicate, cloud_key_set);
			break;
		case 1:
			mux_value(target.systolic_pressure, source.systolic_pressure, sizeof(db::PlaintextRow::systolic_pressure) * 8, predicate, cloud_key_set);
			break;
		case 2:
			mux_value(target.diastolic_pressure, source.diastolic_pressure, sizeof(db::PlaintextRow::diastolic_pressure) * 8, predicate, cloud_key_set);
			break;
		case 3:
			mux_value(target.oxygen_saturation, source.oxygen_saturation, sizeof(db::PlaintextRow::oxygen_saturation) * 8, predicate, cloud_key_set);
			break;
	}
}

LweSample* eq(const LweSample* lhs, const LweSample* rhs, size_t size, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);
	LweSample* result = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);

	bootsCONSTANT(result, 1, cloud_key_set);
	for(size_t i = 0; i < size; ++i)
	{
		bootsXNOR(temp, &lhs[i], &rhs[i], cloud_key_set);
		bootsAND(result, result, temp, cloud_key_set);
	}

	delete_gate_bootstrapping_ciphertext_array(1, temp);

	return result;
}

std::vector<db::EncryptedRow>  scheduler(const std::vector<db::EncryptedRow>& db, const std::array<LweSample *, LIMIT>& indices, size_t threads, const TFheGateBootstrappingCloudKeySet* cloud_key_set,
										std::size_t column_1, std::size_t column_2)
{
	std::vector<db::EncryptedRow> temp_db;
	threads = std::min(threads, db.size());

	LweSample* used = new_gate_bootstrapping_ciphertext_array(threads * LIMIT, cloud_key_set->params);
	for(std::size_t j = 0; j < threads * LIMIT; ++j)
	{
		bootsCONSTANT(&used[j], 0, cloud_key_set);
	}

	std::generate_n(std::back_inserter(temp_db), threads * LIMIT, [cloud_key_set](){
		return db::EncryptedRow(cloud_key_set->params);
	});

	std::vector<std::thread> workers;

	const size_t partition = std::floor(db.size()/static_cast<float>(threads));
	for(size_t i = 0; i < std::min(threads, db.size()); ++i)
	{
		workers.emplace_back([&db, &used, &temp_db, i, partition, &indices, cloud_key_set, column_1, column_2](){
			LweSample* should_insert = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);
			LweSample* already_inserted = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);
			LweSample* predicate = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);

			for(size_t j = i * partition; j < std::min(db.size(), (i+1) * partition); ++j)
			{
				bootsCONSTANT(predicate, 0, cloud_key_set);
				for(std::size_t k = 0; k < LIMIT; ++k)
				{
					auto temp = eq(indices[k], db[j].id, sizeof(db::PlaintextRow::id) * 8, cloud_key_set);

					bootsOR(predicate, temp, predicate, cloud_key_set);
					delete_gate_bootstrapping_ciphertext_array(1, temp);
				}

				bootsCONSTANT(already_inserted, 0, cloud_key_set);

				for(std::size_t k = 0; k < LIMIT; ++k)
				{
					bootsCOPY(should_insert, predicate, cloud_key_set);
					bootsANDYN(should_insert, should_insert, &used[i * LIMIT + k], cloud_key_set);
					bootsANDYN(should_insert, should_insert, already_inserted, cloud_key_set);

					mux_row(temp_db[i*LIMIT + k], db[j], should_insert, cloud_key_set, column_1, column_2);
					bootsOR(&used[i * LIMIT + k], &used[i * LIMIT + k], should_insert, cloud_key_set);
					bootsOR(already_inserted, already_inserted, should_insert, cloud_key_set);
				}
			}

			delete_gate_bootstrapping_ciphertext_array(1, predicate);
			delete_gate_bootstrapping_ciphertext_array(1, should_insert);
			delete_gate_bootstrapping_ciphertext_array(1, already_inserted);
		});
	}

	for(auto& worker: workers)
	{
		worker.join();
	}

	LweSample* results_used = new_gate_bootstrapping_ciphertext_array(threads * LIMIT, cloud_key_set->params);
	for(std::size_t j = 0; j < LIMIT; ++j)
	{
		bootsCONSTANT(&results_used[j], 0, cloud_key_set);
	}

	std::vector<db::EncryptedRow> results;
	std::generate_n(std::back_inserter(results), LIMIT, [cloud_key_set](){
		return db::EncryptedRow(cloud_key_set->params);
	});

	LweSample* should_insert = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);
	LweSample* already_inserted = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);

	for(std::size_t i = 0; i < threads * LIMIT; ++i)
	{
		bootsCONSTANT(already_inserted, 0, cloud_key_set);
		for(std::size_t j = 0; j < LIMIT; ++j)
		{
			bootsCOPY(should_insert, &used[i], cloud_key_set);
			bootsANDYN(should_insert, should_insert, &results_used[j], cloud_key_set);
			bootsANDYN(should_insert, should_insert, already_inserted, cloud_key_set);

			mux_row(results[j], temp_db[i], should_insert, cloud_key_set, column_1, column_2);
			bootsOR(&results_used[j], &results_used[j], should_insert, cloud_key_set);
			bootsOR(already_inserted, already_inserted, should_insert, cloud_key_set);
		}
	}

	delete_gate_bootstrapping_ciphertext_array(1, should_insert);

	delete_gate_bootstrapping_ciphertext_array(LIMIT, results_used);
	delete_gate_bootstrapping_ciphertext_array(threads * LIMIT, used);

	return results;
}

void export_to_stream(std::ostream& out, const db::EncryptedRow& row, size_t column, const LweParams* params)
{
	size_t column_size = 0;
	LweSample* to_extract;

	switch(column)
	{
		case 0:
			column_size = sizeof(db::PlaintextRow::pulse_rate) * 8;
			to_extract = row.pulse_rate;
			break;
		case 1:
			column_size = sizeof(db::PlaintextRow::systolic_pressure) * 8;
			to_extract = row.systolic_pressure;
			break;
		case 2:
			column_size = sizeof(db::PlaintextRow::diastolic_pressure) * 8;
			to_extract = row.diastolic_pressure;
			break;
		case 3:
			column_size = sizeof(db::PlaintextRow::oxygen_saturation) * 8;
			to_extract = row.oxygen_saturation;
			break;
	}
	db::export_encrypted_value(out, to_extract, column_size, params);
}

int main(int argc, char** argv)
{
	const auto cloud_key_set = load_key_set();
	const auto encrypted_db = load_db(cloud_key_set->params);

	std::string key_str;
	std::cin >> key_str;
	auto [key, key_size] = decode64(key_str.c_str(), key_str.size());
	std::stringstream stream;
	stream.write(reinterpret_cast<char*>(key), key_size);
	free(key);

	std::array<LweSample *, LIMIT> indices{};
	for(std::size_t i = 0; i < LIMIT; ++i)
	{
		indices[i] = new_gate_bootstrapping_ciphertext_array(sizeof(db::PlaintextRow::id) * 8, cloud_key_set->params);
		db::import_encrypted_value(indices[i], stream, sizeof(db::PlaintextRow::id) * 8, cloud_key_set->params->in_out_params);
	}

	size_t column_1;
	size_t column_2;

	std::cin >> column_1 >> column_2;

	const auto results = scheduler(encrypted_db, indices, std::thread::hardware_concurrency(), cloud_key_set, column_1, column_2);

	for(std::size_t i = 0; i < LIMIT; ++i)
	{
		delete_gate_bootstrapping_ciphertext_array(sizeof(db::PlaintextRow::id) * 8, indices[i]);
	}

	std::stringstream result_stream;

	for(std::size_t i = 0; i < LIMIT; ++i)
	{
		export_to_stream(result_stream, results[i], column_1, cloud_key_set->params->in_out_params);
		export_to_stream(result_stream, results[i], column_2, cloud_key_set->params->in_out_params);
	}
	std::string buffer(std::istreambuf_iterator<char>(result_stream), {});

	auto [result_base64, result_base64_size] = base64(reinterpret_cast<const unsigned char *>(buffer.c_str()), buffer.size());

	std::cout << result_base64;

	free(result_base64);

	return 0;
}