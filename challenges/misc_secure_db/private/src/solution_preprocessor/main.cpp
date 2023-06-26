#include <fstream>
#include <iostream>
#include <thread>
#include <sstream>
#include <chrono>

#include <tfhe.h>
#include <tfhe_io.h>

#include <openssl/evp.h>

#include <algorithm>
#include <db.hpp>

enum class Field : size_t
{
	PULSE_RATE,
	SYSTOLIC_PRESSURE,
	DIASTOLIC_PRESSURE,
	OXYGEN_SATURATION
};


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
	std::ifstream db_file("db");
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
		bootsMUX(&target[i], predicate, &target[i], &source[i], cloud_key_set);
	}
}

void mux_row(db::EncryptedRow& target, const db::EncryptedRow& source, const LweSample* predicate, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	mux_value(target.id, source.id, sizeof(db::PlaintextRow::id) * 8, predicate, cloud_key_set);
	mux_value(target.pulse_rate, source.pulse_rate, sizeof(db::PlaintextRow::pulse_rate) * 8, predicate, cloud_key_set);
	mux_value(target.systolic_pressure, source.systolic_pressure, sizeof(db::PlaintextRow::systolic_pressure) * 8, predicate, cloud_key_set);
	mux_value(target.diastolic_pressure, source.diastolic_pressure, sizeof(db::PlaintextRow::diastolic_pressure) * 8, predicate, cloud_key_set);
	mux_value(target.oxygen_saturation, source.oxygen_saturation, sizeof(db::PlaintextRow::oxygen_saturation) * 8, predicate, cloud_key_set);
}

void copy_value(LweSample* target, const LweSample* source, size_t size, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	for(std::size_t i = 0; i < size; ++i)
	{
		bootsCOPY(&target[i], &source[i], cloud_key_set);
	}
}

void copy_row(db::EncryptedRow& target, const db::EncryptedRow& source, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	copy_value(target.id, source.id, sizeof(db::PlaintextRow::id) * 8, cloud_key_set);
	copy_value(target.pulse_rate, source.pulse_rate, sizeof(db::PlaintextRow::pulse_rate) * 8, cloud_key_set);
	copy_value(target.systolic_pressure, source.systolic_pressure, sizeof(db::PlaintextRow::systolic_pressure) * 8, cloud_key_set);
	copy_value(target.diastolic_pressure, source.diastolic_pressure, sizeof(db::PlaintextRow::diastolic_pressure) * 8, cloud_key_set);
	copy_value(target.oxygen_saturation, source.oxygen_saturation, sizeof(db::PlaintextRow::oxygen_saturation) * 8, cloud_key_set);
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
	bootsNOT(result, result, cloud_key_set);

	return result;
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

LweSample* gt(const LweSample* lhs, const LweSample* rhs, size_t size, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);
	LweSample* result = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);

	bootsCONSTANT(result, 0, cloud_key_set);
	for(std::size_t i = 0; i < size; ++i)
	{
		bootsXNOR(temp, &lhs[i], &rhs[i], cloud_key_set);
		bootsMUX(result, temp, result, &lhs[i], cloud_key_set);
	}
	delete_gate_bootstrapping_ciphertext_array(1, temp);

	return result;
}

LweSample* gt_row(const db::EncryptedRow& lhs, const db::EncryptedRow& rhs, Field column, const TFheGateBootstrappingCloudKeySet* cloud_key_set)
{
	std::vector<std::thread> workers;

	LweSample* eq_by_column;
	LweSample* gt_by_column;

	switch(column)
	{
		case Field::PULSE_RATE:
			eq_by_column = eq(lhs.pulse_rate, rhs.pulse_rate,  sizeof(db::PlaintextRow::pulse_rate) * 8, cloud_key_set);
			gt_by_column = gt(lhs.pulse_rate, rhs.pulse_rate,  sizeof(db::PlaintextRow::pulse_rate) * 8, cloud_key_set);
			break;
		case Field::SYSTOLIC_PRESSURE:
			eq_by_column = eq(lhs.systolic_pressure, rhs.systolic_pressure,  sizeof(db::PlaintextRow::systolic_pressure) * 8, cloud_key_set);
			gt_by_column = gt(lhs.systolic_pressure, rhs.systolic_pressure,  sizeof(db::PlaintextRow::systolic_pressure) * 8, cloud_key_set);
			break;
		case Field::DIASTOLIC_PRESSURE:
			eq_by_column = eq(lhs.diastolic_pressure, rhs.diastolic_pressure,  sizeof(db::PlaintextRow::diastolic_pressure) * 8, cloud_key_set);
			gt_by_column = gt(lhs.diastolic_pressure, rhs.diastolic_pressure,  sizeof(db::PlaintextRow::diastolic_pressure) * 8, cloud_key_set);
			break;
		case Field::OXYGEN_SATURATION:
			eq_by_column = eq(lhs.oxygen_saturation, rhs.oxygen_saturation,  sizeof(db::PlaintextRow::oxygen_saturation) * 8, cloud_key_set);
			gt_by_column = gt(lhs.oxygen_saturation, rhs.oxygen_saturation,  sizeof(db::PlaintextRow::oxygen_saturation) * 8, cloud_key_set);
			break;
	}

	LweSample* gt_by_id = gt(lhs.id, rhs.id, sizeof(db::PlaintextRow::id) * 8, cloud_key_set);

	LweSample* result = new_gate_bootstrapping_ciphertext_array(1, cloud_key_set->params);
	bootsMUX(result, eq_by_column, gt_by_id, gt_by_column, cloud_key_set);

	delete_gate_bootstrapping_ciphertext_array(1, eq_by_column);
	delete_gate_bootstrapping_ciphertext_array(1, gt_by_column);
	delete_gate_bootstrapping_ciphertext_array(1, gt_by_id);

	return result;
}

TFheGateBootstrappingSecretKeySet* load_keys_from_file()
{
	std::ifstream private_key_file("private.key");
	if(!private_key_file)
	{
		panic("Cannot open private.key for reading!!!");
	}

	return new_tfheGateBootstrappingSecretKeySet_fromStream(private_key_file);
}

void generate_sorted_by_column(const std::vector<db::EncryptedRow>& rows, Field column, const TFheGateBootstrappingCloudKeySet* cloud_key_set, const TFheGateBootstrappingSecretKeySet* secret_key_set)
{
	std::vector<db::EncryptedRow> sorted_db;

	for(std::size_t i = 0; i < rows.size(); ++i)
	{
		sorted_db.emplace_back(cloud_key_set->params);
		copy_row(sorted_db[i], rows[i], cloud_key_set);
	}

	//bubble_sort
	for(std::size_t i = 0; i < rows.size(); ++i)
	{
		const auto start = std::chrono::high_resolution_clock::now();
		std::vector<std::thread> workers;
		for(std::size_t j = 1; j < rows.size() - 1; j += 2)
		{
			workers.emplace_back([&sorted_db, column, &cloud_key_set, j](){
				LweSample* gt_by_column_id = gt_row(sorted_db[j], sorted_db[j+1], column, cloud_key_set);
				bootsNOT(gt_by_column_id, gt_by_column_id, cloud_key_set);

				db::EncryptedRow temp_row_1(cloud_key_set->params);
				copy_row(temp_row_1, sorted_db[j], cloud_key_set);

				db::EncryptedRow temp_row_2(cloud_key_set->params);
				copy_row(temp_row_2, sorted_db[j+1], cloud_key_set);

				mux_row(sorted_db[j], temp_row_2, gt_by_column_id, cloud_key_set);
				mux_row(sorted_db[j+1], temp_row_1, gt_by_column_id, cloud_key_set);

				delete_gate_bootstrapping_ciphertext_array(1, gt_by_column_id);
			});
		}

		for(auto& worker: workers)
		{
			worker.join();
		}

		workers.clear();
		for(std::size_t j = 0; j < rows.size() - 1; j += 2)
		{
			workers.emplace_back([&sorted_db, column, &cloud_key_set, j](){
				LweSample* gt_by_column_id = gt_row(sorted_db[j], sorted_db[j+1], column, cloud_key_set);
				bootsNOT(gt_by_column_id, gt_by_column_id, cloud_key_set);

				db::EncryptedRow temp_row_1(cloud_key_set->params);
				copy_row(temp_row_1, sorted_db[j], cloud_key_set);

				db::EncryptedRow temp_row_2(cloud_key_set->params);
				copy_row(temp_row_2, sorted_db[j+1], cloud_key_set);

				mux_row(sorted_db[j], temp_row_2, gt_by_column_id, cloud_key_set);
				mux_row(sorted_db[j+1], temp_row_1, gt_by_column_id, cloud_key_set);

				delete_gate_bootstrapping_ciphertext_array(1, gt_by_column_id);
			});
		}

		for(auto& worker: workers)
		{
			worker.join();
		}
		const auto end = std::chrono::high_resolution_clock::now();

		std::cout << "Elapsed: " << std::chrono::duration_cast<std::chrono::seconds>(end - start).count() << std::endl;
		std::cout << "Estimated: " << std::chrono::duration_cast<std::chrono::seconds>(end - start).count()*(rows.size()-i-1) << std::endl;

		std::cout << (i+1)*(rows.size()-1)  << "/" << rows.size()*(rows.size()-1) << std::endl;
	}

	//store
	std::ofstream db_file(std::to_string(static_cast<std::size_t>(column)) + "_db");

	db::export_encrypted_db(db_file, sorted_db, cloud_key_set->params->in_out_params);

	{
		for(const auto& encrypted_row: sorted_db)
		{
			const auto plaintext_row = db::decrypt_row(encrypted_row, secret_key_set);
			std::cout << static_cast<long>(plaintext_row.id) << ", ";
			std::cout << static_cast<long>(plaintext_row.pulse_rate) << ", ";
			std::cout << static_cast<long>(plaintext_row.diastolic_pressure) << ", ";
			std::cout << static_cast<long>(plaintext_row.systolic_pressure) << ", ";
			std::cout << static_cast<long>(plaintext_row.oxygen_saturation) << std::endl;
		}
	}
}

int main(int argc, char** argv)
{
	const auto cloud_key_set = load_key_set();
	const auto secret_key_set = load_keys_from_file();
	const auto encrypted_db = load_db(cloud_key_set->params);

	const auto start = std::chrono::high_resolution_clock::now();


	for(const auto& encrypted_row: encrypted_db)
	{
		const auto plaintext_row = db::decrypt_row(encrypted_row, secret_key_set);
		std::cout << static_cast<long>(plaintext_row.id) << ", ";
		std::cout << static_cast<long>(plaintext_row.pulse_rate) << ", ";
		std::cout << static_cast<long>(plaintext_row.diastolic_pressure) << ", ";
		std::cout << static_cast<long>(plaintext_row.systolic_pressure) << ", ";
		std::cout << static_cast<long>(plaintext_row.oxygen_saturation) << std::endl;
	}

	std::cout << "Encrypting..." << std::endl;
	generate_sorted_by_column(encrypted_db, Field::PULSE_RATE, cloud_key_set, secret_key_set);

	const auto end = std::chrono::high_resolution_clock::now();
	std::cout << "Elapsed: " << std::chrono::duration_cast<std::chrono::seconds>(end - start).count() << std::endl;

	return 0;
}