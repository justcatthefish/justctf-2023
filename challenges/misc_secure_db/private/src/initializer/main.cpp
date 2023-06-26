#include <random>
#include <array>
#include <algorithm>
#include <fstream>
#include <iostream>

#include <tfhe.h>
#include <tfhe_io.h>

#include "db_util.hpp"

void panic(const std::string& msg)
{
	std::cerr << msg << std::endl;
	exit(1);
}

std::pair<TFheGateBootstrappingSecretKeySet*, TFheGateBootstrappingParameterSet*> generate_secret_key_set(std::mt19937& mt)
{
	const int minimum_lambda = 10;

	std::uniform_int_distribution<uint32_t> dist;
	std::array<uint32_t, 5> seed{};
	std::generate(std::begin(seed), std::end(seed), [&dist, &mt](){return dist(mt);});

	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
	tfhe_random_generator_setSeed(seed.data(), seed.size());

	TFheGateBootstrappingSecretKeySet* secret_key_set = new_random_gate_bootstrapping_secret_keyset(params);

	return {secret_key_set, params};
}

void dump_keys_to_file(const TFheGateBootstrappingSecretKeySet* secret_key_set)
{
	std::ofstream private_key_file("private.key");
	if(!private_key_file)
	{
		panic("Cannot open private.key for writing!!!");
	}

	export_tfheGateBootstrappingSecretKeySet_toStream(private_key_file, secret_key_set);

	std::ofstream cloud_key_file("cloud.key");
	if(!cloud_key_file)
	{
		panic("Cannot open private.key for writing!!!");
	}
	export_tfheGateBootstrappingCloudKeySet_toStream(cloud_key_file, &secret_key_set->cloud);
}

void dump_db(const std::vector<db::EncryptedRow>& db, const LweParams* params)
{
	std::ofstream db_file("db");
	if(!db_file)
	{
		panic("Cannot open db file for writing!!!");
	}

	db::export_encrypted_db(db_file, db, params);
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


std::vector<db::EncryptedRow> load_db(const TFheGateBootstrappingParameterSet* params)
{
	std::ifstream db_file("db");
	if(!db_file)
	{
		panic("Cannot open db file for reading!!!");
	}

	return db::import_encrypted_db(db_file, params);
}

bool operator==(const db::PlaintextRow& lhs, const db::PlaintextRow& rhs)
{
	return
		lhs.id == rhs.id
		&& lhs.pulse_rate == rhs.pulse_rate
		&& lhs.systolic_pressure == rhs.systolic_pressure
		&& lhs.diastolic_pressure == rhs.diastolic_pressure
		&& lhs.oxygen_saturation == rhs.oxygen_saturation;
}

int main(int argc, char** argv)
{
	constexpr size_t ENTRIES_COUNT = 32;

	std::random_device rd;
	std::mt19937 mt(rd());

	std::vector<db::PlaintextRow> plaintext_db;
	{
		std::cout << "Generating private key" << std::endl;
		auto [secret_key_set, params] = generate_secret_key_set(mt);

		std::cout << "Storing secret & cloud key to file" << std::endl;
		dump_keys_to_file(secret_key_set);

		std::cout << "Generating plaintext_db" << std::endl;
		plaintext_db = db::generate_db(ENTRIES_COUNT, mt);

		std::cout << "Shuffling data" << std::endl;
		std::shuffle(std::begin(plaintext_db), std::end(plaintext_db), mt);

		std::cout << "Encrypting plaintext_db" << std::endl;
		const auto encrypted_db = db::encrypt_db(plaintext_db, secret_key_set);

		std::cout << "Dumping plaintext_db to file" << std::endl;
		dump_db(encrypted_db, secret_key_set->params->in_out_params);

		delete_gate_bootstrapping_parameters(params);
		delete_gate_bootstrapping_secret_keyset(secret_key_set);
	}
	{
		std::cout << "## Testing data integrity" << std::endl;

		std::cout << "Loading secret key_from file" << std::endl;
		auto secret_key_set = load_keys_from_file();

		std::cout << "Loading plaintext_db from file" << std::endl;
		const auto debug_encrypted_db = load_db(secret_key_set->params);

		std::cout << "Decrypting plaintext_db" << std::endl;
		std::vector<db::PlaintextRow> debug_db;
		debug_db.reserve(debug_encrypted_db.size());
		std::transform(std::begin(debug_encrypted_db), std::end(debug_encrypted_db), std::back_inserter(debug_db),
			[&secret_key_set](const db::EncryptedRow& row)
			{
				return db::decrypt_row(row, secret_key_set);
			}
		);

		std::cout << "Validating entries" << std::endl;
		bool result = true;
		for(size_t i = 0; i < debug_db.size(); ++i)
		{
			if (plaintext_db[i] != debug_db[i])
			{
				result = false;
				break;
			}
		}
		if(result)
		{
			std::cout << "Success" << std::endl;
		}
		else
		{
			std::cout << "Failure" << std::endl;
		}

		delete_gate_bootstrapping_secret_keyset(secret_key_set);
	}
}