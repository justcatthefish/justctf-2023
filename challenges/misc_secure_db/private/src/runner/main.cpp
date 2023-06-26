#include <iostream>
#include <fstream>
#include <random>
#include <cstdint>
#include <array>

#include <tfhe.h>
#include <tfhe_io.h>
#include <paseto.h>
#include <grpcpp/grpcpp.h>

#include "db.hpp"
#include "oracle_service.hpp"


void panic(const std::string& msg)
{
	std::cerr << msg << std::endl;
	exit(1);
}

TFheGateBootstrappingSecretKeySet* load_key_set()
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
		panic("Cannot open db for reading!!!");
	}

	return db::import_encrypted_db(db_file, params);
}


int main(int argc, char** argv)
{
	std::ios_base::sync_with_stdio(false);
	std::random_device rd;
	std::mt19937 mt(rd());

	std::uniform_int_distribution<uint32_t> dist;
	std::array<uint32_t, 5> seed{};
	std::generate(std::begin(seed), std::end(seed), [&dist, &mt](){return dist(mt);});
	tfhe_random_generator_setSeed(seed.data(), seed.size());

	const auto secret_key_set = load_key_set();
	auto db = load_db(secret_key_set->params);

	if(!paseto_init())
	{
		panic("Failed to initialize libpaseto!");
	}

	uint8_t key[paseto_v2_LOCAL_KEYBYTES];
	if(!paseto_v2_local_load_key_base64(key, getenv("PASETO_KEY")))
	{
		panic("Failed to load paseto key!");
	}

	std::string flag = getenv("FLAG");
	if (flag.empty())
	{
		panic("Failed to load flag!");
	}

	const std::string address{"0.0.0.0:5050"};
	OracleService service(secret_key_set, std::move(db), key, flag);

	grpc::ServerBuilder builder;
	builder.AddListeningPort(address, grpc::InsecureServerCredentials());
	builder.RegisterService(&service);

	const auto server = builder.BuildAndStart();
	server->Wait();

	return 0;
}