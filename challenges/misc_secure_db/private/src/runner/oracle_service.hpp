#ifndef SECURE_DB_TASK_ORACLESERVICE_HPP
#define SECURE_DB_TASK_ORACLESERVICE_HPP

#include <random>

#include <oracle.grpc.pb.h>

#include "db.hpp"


class OracleService final: public Oracle::Service
{
public:
	OracleService(
			TFheGateBootstrappingSecretKeySet* secret_key_set,
			std::vector<db::EncryptedRow> encrypted_db, uint8_t* key,
			std::string flag
	);


	grpc::Status generateNewTask(::grpc::ServerContext *context, const ::Void *request, ::Task *response) override;

	grpc::Status checkResponse(::grpc::ServerContext *context, const ::TaskResponse *request, ::TaskResult *response) override;

private:
	TFheGateBootstrappingSecretKeySet* secret_key_set_;
	std::vector<db::PlaintextRow> plaintext_db_;

	std::mt19937 mt;
	uint8_t* key_;

	std::string flag_;
};


#endif //SECURE_DB_TASK_ORACLESERVICE_HPP
