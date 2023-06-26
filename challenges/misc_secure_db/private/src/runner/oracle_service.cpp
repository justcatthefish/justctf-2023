#include "oracle_service.hpp"

#include <array>
#include <chrono>
#include <sstream>
#include <utility>

#include <openssl/evp.h>
#include <paseto.h>
#include <spdlog/spdlog.h>


namespace
{
	constexpr std::size_t LIMIT{4};
	const std::chrono::minutes PROCESSING_LIMIT{5};

	enum class Field : size_t
	{
		PULSE_RATE,
		SYSTOLIC_PRESSURE,
		DIASTOLIC_PRESSURE,
		OXYGEN_SATURATION
	};

	const std::array<std::pair<Field, std::string>, 4> fields =
			{
					std::pair<Field, std::string>(Field::PULSE_RATE, "pulse rate"),
					std::pair<Field, std::string>(Field::SYSTOLIC_PRESSURE, "systolic pressure"),
					std::pair<Field, std::string>(Field::DIASTOLIC_PRESSURE, "diastolic pressure"),
					std::pair<Field, std::string>(Field::OXYGEN_SATURATION, "oxygen saturation")};

	bool compare_rows(const db::PlaintextRow& lhs, const db::PlaintextRow& rhs, Field column)
	{
		bool equal = true;
		bool lower = true;
		switch(column)
		{
			case Field::PULSE_RATE:
				equal = lhs.pulse_rate == rhs.pulse_rate;
				lower = lhs.pulse_rate < rhs.pulse_rate;
				break;
			case Field::SYSTOLIC_PRESSURE:
				equal = lhs.systolic_pressure == rhs.systolic_pressure;
				lower = lhs.systolic_pressure < rhs.systolic_pressure;
				break;
			case Field::DIASTOLIC_PRESSURE:
				equal = lhs.diastolic_pressure == rhs.diastolic_pressure;
				lower = lhs.diastolic_pressure < rhs.diastolic_pressure;
				break;
			case Field::OXYGEN_SATURATION:
				equal = lhs.oxygen_saturation == rhs.oxygen_saturation;
				lower = lhs.oxygen_saturation < rhs.oxygen_saturation;
				break;
		}

		if(equal)
		{
			return lhs.id < rhs.id;
		}

		return lower;
	}

	std::array<std::size_t, LIMIT> sample_indices(const std::vector<db::PlaintextRow>& plaintext_db, std::mt19937& mt)
	{
		std::array<size_t, LIMIT> indices{};
		std::size_t generated = 0;
		std::uniform_int_distribution<std::size_t> distribution(0, plaintext_db.size() - 1);

		while(generated < LIMIT)
		{
			const auto candidate = distribution(mt);
			bool duplicate = false;

			for(std::size_t i = 0; i < generated; ++i)
			{
				if(indices[i] == candidate)
				{
					duplicate = true;
					break;
				}
			}

			if(duplicate)
			{
				continue;
			}

			indices[generated] = candidate;
			++generated;
		}

		return indices;
	}

	std::vector<std::pair<Field, std::string>> sample_result_columns(std::mt19937& mt)
	{
		std::vector<std::pair<Field, std::string>> out;
		std::sample(std::begin(fields), std::end(fields), std::back_inserter(out), 2, mt);

		return out;
	}

	std::string indices_to_string(const std::array<std::size_t, LIMIT>& indices)
	{
		std::string indices_info;
		for(std::size_t i = 0; i < indices.size(); ++i)
		{
			if(i != 0)
			{
				indices_info += " ";
			}
			indices_info += std::to_string(indices[i]);
		}
		return indices_info;
	}

	std::pair<Field, std::string> random_sort_column(std::mt19937& mt)
	{
		std::uniform_int_distribution<std::size_t> distribution(0, fields.size() - 1);
		return fields[distribution(mt)];
	}

	//https://stackoverflow.com/questions/5288076/base64-encoding-and-decoding-with-openssl
	std::pair<char*, size_t> base64(const unsigned char* input, int length)
	{
		const auto pl = 4 * ((length + 2) / 3);
		auto output = reinterpret_cast<char*>(calloc(pl + 1,
													 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
		const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output), input, length);
		if(pl != ol)
		{
			spdlog::warn("Whoops, encode predicted {} but we got {}", pl, ol);
		}
		return {output, pl};
	}

	std::pair<unsigned char*, size_t> decode64(const char* input, int length)
	{
		const auto pl = 3 * length / 4;
		auto output = reinterpret_cast<unsigned char*>(calloc(pl + 1, 1));
		const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char*>(input), length);
		if(pl != ol)
		{
			spdlog::warn("Whoops, decode predicted {} but we got {}", pl, ol);
		}
		return {output, ol};
	}

	size_t get_column_size(Field column)
	{
		size_t column_size = 0;

		switch(column)
		{
			case Field::PULSE_RATE:
				column_size = sizeof(db::PlaintextRow::pulse_rate) * 8;
				break;
			case Field::SYSTOLIC_PRESSURE:
				column_size = sizeof(db::PlaintextRow::systolic_pressure) * 8;
				break;
			case Field::DIASTOLIC_PRESSURE:
				column_size = sizeof(db::PlaintextRow::diastolic_pressure) * 8;
				break;
			case Field::OXYGEN_SATURATION:
				column_size = sizeof(db::PlaintextRow::oxygen_saturation) * 8;
				break;
		}
		return column_size;
	}

	LweSample* load_column(std::stringstream& in, Field column, const TFheGateBootstrappingParameterSet* params)
	{
		size_t column_size = get_column_size(column);

		LweSample* out = new_gate_bootstrapping_ciphertext_array(column_size, params);
		db::import_encrypted_value_throw(out, in, column_size, params->in_out_params);
		return out;
	}

	bool compare_column(
			const db::PlaintextRow& plaintext_row, const LweSample* field,
			Field column,
			const TFheGateBootstrappingSecretKeySet* secret_key_set)
	{
		switch(column)
		{
			case Field::PULSE_RATE:
				decltype(db::PlaintextRow::pulse_rate) pulse_rate;
				db::decrypt_value(pulse_rate, field, secret_key_set);
				return pulse_rate == plaintext_row.pulse_rate;
			case Field::SYSTOLIC_PRESSURE:
				decltype(db::PlaintextRow::systolic_pressure) systolic_pressure;
				db::decrypt_value(systolic_pressure, field, secret_key_set);
				return systolic_pressure == plaintext_row.systolic_pressure;
			case Field::DIASTOLIC_PRESSURE:
				decltype(db::PlaintextRow::diastolic_pressure) diastolic_pressure;
				db::decrypt_value(diastolic_pressure, field, secret_key_set);
				return diastolic_pressure == plaintext_row.diastolic_pressure;
			case Field::OXYGEN_SATURATION:
				decltype(db::PlaintextRow::oxygen_saturation) oxygen_saturation;
				db::decrypt_value(oxygen_saturation, field, secret_key_set);
				return oxygen_saturation == plaintext_row.oxygen_saturation;
		}
		return false;
	}
} // namespace


grpc::Status OracleService::generateNewTask(::grpc::ServerContext* context, const ::Void* request, ::Task* response)
{
	const auto indices = sample_indices(plaintext_db_, mt);
	const auto result_columns = sample_result_columns(mt);
	const auto sort_column = random_sort_column(mt);

	{
		std::stringstream stream;

		LweSample* encrypted_id;
		encrypted_id = new_gate_bootstrapping_ciphertext_array(sizeof(db::PlaintextRow::id) * 8, secret_key_set_->params);
		for(std::size_t i = 0; i < LIMIT; ++i)
		{
			const auto& selected_row = plaintext_db_[indices[i]];
			const auto selected_id = selected_row.id;

			db::encrypt_value(encrypted_id, selected_id, secret_key_set_);

			db::export_encrypted_value(
					stream, encrypted_id, sizeof(db::PlaintextRow::id) * 8,
					secret_key_set_->params->in_out_params);
		}
		delete_gate_bootstrapping_ciphertext_array(sizeof(db::PlaintextRow::id) * 8, encrypted_id);

		std::string buffer(std::istreambuf_iterator<char>(stream), {});

		auto [id_base64, id_base64_size] = base64(reinterpret_cast<const unsigned char*>(buffer.c_str()),
												  buffer.size());

		const auto question = fmt::format(
				"Could you tell me values of {} and {} for 4 records which ids are in ({})? Please sort the result array ascending by {}, id ",
				result_columns[0].second, result_columns[1].second, id_base64, sort_column.second);
		response->set_question(question);

		free(id_base64);
	}
	{
		const auto challenge_start = std::chrono::system_clock::now();
		const auto challenge_start_sec_from_epoch = std::chrono::duration_cast<std::chrono::seconds>(
															challenge_start.time_since_epoch())
															.count();

		const std::string indices_info = indices_to_string(indices);
		spdlog::info("Generating new task: index: [{}], columns: {}-{}, sort: {}, timestamp: {}",
					 indices_info,
					 static_cast<size_t>(result_columns[0].first), static_cast<size_t>(result_columns[1].first),
					 static_cast<size_t>(sort_column.first),
					 challenge_start_sec_from_epoch);

		const auto challenge_description = fmt::format("{} {} {} {} {}", challenge_start_sec_from_epoch, indices_info,
													   static_cast<size_t>(result_columns[0].first),
													   static_cast<size_t>(result_columns[1].first),
													   static_cast<size_t>(sort_column.first));

		const auto token = paseto_v2_local_encrypt(reinterpret_cast<const uint8_t*>(challenge_description.data()),
												   challenge_description.size(), key_, nullptr, 0);

		response->set_token(token);

		paseto_free(token);
	}
	return grpc::Status::OK;
}

grpc::Status
OracleService::checkResponse(::grpc::ServerContext* context, const ::TaskResponse* request, ::TaskResult* response)
{
	std::array<std::size_t, LIMIT> indices{};
	size_t result_column_1;
	size_t result_column_2;
	size_t sort_column;

	{
		size_t message_len;
		auto message = paseto_v2_local_decrypt(request->token().c_str(), &message_len, key_, nullptr, nullptr);
		if(!message)
		{
			spdlog::error("Detected tampering with challenge token!");
			response->set_result("I see what you did! Do not try this!");

			return grpc::Status::OK;
		}

		std::string message_str;
		message_str.resize(message_len);
		memcpy(message_str.data(), message, message_len);

		paseto_free(message);

		long sec_from_epoch;

		{
			std::stringstream token_stream(message_str);
			token_stream >> sec_from_epoch;
			for(std::size_t i = 0; i < LIMIT; ++i)
			{
				token_stream >> indices[i];
			}
			token_stream >> result_column_1 >> result_column_2 >> sort_column;
		}

		const std::string indices_info = indices_to_string(indices);
		spdlog::info("Response for task sec_from_epoch: {}, indices: {}, result columns: {}-{}, sort: {}", sec_from_epoch,
					 indices_info,
					 result_column_1, result_column_2, sort_column);

		std::chrono::seconds seconds_from_epoch{sec_from_epoch};
		std::chrono::time_point<std::chrono::system_clock> start{seconds_from_epoch};

		if(std::chrono::system_clock::now() - start > PROCESSING_LIMIT)
		{
			spdlog::info("Timeout for task reached!");
			response->set_result("Timeout for task reached. Try again!");

			return grpc::Status::OK;
		}
	}

	std::array<db::PlaintextRow, LIMIT> expected_rows{};

	for(std::size_t expected_index = 0; const auto index: indices)
	{
		expected_rows[expected_index] = plaintext_db_[index];
		++expected_index;
	}

	std::ranges::sort(expected_rows,
					  [sort_column](const auto& lhs, const auto& rhs) {
						  return compare_rows(lhs, rhs, static_cast<Field>(sort_column));
					  });

	LweSample* response_column_1;
	LweSample* response_column_2;

	const auto& task_response_base64 = request->response();
	auto [task_response, task_response_size] = decode64(task_response_base64.c_str(), task_response_base64.size());
	std::stringstream stream;
	stream.write(reinterpret_cast<char*>(task_response), task_response_size);

	bool result = true;

	for(std::size_t i = 0; i < LIMIT; ++i)
	{
		try
		{
			response_column_1 = load_column(stream, static_cast<Field>(result_column_1), secret_key_set_->params);
			response_column_2 = load_column(stream, static_cast<Field>(result_column_2), secret_key_set_->params);
		}
		catch(const std::runtime_error& error)
		{
			spdlog::error(error.what());
			response->set_result(error.what());
			return grpc::Status::OK;
		}

		const auto& plaintext_row = expected_rows[i];

		result = result && compare_column(plaintext_row, response_column_1, static_cast<Field>(result_column_1), secret_key_set_)
				 && compare_column(plaintext_row, response_column_2, static_cast<Field>(result_column_2), secret_key_set_);

		delete_gate_bootstrapping_ciphertext_array(get_column_size(static_cast<Field>(result_column_1)), response_column_1);
		delete_gate_bootstrapping_ciphertext_array(get_column_size(static_cast<Field>(result_column_2)), response_column_2);

		if(!result)
		{
			break;
		}
	}

	if(result)
	{
		spdlog::info("Correct answer! Delivering flag");
		const auto message = fmt::format(
				"Thank you! We want to reward you for your help. Here is flag: {}",
				flag_);

		response->set_result(message);
	}
	else
	{
		spdlog::info("Wrong answer!");
		response->set_result("I don't think that It's the correct answer. Try again!");
	}

	free(task_response);
	return grpc::Status::OK;
}

OracleService::OracleService(TFheGateBootstrappingSecretKeySet* secret_key_set, std::vector<db::EncryptedRow> encrypted_db, uint8_t* key, std::string flag):
	Oracle::Service(), secret_key_set_(secret_key_set), key_(key),
	flag_(flag)
{
	std::random_device rd;
	mt = std::mt19937(rd());

	plaintext_db_.reserve(encrypted_db.size());
	spdlog::info("Decrypting db...");

	for(const auto& encrypted_row: encrypted_db)
	{
		plaintext_db_.emplace_back(db::decrypt_row(encrypted_row, secret_key_set));
	}

	spdlog::info("Decryption completed");
};
