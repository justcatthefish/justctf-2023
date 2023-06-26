#include "db.hpp"

#include <algorithm>

#include "tfhe_generic_streams.h"

namespace db
{
	EncryptedRow encrypt_row(const PlaintextRow &row, const TFheGateBootstrappingSecretKeySet *secret_key_set)
	{
		EncryptedRow encrypted(secret_key_set->params);

		encrypt_value(encrypted.id, row.id, secret_key_set);
		encrypt_value(encrypted.pulse_rate, row.pulse_rate, secret_key_set);
		encrypt_value(encrypted.systolic_pressure, row.systolic_pressure, secret_key_set);
		encrypt_value(encrypted.diastolic_pressure, row.diastolic_pressure, secret_key_set);
		encrypt_value(encrypted.oxygen_saturation, row.oxygen_saturation, secret_key_set);

		return encrypted;
	}

	PlaintextRow decrypt_row(const EncryptedRow &row, const TFheGateBootstrappingSecretKeySet *secret_key_set)
	{
		PlaintextRow plaintext{};

		decrypt_value(plaintext.id, row.id, secret_key_set);
		decrypt_value(plaintext.pulse_rate, row.pulse_rate, secret_key_set);
		decrypt_value(plaintext.systolic_pressure, row.systolic_pressure, secret_key_set);
		decrypt_value(plaintext.diastolic_pressure, row.diastolic_pressure, secret_key_set);
		decrypt_value(plaintext.oxygen_saturation, row.oxygen_saturation, secret_key_set);

		return plaintext;
	}

	std::vector<EncryptedRow> encrypt_db(const std::vector<PlaintextRow> &entries, const TFheGateBootstrappingSecretKeySet *secret_key_set)
	{
		std::vector<EncryptedRow> output;
		output.reserve(entries.size());

		std::transform(std::begin(entries), std::end(entries), std::back_inserter(output),
		               [&secret_key_set](const PlaintextRow& row)
		               {
			               return encrypt_row(row, secret_key_set);
		               }
		);

		return output;
	}

	void export_encrypted_value(std::ostream &out, const LweSample *src, size_t size, const LweParams *params)
	{
		for(size_t i = 0; i < size; ++i)
		{
			export_lweSample_toStream(out, &src[i], params);
		}
	}

	void export_encrypted_row(std::ostream &out, const EncryptedRow &src, const LweParams *params)
	{
		export_encrypted_value(out, src.id, sizeof(PlaintextRow::id) * 8, params);
		export_encrypted_value(out, src.pulse_rate, sizeof(PlaintextRow::pulse_rate) * 8, params);
		export_encrypted_value(out, src.systolic_pressure, sizeof(PlaintextRow::systolic_pressure) * 8, params);
		export_encrypted_value(out, src.diastolic_pressure, sizeof(PlaintextRow::diastolic_pressure) * 8, params);
		export_encrypted_value(out, src.oxygen_saturation, sizeof(PlaintextRow::oxygen_saturation) * 8, params);
	}

	void export_encrypted_db(std::ostream &out, const std::vector<EncryptedRow> &src, const LweParams *params)
	{
		uint16_t count = src.size();
		out << count;

		std::for_each(std::begin(src), std::end(src),
		              [&out, params](const EncryptedRow& row)
		              {
			              export_encrypted_row(out, row, params);
		              }
		);
	}

	void read_lweSample_throw(std::stringstream& in, LweSample *sample, const LweParams *params) {
		const int32_t n = params->n;

		int32_t type_uid;
		in.read(reinterpret_cast<char*>(&type_uid), sizeof(int32_t));
		if (type_uid != LWE_SAMPLE_TYPE_UID)
		{
			throw std::runtime_error("Failed to import LweSample. No LweSample UID !");
		}

		in.read(reinterpret_cast<char*>(sample->a), sizeof(Torus32) * n);
		in.read(reinterpret_cast<char*>(&sample->b), sizeof(Torus32));
		in.read(reinterpret_cast<char*>(&sample->current_variance), sizeof(double));
	}

	void import_encrypted_value_throw(LweSample *dest, std::stringstream &in, size_t size, const LweParams *params)
	{
		for(size_t i = 0; i < size; ++i)
		{
			read_lweSample_throw(in, &dest[i], params);
		}
	}

	void import_encrypted_value(LweSample *dest, std::istream &in, size_t size, const LweParams *params)
	{
		for(size_t i = 0; i < size; ++i)
		{
			import_lweSample_fromStream(in, &dest[i], params);
		}
	}

	EncryptedRow import_encrypted_row(std::istream &in, const TFheGateBootstrappingParameterSet *params)
	{
		EncryptedRow row(params);

		import_encrypted_value(row.id, in, sizeof(PlaintextRow::id) * 8, params->in_out_params);
		import_encrypted_value(row.pulse_rate, in, sizeof(PlaintextRow::pulse_rate) * 8, params->in_out_params);
		import_encrypted_value(row.systolic_pressure, in, sizeof(PlaintextRow::systolic_pressure) * 8, params->in_out_params);
		import_encrypted_value(row.diastolic_pressure, in, sizeof(PlaintextRow::diastolic_pressure) * 8, params->in_out_params);
		import_encrypted_value(row.oxygen_saturation, in, sizeof(PlaintextRow::oxygen_saturation) * 8, params->in_out_params);

		return row;
	}

	std::vector<EncryptedRow> import_encrypted_db(std::istream &in, const TFheGateBootstrappingParameterSet *params)
	{
		uint16_t count = 0;
		in >> count;

		std::vector<EncryptedRow> rows;
		rows.reserve(count);
		std::generate_n(std::back_inserter(rows), count,
		                [&in, params]()
		                {
			                return import_encrypted_row(in, params);
		                }
		);

		return rows;
	}
}