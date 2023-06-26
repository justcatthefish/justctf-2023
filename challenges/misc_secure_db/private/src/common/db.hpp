#ifndef SECURE_DB_TASK_DB_HPP
#define SECURE_DB_TASK_DB_HPP

#include <cstdint>
#include <concepts>
#include <ostream>
#include <istream>
#include <sstream>

#include <tfhe.h>


namespace db
{
	template<typename T>
	requires std::integral<T>
	void encrypt_value(LweSample* dest, T value, const TFheGateBootstrappingSecretKeySet* secret_key_set)
	{
		for(size_t i = 0; i < sizeof(T) * 8; ++i)
		{
			bootsSymEncrypt(&dest[i], (value >> i) & 1, secret_key_set);
		}
	}

	template<typename T>
	requires std::integral<T>
	void decrypt_value(T& dest, const LweSample* value, const TFheGateBootstrappingSecretKeySet* secret_key_set)
	{
		dest = 0;

		for(size_t i = 0; i < sizeof(T) * 8; ++i)
		{
			dest |= bootsSymDecrypt(&value[i], secret_key_set)  << i;
		}
	}

	struct PlaintextRow
	{
		uint16_t id;
		uint8_t pulse_rate;
		uint8_t systolic_pressure;
		uint8_t diastolic_pressure;
		uint8_t oxygen_saturation;
	};

	struct EncryptedRow
	{
		LweSample* id;
		LweSample* pulse_rate;
		LweSample* systolic_pressure;
		LweSample* diastolic_pressure;
		LweSample* oxygen_saturation;

		explicit EncryptedRow(const TFheGateBootstrappingParameterSet* params)
		{
			id = new_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::id) * 8, params);
			pulse_rate = new_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::pulse_rate) * 8, params);
			systolic_pressure = new_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::systolic_pressure) * 8, params);
			diastolic_pressure = new_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::diastolic_pressure) * 8, params);
			oxygen_saturation = new_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::oxygen_saturation) * 8, params);
		}

		EncryptedRow(const EncryptedRow&) = delete;
		EncryptedRow& operator=(const EncryptedRow&) = delete;

		EncryptedRow(EncryptedRow&& other) noexcept
		{
			id = other.id;
			pulse_rate = other.pulse_rate;
			systolic_pressure = other.systolic_pressure;
			diastolic_pressure = other.diastolic_pressure;
			oxygen_saturation = other.oxygen_saturation;

			other.id = nullptr;
			other.pulse_rate = nullptr;
			other.systolic_pressure = nullptr;
			other.diastolic_pressure = nullptr;
			other.oxygen_saturation = nullptr;
		};

		EncryptedRow& operator=(EncryptedRow&& other) noexcept
		{
			if(id)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::id) * 8, id);
			}

			if(pulse_rate)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::pulse_rate) * 8, pulse_rate);
			}

			if(systolic_pressure)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::systolic_pressure) * 8, systolic_pressure);
			}

			if(diastolic_pressure)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::diastolic_pressure) * 8, diastolic_pressure);
			}

			if(oxygen_saturation)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::oxygen_saturation) * 8, oxygen_saturation);
			}

			id = other.id;
			pulse_rate = other.pulse_rate;
			systolic_pressure = other.systolic_pressure;
			diastolic_pressure = other.diastolic_pressure;
			oxygen_saturation = other.oxygen_saturation;

			other.id = nullptr;
			other.pulse_rate = nullptr;
			other.systolic_pressure = nullptr;
			other.diastolic_pressure = nullptr;
			other.oxygen_saturation = nullptr;

			return *this;
		};

		~EncryptedRow()
		{
			if(id)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::id) * 8, id);
			}

			if(pulse_rate)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::pulse_rate) * 8, pulse_rate);
			}

			if(systolic_pressure)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::systolic_pressure) * 8, systolic_pressure);
			}

			if(diastolic_pressure)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::diastolic_pressure) * 8, diastolic_pressure);
			}

			if(oxygen_saturation)
			{
				delete_gate_bootstrapping_ciphertext_array(sizeof(PlaintextRow::oxygen_saturation) * 8, oxygen_saturation);
			}
		}
	};

	void read_lweSample_throw(std::stringstream& in, LweSample *sample, const LweParams *params);

	EncryptedRow encrypt_row(const PlaintextRow& row, const TFheGateBootstrappingSecretKeySet* secret_key_set);

	PlaintextRow decrypt_row(const EncryptedRow& row, const TFheGateBootstrappingSecretKeySet* secret_key_set);

	std::vector<EncryptedRow> encrypt_db(const std::vector<PlaintextRow>& entries,
	                                         const TFheGateBootstrappingSecretKeySet* secret_key_set);

	void export_encrypted_value(std::ostream& out, const LweSample* src, size_t size, const LweParams* params);

	void export_encrypted_row(std::ostream& out, const EncryptedRow& src, const LweParams* params);

	void export_encrypted_db(std::ostream& out, const std::vector<EncryptedRow>& src, const LweParams* params);

	void import_encrypted_value_throw(LweSample* dest, std::stringstream& in, size_t size, const LweParams* params);
	void import_encrypted_value(LweSample* dest, std::istream& in, size_t size, const LweParams* params);

	EncryptedRow import_encrypted_row(std::istream& in, const TFheGateBootstrappingParameterSet* params);

	std::vector<EncryptedRow> import_encrypted_db(std::istream& in, const TFheGateBootstrappingParameterSet* params);
}

#endif //SECURE_DB_TASK_DB_HPP
