#include "db_util.hpp"


namespace db
{
	std::vector<PlaintextRow> generate_db(size_t entries_count, std::mt19937& mt)
	{
		std::vector<PlaintextRow> rows;
		rows.reserve(entries_count);

		std::uniform_int_distribution<decltype(PlaintextRow::pulse_rate)> pulse_rate_distribution(60, 150);
		std::uniform_int_distribution<decltype(PlaintextRow::systolic_pressure)> systolic_pressure_distribution(90, 220);
		std::uniform_int_distribution<decltype(PlaintextRow::diastolic_pressure)> diastolic_pressure_distribution(60, 130);
		std::uniform_int_distribution<decltype(PlaintextRow::oxygen_saturation)> oxygen_saturation_distribution(60, 100);

		for (size_t i = 0; i < entries_count; ++i)
		{
			const auto pulse_rate = pulse_rate_distribution(mt);
			const auto systolic_pressure = systolic_pressure_distribution(mt);
			const auto diastolic_pressure = diastolic_pressure_distribution(mt);
			const auto oxygen_saturation = oxygen_saturation_distribution(mt);

			rows.emplace_back(i, pulse_rate, systolic_pressure, diastolic_pressure, oxygen_saturation);
		}

		return rows;
	}


}
