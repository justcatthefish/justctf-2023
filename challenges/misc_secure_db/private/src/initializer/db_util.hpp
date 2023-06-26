#ifndef SECURE_DB_TASK_DB_UTIL_HPP
#define SECURE_DB_TASK_DB_UTIL_HPP

#include "db.hpp"

#include <vector>


namespace db
{
	std::vector<PlaintextRow> generate_db(size_t entries_count, std::mt19937& mt);
}

#endif //SECURE_DB_TASK_DB_UTIL_HPP
