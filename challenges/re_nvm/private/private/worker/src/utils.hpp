#pragma once
#include <string.h>
#include <iomanip>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#ifdef NDEBUG
#define DEBUG(str) do { } while ( false )
#else
#define DEBUG(str) do { std::cout << std::right << std::setw(16) << __FILENAME__ << ":" << std::dec << std::left << std::setw(3) << __LINE__ << " - " << str << std::endl; } while( false )
#endif
