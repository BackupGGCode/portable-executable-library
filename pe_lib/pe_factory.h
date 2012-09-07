#pragma once
#include <memory>
#include <istream>
#include "pe_base.h"

class pe_factory
{
public:
	//Creates pe_base class instance from PE or PE+ istream
	//If read_bound_import_raw_data, raw bound import data will be read (used to get bound import info)
	//If read_debug_raw_data, raw debug data will be read (used to get image debug info)
	static std::auto_ptr<pe_base> create_pe(std::istream& file, bool read_bound_import_raw_data = true, bool read_debug_raw_data = true);
};
