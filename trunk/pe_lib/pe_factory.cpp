#include "pe_factory.h"
#include "pe_32_64.h"

namespace pe_bliss
{
std::auto_ptr<pe_base> pe_factory::create_pe(std::istream& file, bool read_bound_import_raw_data, bool read_debug_raw_data)
{
	std::auto_ptr<pe_base> ret;

	//Determine PE type and create corresponding class instance
	ret.reset(pe_base::get_pe_type(file) == pe_base::pe_type_32
		? static_cast<pe_base*>(new pe32(file, read_bound_import_raw_data, read_debug_raw_data))
		: static_cast<pe_base*>(new pe64(file, read_bound_import_raw_data, read_debug_raw_data))
		);

	return ret;
}
}
