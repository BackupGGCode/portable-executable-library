#include <ctime>
#include <string.h>
#include "pe_32_64.h"

namespace pe_bliss
{
using namespace pe_win;

//Constructor of empty PE file
template<typename PEClassType>
pe<PEClassType>::pe(uint32_t section_alignment, bool dll, uint16_t subsystem)
{
	has_overlay_ = false;
	memset(&nt_headers_, 0, sizeof(nt_headers_));
	memset(&dos_header_, 0, sizeof(dos_header_));

	dos_header_.e_magic = 0x5A4D; //"MZ"
	//Magic numbers from MSVC++ build
	dos_header_.e_maxalloc = 0xFFFF;
	dos_header_.e_cblp = 0x90;
	dos_header_.e_cp = 3;
	dos_header_.e_cparhdr = 4;
	dos_header_.e_sp = 0xB8;
	dos_header_.e_lfarlc = 64;

	nt_headers_.Signature = 0x4550; //"PE"
	nt_headers_.FileHeader.Machine = 0x14C; //i386
	nt_headers_.FileHeader.SizeOfOptionalHeader = sizeof(nt_headers_.OptionalHeader);
	set_characteristics(image_file_executable_image | image_file_relocs_stripped);

	if(get_pe_type() == pe_type_32)
		set_characteristics_flags(image_file_32bit_machine);

	if(dll)
		set_characteristics_flags(image_file_dll);

	nt_headers_.OptionalHeader.Magic = PEClassType::Id;
	nt_headers_.OptionalHeader.ImageBase = 0x400000;
	nt_headers_.OptionalHeader.SectionAlignment = section_alignment;
	nt_headers_.OptionalHeader.FileAlignment = 0x200;
	set_subsystem_version(5, 1); //WinXP
	set_os_version(5, 1); //WinXP
	nt_headers_.OptionalHeader.SizeOfHeaders = 1024;
	nt_headers_.OptionalHeader.Subsystem = subsystem;
	nt_headers_.OptionalHeader.SizeOfHeapReserve = 0x100000;
	nt_headers_.OptionalHeader.SizeOfHeapCommit = 0x1000;
	nt_headers_.OptionalHeader.SizeOfStackReserve = 0x100000;
	nt_headers_.OptionalHeader.SizeOfStackCommit = 0x1000;
	nt_headers_.OptionalHeader.NumberOfRvaAndSizes = 0x10;
}

//Constructor from istream
template<typename PEClassType>
pe<PEClassType>::pe(std::istream& file, bool read_bound_import_raw_data, bool read_debug_raw_data)
{
	//Save istream state
	std::ios_base::iostate state = file.exceptions();
	std::streamoff old_offset = file.tellg();

	try
	{
		file.exceptions(std::ios::goodbit);
		//Read DOS header, PE headers and section data
		read_dos_header(file);
		read_pe(file, read_bound_import_raw_data, read_debug_raw_data);
	}
	catch(const std::exception&)
	{
		//If something went wrong, restore istream state
		file.seekg(old_offset);
		file.exceptions(state);
		file.clear();
		//Rethrow
		throw;
	}

	//Restore istream state
	file.seekg(old_offset);
	file.exceptions(state);
	file.clear();
}

//Destructor
template<typename PEClassType>
pe<PEClassType>::~pe()
{}

//Returns true if directory exists
template<typename PEClassType>
bool pe<PEClassType>::directory_exists(uint32_t id) const
{
	return (nt_headers_.OptionalHeader.NumberOfRvaAndSizes - 1) >= id &&
		nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress;
}

//Removes directory
template<typename PEClassType>
void pe<PEClassType>::remove_directory(uint32_t id)
{
	if(directory_exists(id))
	{
		nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress = 0;
		nt_headers_.OptionalHeader.DataDirectory[id].Size = 0;

		if(id == image_directory_entry_basereloc)
		{
			set_characteristics_flags(image_file_relocs_stripped);
			set_dll_characteristics(get_dll_characteristics() & ~image_dllcharacteristics_dynamic_base);
		}
		else if(id == image_directory_entry_export)
		{
			clear_characteristics_flags(image_file_dll);
		}
	}
}

//Returns directory RVA
template<typename PEClassType>
uint32_t pe<PEClassType>::get_directory_rva(uint32_t id) const
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	return nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress;
}

//Returns directory size
template<typename PEClassType>
void pe<PEClassType>::set_directory_rva(uint32_t id, uint32_t va)
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress = va;
}

template<typename PEClassType>
void pe<PEClassType>::set_directory_size(uint32_t id, uint32_t size)
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	nt_headers_.OptionalHeader.DataDirectory[id].Size = size;
}

//Returns directory size
template<typename PEClassType>
uint32_t pe<PEClassType>::get_directory_size(uint32_t id) const
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	return nt_headers_.OptionalHeader.DataDirectory[id].Size;
}

//Strips only zero DATA_DIRECTORY entries to count = min_count
//Returns resulting number of data directories
//strip_iat_directory - if true, even not empty IAT directory will be stripped
template<typename PEClassType>
uint32_t pe<PEClassType>::strip_data_directories(uint32_t min_count, bool strip_iat_directory)
{
	int i = nt_headers_.OptionalHeader.NumberOfRvaAndSizes - 1;

	//Enumerate all data directories from the end
	for(; i >= 0; i--)
	{
		//If directory exists, break
		if(nt_headers_.OptionalHeader.DataDirectory[i].VirtualAddress && (i != image_directory_entry_iat || !strip_iat_directory))
			break;

		if(i <= static_cast<int>(min_count) - 2)
			break;
	}

	if(i == image_numberof_directory_entries - 1)
		return image_numberof_directory_entries;

	//Return new number of data directories
	return nt_headers_.OptionalHeader.NumberOfRvaAndSizes = i + 1;
}

//Returns image base for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::get_image_base_32() const
{
	return static_cast<uint32_t>(nt_headers_.OptionalHeader.ImageBase);
}

//Returns image base for PE32/PE64
template<typename PEClassType>
uint64_t pe<PEClassType>::get_image_base_64() const
{
	return static_cast<uint64_t>(nt_headers_.OptionalHeader.ImageBase);
}

//Sets new image base
template<typename PEClassType>
void pe<PEClassType>::set_image_base(uint32_t base)
{
	nt_headers_.OptionalHeader.ImageBase = base;
}

//Sets new image base
template<typename PEClassType>
void pe<PEClassType>::set_image_base_64(uint64_t base)
{
	nt_headers_.OptionalHeader.ImageBase = static_cast<typename PEClassType::BaseSize>(base);
}

//Returns image entry point
template<typename PEClassType>
uint32_t pe<PEClassType>::get_ep() const
{
	return nt_headers_.OptionalHeader.AddressOfEntryPoint;
}

//Sets image entry point
template<typename PEClassType>
void pe<PEClassType>::set_ep(uint32_t new_ep)
{
	nt_headers_.OptionalHeader.AddressOfEntryPoint = new_ep;
}

//Returns file alignment
template<typename PEClassType>
uint32_t pe<PEClassType>::get_file_alignment() const
{
	return nt_headers_.OptionalHeader.FileAlignment;
}

//Returns section alignment
template<typename PEClassType>
uint32_t pe<PEClassType>::get_section_alignment() const
{
	return nt_headers_.OptionalHeader.SectionAlignment;
}

//Sets heap size commit for PE32
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_commit(uint32_t size)
{
	nt_headers_.OptionalHeader.SizeOfHeapCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets heap size commit for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_commit(uint64_t size)
{
	nt_headers_.OptionalHeader.SizeOfHeapCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets heap size reserve for PE32
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_reserve(uint32_t size)
{
	nt_headers_.OptionalHeader.SizeOfHeapReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets heap size reserve for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_reserve(uint64_t size)
{
	nt_headers_.OptionalHeader.SizeOfHeapReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size commit for PE32
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_commit(uint32_t size)
{
	nt_headers_.OptionalHeader.SizeOfStackCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size commit for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_commit(uint64_t size)
{
	nt_headers_.OptionalHeader.SizeOfStackCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size reserve for PE32
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_reserve(uint32_t size)
{
	nt_headers_.OptionalHeader.SizeOfStackReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size reserve for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_reserve(uint64_t size)
{
	nt_headers_.OptionalHeader.SizeOfStackReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Returns heap size commit for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::get_heap_size_commit_32() const
{
	return static_cast<uint32_t>(nt_headers_.OptionalHeader.SizeOfHeapCommit);
}

//Returns heap size commit for PE32/PE64
template<typename PEClassType>
uint64_t pe<PEClassType>::get_heap_size_commit_64() const
{
	return static_cast<uint64_t>(nt_headers_.OptionalHeader.SizeOfHeapCommit);
}

//Returns heap size reserve for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::get_heap_size_reserve_32() const
{
	return static_cast<uint32_t>(nt_headers_.OptionalHeader.SizeOfHeapReserve);
}

//Returns heap size reserve for PE32/PE64
template<typename PEClassType>
uint64_t pe<PEClassType>::get_heap_size_reserve_64() const
{
	return static_cast<uint64_t>(nt_headers_.OptionalHeader.SizeOfHeapReserve);
}

//Returns stack size commit for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::get_stack_size_commit_32() const
{
	return static_cast<uint32_t>(nt_headers_.OptionalHeader.SizeOfStackCommit);
}

//Returns stack size commit for PE32/PE64
template<typename PEClassType>
uint64_t pe<PEClassType>::get_stack_size_commit_64() const
{
	return static_cast<uint64_t>(nt_headers_.OptionalHeader.SizeOfStackCommit);
}

//Returns stack size reserve for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::get_stack_size_reserve_32() const
{
	return static_cast<uint32_t>(nt_headers_.OptionalHeader.SizeOfStackReserve);
}

//Returns stack size reserve for PE32/PE64
template<typename PEClassType>
uint64_t pe<PEClassType>::get_stack_size_reserve_64() const
{
	return static_cast<uint64_t>(nt_headers_.OptionalHeader.SizeOfStackReserve);
}

//Returns virtual size of image
template<typename PEClassType>
uint32_t pe<PEClassType>::get_size_of_image() const
{
	return nt_headers_.OptionalHeader.SizeOfImage;
}

//Returns number of RVA and sizes (number of DATA_DIRECTORY entries)
template<typename PEClassType>
uint32_t pe<PEClassType>::get_number_of_rvas_and_sizes() const
{
	return nt_headers_.OptionalHeader.NumberOfRvaAndSizes;
}

//Sets number of RVA and sizes (number of DATA_DIRECTORY entries)
template<typename PEClassType>
void pe<PEClassType>::set_number_of_rvas_and_sizes(uint32_t number)
{
	nt_headers_.OptionalHeader.NumberOfRvaAndSizes = number;
}

//Returns PE characteristics
template<typename PEClassType>
uint16_t pe<PEClassType>::get_characteristics() const
{
	return nt_headers_.FileHeader.Characteristics;
}

//Returns checksum of PE file from header
template<typename PEClassType>
uint32_t pe<PEClassType>::get_checksum() const
{
	return nt_headers_.OptionalHeader.CheckSum;
}

//Sets checksum of PE file
template<typename PEClassType>
void pe<PEClassType>::set_checksum(uint32_t checksum)
{
	nt_headers_.OptionalHeader.CheckSum = checksum;
}

//Returns DLL Characteristics
template<typename PEClassType>
uint16_t pe<PEClassType>::get_dll_characteristics() const
{
	return nt_headers_.OptionalHeader.DllCharacteristics;
}

//Returns timestamp of PE file from header
template<typename PEClassType>
uint32_t pe<PEClassType>::get_time_date_stamp() const
{
	return nt_headers_.FileHeader.TimeDateStamp;
}

//Sets timestamp of PE file
template<typename PEClassType>
void pe<PEClassType>::set_time_date_stamp(uint32_t timestamp)
{
	nt_headers_.FileHeader.TimeDateStamp = timestamp;
}

//Sets DLL Characteristics
template<typename PEClassType>
void pe<PEClassType>::set_dll_characteristics(uint16_t characteristics)
{
	nt_headers_.OptionalHeader.DllCharacteristics = characteristics;
}

//Returns Machine field value of PE file from header
template<typename PEClassType>
uint16_t pe<PEClassType>::get_machine() const
{
	return nt_headers_.FileHeader.Machine;
}

//Sets Machine field value of PE file
template<typename PEClassType>
void pe<PEClassType>::set_machine(uint16_t machine)
{
	nt_headers_.FileHeader.Machine = machine;
}

//Sets PE characteristics
template<typename PEClassType>
void pe<PEClassType>::set_characteristics(uint16_t ch)
{
	nt_headers_.FileHeader.Characteristics = ch;
}

//Returns size of headers
template<typename PEClassType>
uint32_t pe<PEClassType>::get_size_of_headers() const
{
	return nt_headers_.OptionalHeader.SizeOfHeaders;
}

//Returns subsystem
template<typename PEClassType>
uint16_t pe<PEClassType>::get_subsystem() const
{
	return nt_headers_.OptionalHeader.Subsystem;
}

//Sets subsystem
template<typename PEClassType>
void pe<PEClassType>::set_subsystem(uint16_t subsystem)
{
	nt_headers_.OptionalHeader.Subsystem = subsystem;
}

//Returns size of optional header
template<typename PEClassType>
uint16_t pe<PEClassType>::get_size_of_optional_header() const
{
	return nt_headers_.FileHeader.SizeOfOptionalHeader;
}

//Returns PE signature
template<typename PEClassType>
uint32_t pe<PEClassType>::get_pe_signature() const
{
	return nt_headers_.Signature;
}

//Returns PE magic value
template<typename PEClassType>
uint32_t pe<PEClassType>::get_magic() const
{
	return nt_headers_.OptionalHeader.Magic;
}

//Sets required operation system version
template<typename PEClassType>
void pe<PEClassType>::set_os_version(uint16_t major, uint16_t minor)
{
	nt_headers_.OptionalHeader.MinorOperatingSystemVersion = minor;
	nt_headers_.OptionalHeader.MajorOperatingSystemVersion = major;
}

//Returns required operation system version (minor word)
template<typename PEClassType>
uint16_t pe<PEClassType>::get_minor_os_version() const
{
	return nt_headers_.OptionalHeader.MinorOperatingSystemVersion;
}

//Returns required operation system version (major word)
template<typename PEClassType>
uint16_t pe<PEClassType>::get_major_os_version() const
{
	return nt_headers_.OptionalHeader.MajorOperatingSystemVersion;
}


//Sets required subsystem version
template<typename PEClassType>
void pe<PEClassType>::set_subsystem_version(uint16_t major, uint16_t minor)
{
	nt_headers_.OptionalHeader.MinorSubsystemVersion = minor;
	nt_headers_.OptionalHeader.MajorSubsystemVersion = major;
}

//Returns required subsystem version (minor word)
template<typename PEClassType>
uint16_t pe<PEClassType>::get_minor_subsystem_version() const
{
	return nt_headers_.OptionalHeader.MinorSubsystemVersion;
}

//Returns required subsystem version (major word)
template<typename PEClassType>
uint16_t pe<PEClassType>::get_major_subsystem_version() const
{
	return nt_headers_.OptionalHeader.MajorSubsystemVersion;
}

//Virtual Address (VA) to Relative Virtual Address (RVA) convertions for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::va_to_rva(uint32_t va, bool bound_check) const
{
	if(bound_check && static_cast<uint64_t>(va) - nt_headers_.OptionalHeader.ImageBase > max_dword)
		throw pe_exception("Incorrect address conversion", pe_exception::incorrect_address_conversion);

	return static_cast<uint32_t>(va - nt_headers_.OptionalHeader.ImageBase);
}

//Virtual Address (VA) to Relative Virtual Address (RVA) convertions for PE32/PE64
template<typename PEClassType>
uint32_t pe<PEClassType>::va_to_rva(uint64_t va, bool bound_check) const
{
	if(bound_check && va - nt_headers_.OptionalHeader.ImageBase > max_dword)
		throw pe_exception("Incorrect address conversion", pe_exception::incorrect_address_conversion);

	return static_cast<uint32_t>(va - nt_headers_.OptionalHeader.ImageBase);
}

//Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32
template<typename PEClassType>
uint32_t pe<PEClassType>::rva_to_va_32(uint32_t rva) const
{
	if(!is_sum_safe(rva, static_cast<uint32_t>(nt_headers_.OptionalHeader.ImageBase)))
		throw pe_exception("Incorrect address conversion", pe_exception::incorrect_address_conversion);

	return static_cast<uint32_t>(rva + nt_headers_.OptionalHeader.ImageBase);
}

//Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32/PE64
template<typename PEClassType>
uint64_t pe<PEClassType>::rva_to_va_64(uint32_t rva) const
{
	return static_cast<uint64_t>(rva) + nt_headers_.OptionalHeader.ImageBase;
}

//Returns number of sections
template<typename PEClassType>
uint16_t pe<PEClassType>::get_number_of_sections() const
{
	return nt_headers_.FileHeader.NumberOfSections;
}

//Sets number of sections
template<typename PEClassType>
void pe<PEClassType>::set_number_of_sections(uint16_t number)
{
	nt_headers_.FileHeader.NumberOfSections = number;
}

//Sets virtual size of image
template<typename PEClassType>
void pe<PEClassType>::set_size_of_image(uint32_t size)
{
	nt_headers_.OptionalHeader.SizeOfImage = size;
}

//Sets size of headers
template<typename PEClassType>
void pe<PEClassType>::set_size_of_headers(uint32_t size)
{
	nt_headers_.OptionalHeader.SizeOfHeaders = size;
}

//Sets size of optional headers
template<typename PEClassType>
void pe<PEClassType>::set_size_of_optional_header(uint16_t size)
{
	nt_headers_.FileHeader.SizeOfOptionalHeader = size;
}

//Returns nt headers data pointer
template<typename PEClassType>
char* pe<PEClassType>::get_nt_headers_ptr()
{
	return reinterpret_cast<char*>(&nt_headers_);
}

//Returns size of NT header
template<typename PEClassType>
uint32_t pe<PEClassType>::get_sizeof_nt_header() const
{
	return sizeof(typename PEClassType::NtHeaders);
}

//Returns size of optional headers
template<typename PEClassType>
uint32_t pe<PEClassType>::get_sizeof_opt_headers() const
{
	return sizeof(typename PEClassType::OptHeaders);
}

//Sets file alignment (no checks)
template<typename PEClassType>
void pe<PEClassType>::set_file_alignment_unchecked(uint32_t alignment) 
{
	nt_headers_.OptionalHeader.FileAlignment = alignment;
}

//Sets base of code
template<typename PEClassType>
void pe<PEClassType>::set_base_of_code(uint32_t base)
{
	nt_headers_.OptionalHeader.BaseOfCode = base;
}

//Returns needed PE magic for PE or PE+ (from template parameters)
template<typename PEClassType>
uint32_t pe<PEClassType>::get_needed_magic() const
{
	return PEClassType::Id;
}

//Returns imported functions list with related libraries info
template<typename PEClassType>
const pe_base::imported_functions_list pe<PEClassType>::get_imported_functions() const
{
	imported_functions_list ret;

	//If image has no imports, return empty array
	if(!has_imports())
		return ret;

	unsigned long current_descriptor_pos = get_directory_rva(image_directory_entry_import);
	//Get first IMAGE_IMPORT_DESCRIPTOR
	image_import_descriptor import_descriptor = section_data_from_rva<image_import_descriptor>(current_descriptor_pos, section_data_virtual, true);

	//Iterate them until we reach zero-element
	//We don't need to check correctness of this, because exception will be thrown
	//inside of loop if we go outsize of section
	while(import_descriptor.Name)
	{
		//Get imported library information
		import_library lib;

		unsigned long max_name_length;
		//Get byte count that we have for library name
		if((max_name_length = section_data_length_from_rva(import_descriptor.Name, import_descriptor.Name, section_data_virtual, true)) < 2)
			throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

		//Get DLL name pointer
		const char* dll_name = section_data_from_rva(import_descriptor.Name, section_data_virtual, true);

		//Check for null-termination
		if(!is_null_terminated(dll_name, max_name_length))
			throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

		//Set library name
		lib.set_name(dll_name);
		//Set library timestamp
		lib.set_timestamp(import_descriptor.TimeDateStamp);
		//Set library RVA to IAT and original IAT
		lib.set_rva_to_iat(import_descriptor.FirstThunk);
		lib.set_rva_to_original_iat(import_descriptor.OriginalFirstThunk);

		//Get RVA to IAT (it must be filled by loader when loading PE)
		uint32_t current_thunk_rva = import_descriptor.FirstThunk;
		typename PEClassType::BaseSize import_address_table = section_data_from_rva<typename PEClassType::BaseSize>(current_thunk_rva, section_data_virtual, true);

		//Get RVA to original IAT (lookup table), which must handle imported functions names
		//Some linkers leave this pointer zero-filled
		//Such image is valid, but it is not possible to restore imported functions names
		//afted image was loaded, because IAT becomes the only one table
		//containing both function names and function RVAs after loading
		uint32_t current_original_thunk_rva = import_descriptor.OriginalFirstThunk;
		typename PEClassType::BaseSize import_lookup_table = current_original_thunk_rva == 0 ? import_address_table : section_data_from_rva<typename PEClassType::BaseSize>(current_original_thunk_rva, section_data_virtual, true);
		if(current_original_thunk_rva == 0)
			current_original_thunk_rva = current_thunk_rva;

		//List all imported functions for current DLL
		if(import_lookup_table != 0 && import_address_table != 0)
		{
			while(true)
			{
				//Imported function description
				imported_function func;

				//Get VA from IAT
				typename PEClassType::BaseSize address = section_data_from_rva<typename PEClassType::BaseSize>(current_thunk_rva, section_data_virtual, true);
				//Move pointer
				current_thunk_rva += sizeof(typename PEClassType::BaseSize);

				//Jump to next DLL if we finished with this one
				if(!address)
					break;

				func.set_iat_va(address);

				//Get VA from original IAT
				typename PEClassType::BaseSize lookup = section_data_from_rva<typename PEClassType::BaseSize>(current_original_thunk_rva, section_data_virtual, true);
				//Move pointer
				current_original_thunk_rva += sizeof(typename PEClassType::BaseSize);

				//Check if function is imported by ordinal
				if((lookup & PEClassType::ImportSnapFlag) != 0)
				{
					//Set function ordinal
					func.set_ordinal(static_cast<uint16_t>(lookup & 0xffff));
				}
				else
				{
					//Get byte count that we have for function name
					if(lookup > static_cast<uint32_t>(-1) - sizeof(uint16_t))
						throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

					//Get maximum available length of function name
					if((max_name_length = section_data_length_from_rva(static_cast<uint32_t>(lookup + sizeof(uint16_t)), static_cast<uint32_t>(lookup + sizeof(uint16_t)), section_data_virtual, true)) < 2)
						throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

					//Get imported function name
					const char* func_name = section_data_from_rva(static_cast<uint32_t>(lookup + sizeof(uint16_t)), section_data_virtual, true);

					//Check for null-termination
					if(!is_null_terminated(func_name, max_name_length))
						throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

					//HINT in import table is ORDINAL in export table
					uint16_t hint = section_data_from_rva<uint16_t>(static_cast<uint32_t>(lookup), section_data_virtual, true);

					//Save hint and name
					func.set_name(func_name);
					func.set_hint(hint);
				}

				//Add function to list
				lib.add_import(func);
			}
		}

		//Check possible overflow
		if(!is_sum_safe(current_descriptor_pos, sizeof(image_import_descriptor)))
			throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

		//Go to next library
		current_descriptor_pos += sizeof(image_import_descriptor);
		import_descriptor = section_data_from_rva<image_import_descriptor>(current_descriptor_pos, section_data_virtual, true);

		//Save import information
		ret.push_back(lib);
	}

	//Return resulting list
	return ret;
}

//Simple import directory rebuilder
//You can get all image imports with get_imported_functions() function
//You can use returned value to, for example, add new imported library with some functions
//to the end of list of imported libraries
//To keep PE file working, rebuild its imports with save_iat_and_original_iat_rvas = true (default)
//Don't add new imported functions to existing imported library entries, because this can cause
//rewriting of some used memory (or other IAT/orig.IAT fields) by system loader
//The safest way is just adding import libraries with functions to the end of imported_functions_list array
template<typename PEClassType>
const pe_base::image_directory pe<PEClassType>::rebuild_imports(const imported_functions_list& imports, section& import_section, const import_rebuilder_settings& import_settings)
{
	//Check that import_section is attached to this PE image
	if(!section_attached(import_section))
		throw pe_exception("Import section must be attached to PE file", pe_exception::section_is_not_attached);

	uint32_t needed_size = 0; //Calculate needed size for import structures and strings
	uint32_t needed_size_for_strings = 0; //Calculate needed size for import strings (library and function names and hints)
	uint32_t size_of_iat = 0; //Size of IAT structures

	needed_size += static_cast<uint32_t>((1 /* ending null descriptor */ + imports.size()) * sizeof(image_import_descriptor));
	
	//Enumerate imported functions
	for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
	{
		needed_size_for_strings += static_cast<uint32_t>((*it).get_name().length() + 1 /* nullbyte */);

		const import_library::imported_list& funcs = (*it).get_imported_functions();

		//IMAGE_THUNK_DATA
		size_of_iat += static_cast<uint32_t>(sizeof(typename PEClassType::BaseSize) * (1 /*ending null */ + funcs.size()));

		//Enumerate all imported functions in library
		for(import_library::imported_list::const_iterator f = funcs.begin(); f != funcs.end(); ++f)
		{
			if((*f).has_name())
				needed_size_for_strings += static_cast<uint32_t>((*f).get_name().length() + 1 /* nullbyte */ + sizeof(uint16_t) /* hint */);
		}
	}

	if(import_settings.build_original_iat())
		needed_size += size_of_iat * 2; //We'll have two similar-sized IATs if we're building original IAT
	else
		needed_size += size_of_iat;

	needed_size += sizeof(typename PEClassType::BaseSize); //Maximum align for IAT and original IAT
	
	//Total needed size for import structures and strings
	needed_size += needed_size_for_strings;

	//Check if import_section is last one. If it's not, check if there's enough place for import data
	if(&import_section != &*(sections_.end() - 1) && 
		(import_section.empty() || align_up(import_section.get_size_of_raw_data(), get_file_alignment()) < needed_size + import_settings.get_offset_from_section_start()))
		throw pe_exception("Insufficient space for import directory", pe_exception::insufficient_space);

	std::string& raw_data = import_section.get_raw_data();

	//This will be done only is image_section is the last section of image or for section with unaligned raw length of data
	if(raw_data.length() < needed_size + import_settings.get_offset_from_section_start())
		raw_data.resize(needed_size + import_settings.get_offset_from_section_start()); //Expand section raw data
	
	uint32_t current_string_pointer = import_settings.get_offset_from_section_start();/* we will paste structures after strings */
	
	//Position for IAT
	uint32_t current_pos_for_iat = align_up(static_cast<uint32_t>(needed_size_for_strings + import_settings.get_offset_from_section_start() + (1 + imports.size()) * sizeof(image_import_descriptor)), sizeof(typename PEClassType::BaseSize));
	//Position for original IAT
	uint32_t current_pos_for_original_iat = current_pos_for_iat + size_of_iat;
	//Position for import descriptors
	uint32_t current_pos_for_descriptors = needed_size_for_strings + import_settings.get_offset_from_section_start();

	//Build imports
	for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
	{
		//Create import descriptor
		image_import_descriptor descr;
		memset(&descr, 0, sizeof(descr));
		descr.TimeDateStamp = (*it).get_timestamp(); //Restore timestamp
		descr.Name = rva_from_section_offset(import_section, current_string_pointer); //Library name RVA

		//If we should save IAT for current import descriptor
		bool save_iats_for_this_descriptor = import_settings.save_iat_and_original_iat_rvas() && (*it).get_rva_to_iat() != 0;
		//If we should write original IAT
		bool write_original_iat = (!save_iats_for_this_descriptor && import_settings.build_original_iat()) || import_settings.fill_missing_original_iats();

		//If we should rewrite saved original IAT for current import descriptor (without changing its position)
		bool rewrite_saved_original_iat = save_iats_for_this_descriptor && import_settings.rewrite_iat_and_original_iat_contents() && import_settings.build_original_iat();
		//If we should rewrite saved IAT for current import descriptor (without changing its position)
		bool rewrite_saved_iat = save_iats_for_this_descriptor && import_settings.rewrite_iat_and_original_iat_contents() && (*it).get_rva_to_iat() != 0;

		//Helper values if we're rewriting existing IAT or orig.IAT
		uint32_t original_first_thunk = 0;
		uint32_t first_thunk = 0;

		if(save_iats_for_this_descriptor)
		{
			//If there's no original IAT and we're asked to rebuild missing original IATs
			if(!(*it).get_rva_to_original_iat() && import_settings.fill_missing_original_iats())
				descr.OriginalFirstThunk = import_settings.build_original_iat() ? rva_from_section_offset(import_section, current_pos_for_original_iat) : 0;
			else
				descr.OriginalFirstThunk = import_settings.build_original_iat() ? (*it).get_rva_to_original_iat() : 0;
			
			descr.FirstThunk = (*it).get_rva_to_iat();

			original_first_thunk = descr.OriginalFirstThunk;
			first_thunk = descr.FirstThunk;

			if(rewrite_saved_original_iat)
			{
				if((*it).get_rva_to_original_iat())
					write_original_iat = true;
				else
					rewrite_saved_original_iat = false;
			}

			if(rewrite_saved_iat)
				save_iats_for_this_descriptor = false;
		}
		else
		{
			//We are creating new IAT and original IAT (if needed)
			descr.OriginalFirstThunk = import_settings.build_original_iat() ? rva_from_section_offset(import_section, current_pos_for_original_iat) : 0;
			descr.FirstThunk = rva_from_section_offset(import_section, current_pos_for_iat);
		}
		
		//Save import descriptor
		memcpy(&raw_data[current_pos_for_descriptors], &descr, sizeof(descr));
		current_pos_for_descriptors += sizeof(descr);

		//Save library name
		memcpy(&raw_data[current_string_pointer], (*it).get_name().c_str(), (*it).get_name().length() + 1 /* nullbyte */);
		current_string_pointer += static_cast<uint32_t>((*it).get_name().length() + 1 /* nullbyte */);
		
		//List all imported functions
		const import_library::imported_list& funcs = (*it).get_imported_functions();
		for(import_library::imported_list::const_iterator f = funcs.begin(); f != funcs.end(); ++f)
		{
			if((*f).has_name()) //If function is imported by name
			{
				//Get RVA of IMAGE_IMPORT_BY_NAME
				typename PEClassType::BaseSize rva_of_named_import = rva_from_section_offset(import_section, current_string_pointer);

				if(!save_iats_for_this_descriptor)
				{
					if(write_original_iat)
					{
						//We're creating original IATs - so we can write to IAT saved VA (because IMAGE_IMPORT_BY_NAME will be read
						//by PE loader from original IAT)
						typename PEClassType::BaseSize iat_value = static_cast<typename PEClassType::BaseSize>((*f).get_iat_va());

						if(rewrite_saved_iat)
						{
							if(section_data_length_from_rva(first_thunk, first_thunk, section_data_raw, true) <= sizeof(iat_value))
								throw pe_exception("Insufficient space inside initial IAT", pe_exception::insufficient_space);

							memcpy(section_data_from_rva(first_thunk, true), &iat_value, sizeof(iat_value));

							first_thunk += sizeof(iat_value);
						}
						else
						{
							memcpy(&raw_data[current_pos_for_iat], &iat_value, sizeof(iat_value));
							current_pos_for_iat += sizeof(rva_of_named_import);
						}
					}
					else
					{
						//Else - write to IAT RVA of IMAGE_IMPORT_BY_NAME
						if(rewrite_saved_iat)
						{
							if(section_data_length_from_rva(first_thunk, first_thunk, section_data_raw, true) <= sizeof(rva_of_named_import))
								throw pe_exception("Insufficient space inside initial IAT", pe_exception::insufficient_space);

							memcpy(section_data_from_rva(first_thunk, true), &rva_of_named_import, sizeof(rva_of_named_import));

							first_thunk += sizeof(rva_of_named_import);
						}
						else
						{
							memcpy(&raw_data[current_pos_for_iat], &rva_of_named_import, sizeof(rva_of_named_import));
							current_pos_for_iat += sizeof(rva_of_named_import);
						}
					}
				}

				if(write_original_iat)
				{
					if(rewrite_saved_original_iat)
					{
						if(section_data_length_from_rva(original_first_thunk, original_first_thunk, section_data_raw, true) <= sizeof(rva_of_named_import))
							throw pe_exception("Insufficient space inside initial original IAT", pe_exception::insufficient_space);

						memcpy(section_data_from_rva(original_first_thunk, true), &rva_of_named_import, sizeof(rva_of_named_import));

						original_first_thunk += sizeof(rva_of_named_import);
					}
					else
					{
						//We're creating original IATs
						memcpy(&raw_data[current_pos_for_original_iat], &rva_of_named_import, sizeof(rva_of_named_import));
						current_pos_for_original_iat += sizeof(rva_of_named_import);
					}
				}

				//Write IMAGE_IMPORT_BY_NAME (WORD hint + string function name)
				uint16_t hint = (*f).get_hint();
				memcpy(&raw_data[current_string_pointer], &hint, sizeof(hint));
				memcpy(&raw_data[current_string_pointer + sizeof(uint16_t)], (*f).get_name().c_str(), (*f).get_name().length() + 1 /* nullbyte */);
				current_string_pointer += static_cast<uint32_t>((*f).get_name().length() + 1 /* nullbyte */ + sizeof(uint16_t) /* hint */);
			}
			else //Function is imported by ordinal
			{
				uint16_t ordinal = (*f).get_ordinal();
				typename PEClassType::BaseSize thunk_value = ordinal;
				thunk_value |= PEClassType::ImportSnapFlag; //Imported by ordinal

				if(!save_iats_for_this_descriptor)
				{
					if(write_original_iat)
					{
						//We're creating original IATs - so we can wtire to IAT saved VA (because ordinal will be read
						//by PE loader from original IAT)
						typename PEClassType::BaseSize iat_value = static_cast<typename PEClassType::BaseSize>((*f).get_iat_va());
						if(rewrite_saved_iat)
						{
							if(section_data_length_from_rva(first_thunk, first_thunk, section_data_raw, true) <= sizeof(iat_value))
								throw pe_exception("Insufficient space inside initial IAT", pe_exception::insufficient_space);

							memcpy(section_data_from_rva(first_thunk, true), &iat_value, sizeof(iat_value));

							first_thunk += sizeof(iat_value);
						}
						else
						{
							memcpy(&raw_data[current_pos_for_iat], &iat_value, sizeof(iat_value));
							current_pos_for_iat += sizeof(thunk_value);
						}
					}
					else
					{
						//Else - write ordinal to IAT
						if(rewrite_saved_iat)
						{
							if(section_data_length_from_rva(first_thunk, first_thunk, section_data_raw, true) <= sizeof(thunk_value))
								throw pe_exception("Insufficient space inside initial IAT", pe_exception::insufficient_space);

							memcpy(section_data_from_rva(first_thunk, true), &thunk_value, sizeof(thunk_value));

							first_thunk += sizeof(thunk_value);
						}
						else
						{
							memcpy(&raw_data[current_pos_for_iat], &thunk_value, sizeof(thunk_value));
						}
					}
				}

				//We're writing ordinal to original IAT slot
				if(write_original_iat)
				{
					if(rewrite_saved_original_iat)
					{
						if(section_data_length_from_rva(original_first_thunk, original_first_thunk, section_data_raw, true) <= sizeof(thunk_value))
							throw pe_exception("Insufficient space inside initial original IAT", pe_exception::insufficient_space);

						memcpy(section_data_from_rva(original_first_thunk, true), &thunk_value, sizeof(thunk_value));

						original_first_thunk += sizeof(thunk_value);
					}
					else
					{
						memcpy(&raw_data[current_pos_for_original_iat], &thunk_value, sizeof(thunk_value));
						current_pos_for_original_iat += sizeof(thunk_value);
					}
				}
			}
		}

		if(!save_iats_for_this_descriptor)
		{
			//Ending null thunks
			typename PEClassType::BaseSize thunk_value = 0;

			if(rewrite_saved_iat)
			{
				if(section_data_length_from_rva(first_thunk, first_thunk, section_data_raw, true) <= sizeof(thunk_value))
					throw pe_exception("Insufficient space inside initial IAT", pe_exception::insufficient_space);

				memcpy(section_data_from_rva(first_thunk, true), &thunk_value, sizeof(thunk_value));

				first_thunk += sizeof(thunk_value);
			}
			else
			{
				memcpy(&raw_data[current_pos_for_iat], &thunk_value, sizeof(thunk_value));
				current_pos_for_iat += sizeof(thunk_value);
			}
		}

		if(write_original_iat)
		{
			//Ending null thunks
			typename PEClassType::BaseSize thunk_value = 0;

			if(rewrite_saved_original_iat)
			{
				if(section_data_length_from_rva(original_first_thunk, original_first_thunk, section_data_raw, true) <= sizeof(thunk_value))
					throw pe_exception("Insufficient space inside initial original IAT", pe_exception::insufficient_space);

				memcpy(section_data_from_rva(original_first_thunk, true), &thunk_value, sizeof(thunk_value));

				original_first_thunk += sizeof(thunk_value);
			}
			else
			{
				memcpy(&raw_data[current_pos_for_original_iat], &thunk_value, sizeof(thunk_value));
				current_pos_for_original_iat += sizeof(thunk_value);
			}
		}
	}

	{
		//Null ending descriptor
		image_import_descriptor descr;
		memset(&descr, 0, sizeof(descr));
		memcpy(&raw_data[current_pos_for_descriptors], &descr, sizeof(descr));
	}

	//Strip data a little, if we saved some place
	//We're allocating more space than needed, if present original IAT and IAT are saved
	raw_data.resize(current_pos_for_original_iat);

	//Adjust section raw and virtual sizes
	recalculate_section_sizes(import_section, import_settings.auto_strip_last_section_enabled());

	//Return information about rebuilt import directory
	image_directory ret(rva_from_section_offset(import_section, import_settings.get_offset_from_section_start() + needed_size_for_strings), needed_size - needed_size_for_strings);

	//If auto-rewrite of PE headers is required
	if(import_settings.auto_set_to_pe_headers())
	{
		set_directory_rva(image_directory_entry_import, ret.get_rva());
		set_directory_size(image_directory_entry_import, ret.get_size());

		//If we are requested to zero IMAGE_DIRECTORY_ENTRY_IAT also
		if(import_settings.zero_directory_entry_iat())
		{
			set_directory_rva(image_directory_entry_iat, 0);
			set_directory_size(image_directory_entry_iat, 0);
		}
	}

	return ret;
}

//Get TLS info
//If image does not have TLS, throws an exception
template<typename PEClassType>
const pe_base::tls_info pe<PEClassType>::get_tls_info() const
{
	tls_info ret;

	//If there's no TLS directory, throw an exception
	if(!has_tls())
		throw pe_exception("Image does not have TLS directory", pe_exception::directory_does_not_exist);

	//Get TLS directory data
	typename PEClassType::TLSStruct tls_directory_data = section_data_from_rva<typename PEClassType::TLSStruct>(get_directory_rva(image_directory_entry_tls), section_data_virtual, true);

	//Check data addresses
	if(tls_directory_data.EndAddressOfRawData == tls_directory_data.StartAddressOfRawData)
	{
		try
		{
			va_to_rva(static_cast<typename PEClassType::BaseSize>(tls_directory_data.EndAddressOfRawData));
		}
		catch(const pe_exception&)
		{
			//Fix addressess on incorrect conversion
			tls_directory_data.EndAddressOfRawData = tls_directory_data.StartAddressOfRawData = 0;
		}
	}

	if(tls_directory_data.StartAddressOfRawData &&
		section_data_length_from_va(static_cast<typename PEClassType::BaseSize>(tls_directory_data.StartAddressOfRawData), static_cast<typename PEClassType::BaseSize>(tls_directory_data.StartAddressOfRawData), section_data_virtual, true)
		< (tls_directory_data.EndAddressOfRawData - tls_directory_data.StartAddressOfRawData))
		throw pe_exception("Incorrect TLS directory", pe_exception::incorrect_tls_directory);

	//Fill TLS info
	//VAs are not checked
	ret.set_raw_data_start_rva(tls_directory_data.StartAddressOfRawData ? va_to_rva(static_cast<typename PEClassType::BaseSize>(tls_directory_data.StartAddressOfRawData)) : 0);
	ret.set_raw_data_end_rva(tls_directory_data.EndAddressOfRawData ? va_to_rva(static_cast<typename PEClassType::BaseSize>(tls_directory_data.EndAddressOfRawData)) : 0);
	ret.set_index_rva(tls_directory_data.AddressOfIndex ? va_to_rva(static_cast<typename PEClassType::BaseSize>(tls_directory_data.AddressOfIndex)) : 0);
	ret.set_callbacks_rva(tls_directory_data.AddressOfCallBacks ? va_to_rva(static_cast<typename PEClassType::BaseSize>(tls_directory_data.AddressOfCallBacks)) : 0);
	ret.set_size_of_zero_fill(tls_directory_data.SizeOfZeroFill);
	ret.set_characteristics(tls_directory_data.Characteristics);

	if(tls_directory_data.StartAddressOfRawData && tls_directory_data.StartAddressOfRawData != tls_directory_data.EndAddressOfRawData)
	{
		//Read and save TLS RAW data
		ret.set_raw_data(std::string(
			section_data_from_va(static_cast<typename PEClassType::BaseSize>(tls_directory_data.StartAddressOfRawData), section_data_virtual, true),
			static_cast<uint32_t>(tls_directory_data.EndAddressOfRawData - tls_directory_data.StartAddressOfRawData)));
	}

	//If file has TLS callbacks
	if(ret.get_callbacks_rva())
	{
		//Read callbacks VAs
		uint32_t current_tls_callback = 0;

		while(true)
		{
			//Read TLS callback VA
			typename PEClassType::BaseSize va = section_data_from_va<typename PEClassType::BaseSize>(static_cast<typename PEClassType::BaseSize>(tls_directory_data.AddressOfCallBacks + current_tls_callback), section_data_virtual, true);
			if(va == 0)
				break;

			//Save it
			ret.add_tls_callback(va_to_rva(va, false));

			//Move to next callback VA
			current_tls_callback += sizeof(va);
		}
	}

	return ret;
}

//Rebuilder of TLS structures
//If write_tls_callbacks = true, TLS callbacks VAs will be written to their place
//If write_tls_data = true, TLS data will be written to its place
//If you have chosen to rewrite raw data, only (EndAddressOfRawData - StartAddressOfRawData) bytes will be written, not the full length of string
//representing raw data content
//auto_strip_last_section - if true and TLS are placed in the last section, it will be automatically stripped
//Note/TODO: TLS Callbacks array is not DWORD-aligned (seems to work on WinXP - Win7)
template<typename PEClassType>
const pe_base::image_directory pe<PEClassType>::rebuild_tls(const tls_info& info, section& tls_section, uint32_t offset_from_section_start, bool write_tls_callbacks, bool write_tls_data, tls_data_expand_type expand, bool save_to_pe_header, bool auto_strip_last_section)
{
	//Check that tls_section is attached to this PE image
	if(!section_attached(tls_section))
		throw pe_exception("TLS section must be attached to PE file", pe_exception::section_is_not_attached);
	
	uint32_t tls_data_pos = align_up(offset_from_section_start, sizeof(typename PEClassType::BaseSize));
	uint32_t needed_size = sizeof(typename PEClassType::TLSStruct) + (tls_data_pos - offset_from_section_start); //Calculate needed size for TLS table
	
	//Check if tls_section is last one. If it's not, check if there's enough place for TLS data
	if(&tls_section != &*(sections_.end() - 1) && 
		(tls_section.empty() || align_up(tls_section.get_size_of_raw_data(), get_file_alignment()) < needed_size + offset_from_section_start))
		throw pe_exception("Insufficient space for TLS directory", pe_exception::insufficient_space);

	//Check raw data positions
	if(info.get_raw_data_end_rva() < info.get_raw_data_start_rva() || info.get_index_rva() == 0)
		throw pe_exception("Incorrect TLS directory", pe_exception::incorrect_tls_directory);

	std::string& raw_data = tls_section.get_raw_data();

	//This will be done only is tls_section is the last section of image or for section with unaligned raw length of data
	if(raw_data.length() < needed_size + offset_from_section_start)
		raw_data.resize(needed_size + offset_from_section_start); //Expand section raw data

	//Create and fill TLS structure
	typename PEClassType::TLSStruct tls_struct = {0};
	
	typename PEClassType::BaseSize va;
	if(info.get_raw_data_start_rva())
	{
		rva_to_va(info.get_raw_data_start_rva(), va);
		tls_struct.StartAddressOfRawData = va;
		tls_struct.SizeOfZeroFill = info.get_size_of_zero_fill();
	}

	if(info.get_raw_data_end_rva())
	{
		rva_to_va(info.get_raw_data_end_rva(), va);
		tls_struct.EndAddressOfRawData = va;
	}

	rva_to_va(info.get_index_rva(), va);
	tls_struct.AddressOfIndex = va;

	if(info.get_callbacks_rva())
	{
		rva_to_va(info.get_callbacks_rva(), va);
		tls_struct.AddressOfCallBacks = va;
	}

	tls_struct.Characteristics = info.get_characteristics();

	//Save TLS structure
	memcpy(&raw_data[tls_data_pos], &tls_struct, sizeof(tls_struct));

	//If we are asked to rewrite TLS raw data
	if(write_tls_data && info.get_raw_data_start_rva() && info.get_raw_data_start_rva() != info.get_raw_data_end_rva())
	{
		try
		{
			//Check if we're going to write TLS raw data to an existing section (not to PE headers)
			section& raw_data_section = section_from_rva(info.get_raw_data_start_rva());
			expand_section(raw_data_section, info.get_raw_data_start_rva(), info.get_raw_data_end_rva() - info.get_raw_data_start_rva(), expand == tls_data_expand_raw ? expand_section_raw : expand_section_virtual);
		}
		catch(const pe_exception&)
		{
			//If no section is presented by StartAddressOfRawData, just go to next step
		}

		unsigned long write_raw_data_size = info.get_raw_data_end_rva() - info.get_raw_data_start_rva();
		unsigned long available_raw_length = 0;

		//Check if there's enough RAW space to write raw TLS data...
		if((available_raw_length = section_data_length_from_rva(info.get_raw_data_start_rva(), info.get_raw_data_start_rva(), section_data_raw, true))
			< info.get_raw_data_end_rva() - info.get_raw_data_start_rva())
		{
			//Check if there's enough virtual space for it...
			if(section_data_length_from_rva(info.get_raw_data_start_rva(), info.get_raw_data_start_rva(), section_data_virtual, true)
				< info.get_raw_data_end_rva() - info.get_raw_data_start_rva())
				throw pe_exception("Insufficient space for TLS raw data", pe_exception::insufficient_space);
			else
				write_raw_data_size = available_raw_length; //We'll write just a part of full raw data
		}

		//Write raw TLS data, if any
		if(write_raw_data_size != 0)
			memcpy(section_data_from_rva(info.get_raw_data_start_rva(), true), info.get_raw_data().data(), write_raw_data_size);
	}

	//If we are asked to rewrite TLS callbacks addresses
	if(write_tls_callbacks && info.get_callbacks_rva())
	{
		unsigned long needed_callback_size = static_cast<unsigned long>((info.get_tls_callbacks().size() + 1 /* last null element */) * sizeof(typename PEClassType::BaseSize));

		try
		{
			//Check if we're going to write TLS callbacks VAs to an existing section (not to PE headers)
			section& raw_data_section = section_from_rva(info.get_callbacks_rva());
			expand_section(raw_data_section, info.get_callbacks_rva(), needed_callback_size, expand_section_raw);
		}
		catch(const pe_exception&)
		{
			//If no section is presented by RVA of callbacks, just go to next step
		}

		//Check if there's enough space to write callbacks TLS data...
		if(section_data_length_from_rva(info.get_callbacks_rva(), info.get_callbacks_rva(), section_data_raw, true)
			< needed_callback_size - sizeof(typename PEClassType::BaseSize) /* last zero element can be virtual only */)
			throw pe_exception("Insufficient space for TLS callbacks data", pe_exception::insufficient_space);
		
		if(section_data_length_from_rva(info.get_callbacks_rva(), info.get_callbacks_rva(), section_data_virtual, true)
			< needed_callback_size /* check here full virtual data length available */)
			throw pe_exception("Insufficient space for TLS callbacks data", pe_exception::insufficient_space);

		std::vector<typename PEClassType::BaseSize> callbacks_virtual_addresses;
		callbacks_virtual_addresses.reserve(info.get_tls_callbacks().size() + 1 /* last null element */);

		//Convert TLS RVAs to VAs
		for(tls_info::tls_callback_list::const_iterator it = info.get_tls_callbacks().begin(); it != info.get_tls_callbacks().end(); ++it)
		{
			typename PEClassType::BaseSize cb_va = 0;
			rva_to_va(*it, cb_va);
			callbacks_virtual_addresses.push_back(cb_va);
		}

		//Ending null element
		callbacks_virtual_addresses.push_back(0);

		//Write callbacks TLS data
		memcpy(section_data_from_rva(info.get_callbacks_rva(), true), &callbacks_virtual_addresses[0], needed_callback_size);
	}
	
	//Adjust section raw and virtual sizes
	recalculate_section_sizes(tls_section, auto_strip_last_section);

	image_directory ret(rva_from_section_offset(tls_section, tls_data_pos), needed_size);

	//If auto-rewrite of PE headers is required
	if(save_to_pe_header)
	{
		set_directory_rva(image_directory_entry_tls, ret.get_rva());
		set_directory_size(image_directory_entry_tls, ret.get_size());
	}

	return ret;
}


//Returns image config info
//If image does not have config info, throws an exception
template<typename PEClassType>
const pe_base::image_config_info pe<PEClassType>::get_image_config() const
{
	//Check if image has config directory
	if(!has_config())
		throw pe_exception("Image does not have load config directory", pe_exception::directory_does_not_exist);

	//Get load config structure
	typename PEClassType::ConfigStruct config_info = section_data_from_rva<typename PEClassType::ConfigStruct>(get_directory_rva(image_directory_entry_load_config), section_data_virtual);

	//Check size of config directory
	if(config_info.Size != sizeof(config_info))
		throw pe_exception("Incorrect (or old) load config directory", pe_exception::incorrect_config_directory);

	//Fill return structure
	image_config_info ret(config_info);

	//Check possible overflow
	if(config_info.SEHandlerCount >= max_dword / sizeof(uint32_t)
		|| config_info.SEHandlerTable >= static_cast<typename PEClassType::BaseSize>(-1) - config_info.SEHandlerCount * sizeof(uint32_t))
		throw pe_exception("Incorrect load config directory", pe_exception::incorrect_config_directory);

	//Read sorted SE handler RVA list (if any)
	for(typename PEClassType::BaseSize i = 0; i != config_info.SEHandlerCount; ++i)
		ret.add_se_handler_rva(section_data_from_va<uint32_t>(static_cast<typename PEClassType::BaseSize>(config_info.SEHandlerTable + i * sizeof(uint32_t))));

	if(config_info.LockPrefixTable)
	{
		//Read Lock Prefix VA list (if any)
		unsigned long current = 0;
		while(true)
		{
			typename PEClassType::BaseSize lock_prefix_va = section_data_from_va<typename PEClassType::BaseSize>(static_cast<typename PEClassType::BaseSize>(config_info.LockPrefixTable + current * sizeof(typename PEClassType::BaseSize)));
			if(!lock_prefix_va)
				break;

			ret.add_lock_prefix_rva(va_to_rva(lock_prefix_va));

			++current;
		}
	}

	return ret;
}

//Image config directory rebuilder
//auto_strip_last_section - if true and TLS are placed in the last section, it will be automatically stripped
//If write_se_handlers = true, SE Handlers list will be written just after image config directory structure
//If write_lock_prefixes = true, Lock Prefixes address list will be written just after image config directory structure
template<typename PEClassType>
const pe_base::image_directory pe<PEClassType>::rebuild_image_config(const image_config_info& info, section& image_config_section, uint32_t offset_from_section_start, bool write_se_handlers, bool write_lock_prefixes, bool save_to_pe_header, bool auto_strip_last_section)
{
	//Check that image_config_section is attached to this PE image
	if(!section_attached(image_config_section))
		throw pe_exception("Image Config section must be attached to PE file", pe_exception::section_is_not_attached);
	
	uint32_t alignment = align_up(offset_from_section_start, sizeof(typename PEClassType::BaseSize)) - offset_from_section_start;

	uint32_t needed_size = sizeof(typename PEClassType::ConfigStruct) + alignment; //Calculate needed size for Image Config table

	uint32_t current_pos_of_se_handlers = 0;
	uint32_t current_pos_of_lock_prefixes = 0;
	
	if(write_se_handlers)
	{
		current_pos_of_se_handlers = needed_size + offset_from_section_start;
		needed_size += static_cast<uint32_t>(info.get_se_handler_rvas().size()) * sizeof(uint32_t); //RVAs of SE Handlers
	}
	
	if(write_lock_prefixes)
	{
		current_pos_of_lock_prefixes = needed_size + offset_from_section_start;
		needed_size += static_cast<uint32_t>((info.get_lock_prefix_rvas().size() + 1) * sizeof(typename PEClassType::BaseSize)); //VAs of Lock Prefixes (and ending null element)
	}

	//Check if image_config_section is last one. If it's not, check if there's enough place for Image Config data
	if(&image_config_section != &*(sections_.end() - 1) && 
		(image_config_section.empty() || align_up(image_config_section.get_size_of_raw_data(), get_file_alignment()) < needed_size + offset_from_section_start))
		throw pe_exception("Insufficient space for TLS directory", pe_exception::insufficient_space);

	std::string& raw_data = image_config_section.get_raw_data();

	//This will be done only is tls_section is the last section of image or for section with unaligned raw length of data
	if(raw_data.length() < needed_size + offset_from_section_start)
		raw_data.resize(needed_size + offset_from_section_start); //Expand section raw data

	uint32_t image_config_data_pos = offset_from_section_start + alignment;

	//Create and fill Image Config structure
	typename PEClassType::ConfigStruct image_config_section_struct = {0};
	image_config_section_struct.Size = sizeof(image_config_section_struct);
	image_config_section_struct.TimeDateStamp = info.get_time_stamp();
	image_config_section_struct.MajorVersion = info.get_major_version();
	image_config_section_struct.MinorVersion = info.get_minor_version();
	image_config_section_struct.GlobalFlagsClear = info.get_global_flags_clear();
	image_config_section_struct.GlobalFlagsSet = info.get_global_flags_set();
	image_config_section_struct.CriticalSectionDefaultTimeout = info.get_critical_section_default_timeout();
	image_config_section_struct.DeCommitFreeBlockThreshold = static_cast<typename PEClassType::BaseSize>(info.get_decommit_free_block_threshold());
	image_config_section_struct.DeCommitTotalFreeThreshold = static_cast<typename PEClassType::BaseSize>(info.get_decommit_total_free_threshold());
	image_config_section_struct.MaximumAllocationSize = static_cast<typename PEClassType::BaseSize>(info.get_max_allocation_size());
	image_config_section_struct.VirtualMemoryThreshold = static_cast<typename PEClassType::BaseSize>(info.get_virtual_memory_threshold());
	image_config_section_struct.ProcessHeapFlags = info.get_process_heap_flags();
	image_config_section_struct.ProcessAffinityMask = static_cast<typename PEClassType::BaseSize>(info.get_process_affinity_mask());
	image_config_section_struct.CSDVersion = info.get_service_pack_version();
	image_config_section_struct.EditList = static_cast<typename PEClassType::BaseSize>(info.get_edit_list_va());
	image_config_section_struct.SecurityCookie = static_cast<typename PEClassType::BaseSize>(info.get_security_cookie_va());
	image_config_section_struct.SEHandlerCount = static_cast<typename PEClassType::BaseSize>(info.get_se_handler_rvas().size());
	

	if(write_se_handlers)
	{
		if(info.get_se_handler_rvas().empty())
		{
			write_se_handlers = false;
			image_config_section_struct.SEHandlerTable = 0;
		}
		else
		{
			typename PEClassType::BaseSize va;
			rva_to_va(rva_from_section_offset(image_config_section, current_pos_of_se_handlers), va);
			image_config_section_struct.SEHandlerTable = va;
		}
	}
	else
	{
		image_config_section_struct.SEHandlerTable = static_cast<typename PEClassType::BaseSize>(info.get_se_handler_table_va());
	}

	if(write_lock_prefixes)
	{
		if(info.get_lock_prefix_rvas().empty())
		{
			write_lock_prefixes = false;
			image_config_section_struct.LockPrefixTable = 0;
		}
		else
		{
			typename PEClassType::BaseSize va;
			rva_to_va(rva_from_section_offset(image_config_section, current_pos_of_lock_prefixes), va);
			image_config_section_struct.LockPrefixTable = va;
		}
	}
	else
	{
		image_config_section_struct.LockPrefixTable = static_cast<typename PEClassType::BaseSize>(info.get_lock_prefix_table_va());
	}

	//Write image config section
	memcpy(&raw_data[image_config_data_pos], &image_config_section_struct, sizeof(image_config_section_struct));

	if(write_se_handlers)
	{
		//Sort SE Handlers list
		image_config_info::se_handler_list sorted_list = info.get_se_handler_rvas();
		std::sort(sorted_list.begin(), sorted_list.end());

		//Write SE Handlers table
		for(image_config_info::se_handler_list::const_iterator it = sorted_list.begin(); it != sorted_list.end(); ++it)
		{
			uint32_t se_handler_rva = *it;
			memcpy(&raw_data[current_pos_of_se_handlers], &se_handler_rva, sizeof(se_handler_rva));
			current_pos_of_se_handlers += sizeof(se_handler_rva);
		}
	}

	if(write_lock_prefixes)
	{
		//Write Lock Prefixes VA list
		for(image_config_info::lock_prefix_rva_list::const_iterator it = info.get_lock_prefix_rvas().begin(); it != info.get_lock_prefix_rvas().end(); ++it)
		{
			typename PEClassType::BaseSize lock_prefix_va;
			rva_to_va(*it, lock_prefix_va);
			memcpy(&raw_data[current_pos_of_lock_prefixes], &lock_prefix_va, sizeof(lock_prefix_va));
			current_pos_of_lock_prefixes += sizeof(lock_prefix_va);
		}

		{
			//Ending null VA
			typename PEClassType::BaseSize lock_prefix_va = 0;
			memcpy(&raw_data[current_pos_of_lock_prefixes], &lock_prefix_va, sizeof(lock_prefix_va));
		}
	}

	//Adjust section raw and virtual sizes
	recalculate_section_sizes(image_config_section, auto_strip_last_section);

	image_directory ret(rva_from_section_offset(image_config_section, image_config_data_pos), sizeof(typename PEClassType::ConfigStruct));

	//If auto-rewrite of PE headers is required
	if(save_to_pe_header)
	{
		set_directory_rva(image_directory_entry_load_config, ret.get_rva());
		set_directory_size(image_directory_entry_load_config, ret.get_size());
	}

	return ret;
}


//RELOCATIONS
//Recalculates image base with the help of relocation tables
//Recalculates VAs of DWORDS/QWORDS in image according to relocations
//Notice: if you move some critical structures like TLS, image relocations will not fix new
//positions of TLS VAs. Instead, some bytes that now doesn't belong to TLS will be fixed.
//It is recommended to rebase image in the very beginning and move all structures afterwards.
template<typename PEClassType>
void pe<PEClassType>::rebase_image(const relocation_table_list& tables, uint64_t new_base)
{
	//Get current image base value
	typename PEClassType::BaseSize image_base;
	get_image_base(image_base);

	//ImageBase difference
	typename PEClassType::BaseSize base_rel = static_cast<typename PEClassType::BaseSize>(static_cast<int32_t>(new_base) - image_base);

	//We need to fix addresses from relocation tables
	//Enumerate relocation tables
	for(relocation_table_list::const_iterator it = tables.begin(); it != tables.end(); ++it)
	{
		const relocation_table::relocation_list& relocs = (*it).get_relocations();

		uint32_t base_rva = (*it).get_rva();

		//Enumerate relocations
		for(relocation_table::relocation_list::const_iterator rel = relocs.begin(); rel != relocs.end(); ++rel)
		{
			//Recalculate value by RVA and rewrite it
			uint32_t current_rva = base_rva + (*rel).get_rva();
			typename PEClassType::BaseSize value = section_data_from_rva<typename PEClassType::BaseSize>(current_rva, section_data_raw, true);
			value += base_rel;
			memcpy(section_data_from_rva(current_rva, true), &value, sizeof(value));
		}
	}

	//Finally, save new image base
	set_image_base_64(new_base);
}

//Returns PE type of this image
template<typename PEClassType>
pe_base::pe_type pe<PEClassType>::get_pe_type() const
{
	return PEClassType::Id == image_nt_optional_hdr32_magic ? pe_type_32 : pe_type_64;
}

//Two used instantiations for PE32 (PE) and PE64 (PE+)
template class pe<pe_class_type<image_nt_headers32, image_optional_header32, image_nt_optional_hdr32_magic, uint32_t, image_ordinal_flag32, image_tls_directory32, image_load_config_directory32> >;
template class pe<pe_class_type<image_nt_headers64, image_optional_header64, image_nt_optional_hdr64_magic, uint64_t, image_ordinal_flag64, image_tls_directory64, image_load_config_directory64> >;
}
