#include "pe_32_64.h"

//Constructor from istream
template<typename PEClassType>
pe<PEClassType>::pe(std::istream& file, bool read_bound_import_raw_data, bool read_debug_raw_data)
{
	//Save istream state
	std::ios_base::iostate state = file.exceptions();
	std::streamoff old_offset = file.tellg();

	try
	{
		file.exceptions(0);
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
bool pe<PEClassType>::directory_exists(unsigned long id) const
{
	return (nt_headers_.OptionalHeader.NumberOfRvaAndSizes - 1) >= id &&
		nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress;
}

//Removes directory
template<typename PEClassType>
void pe<PEClassType>::remove_directory(unsigned long id)
{
	if(directory_exists(id))
	{
		nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress = 0;
		nt_headers_.OptionalHeader.DataDirectory[id].Size = 0;

		if(id == IMAGE_DIRECTORY_ENTRY_BASERELOC)
			set_characteristics_flags(IMAGE_FILE_RELOCS_STRIPPED);
		else if(id == IMAGE_DIRECTORY_ENTRY_EXPORT)
			clear_characteristics_flags(IMAGE_FILE_DLL);
	}
}

//Returns directory RVA
template<typename PEClassType>
DWORD pe<PEClassType>::get_directory_rva(unsigned long id) const
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	return nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress;
}

//Returns directory size
template<typename PEClassType>
void pe<PEClassType>::set_directory_rva(unsigned long id, DWORD va)
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	nt_headers_.OptionalHeader.DataDirectory[id].VirtualAddress = va;
}

template<typename PEClassType>
void pe<PEClassType>::set_directory_size(unsigned long id, DWORD size)
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	nt_headers_.OptionalHeader.DataDirectory[id].Size = size;
}

//Returns directory size
template<typename PEClassType>
DWORD pe<PEClassType>::get_directory_size(unsigned long id) const
{
	//Check if directory exists
	if(nt_headers_.OptionalHeader.NumberOfRvaAndSizes <= id)
		throw pe_exception("Specified directory does not exist", pe_exception::directory_does_not_exist);

	return nt_headers_.OptionalHeader.DataDirectory[id].Size;
}

//Strips only zero DATA_DIRECTORY entries to count = min_count
//Returns resulting number of data directories
template<typename PEClassType>
unsigned long pe<PEClassType>::strip_data_directories(long min_count)
{
	long i = nt_headers_.OptionalHeader.NumberOfRvaAndSizes - 1;

	//Enumerate all data directories from the end
	for(; i >= 0; i--)
	{
		//If directory exists (and it is not IMAGE_DIRECTORY_ENTRY_IAT, we can strip it anyway), break
		if(nt_headers_.OptionalHeader.DataDirectory[i].VirtualAddress && i != IMAGE_DIRECTORY_ENTRY_IAT)
			break;

		if(i <= min_count - 2)
			break;
	}

	if(i == IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1)
		return IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	//Return new number of data directories
	return nt_headers_.OptionalHeader.NumberOfRvaAndSizes = i + 1;
}

//Returns image base for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::get_image_base_32() const
{
	return static_cast<DWORD>(nt_headers_.OptionalHeader.ImageBase);
}

//Returns image base for PE32/PE64
template<typename PEClassType>
ULONGLONG pe<PEClassType>::get_image_base_64() const
{
	return static_cast<ULONGLONG>(nt_headers_.OptionalHeader.ImageBase);
}

//Sets new image base
template<typename PEClassType>
void pe<PEClassType>::set_image_base(DWORD base)
{
	nt_headers_.OptionalHeader.ImageBase = base;
}

//Sets new image base
template<typename PEClassType>
void pe<PEClassType>::set_image_base_64(ULONGLONG base)
{
	nt_headers_.OptionalHeader.ImageBase = static_cast<typename PEClassType::BaseSize>(base);
}

//Returns image entry point
template<typename PEClassType>
DWORD pe<PEClassType>::get_ep() const
{
	return nt_headers_.OptionalHeader.AddressOfEntryPoint;
}

//Sets image entry point
template<typename PEClassType>
void pe<PEClassType>::set_ep(DWORD new_ep)
{
	nt_headers_.OptionalHeader.AddressOfEntryPoint = new_ep;
}

//Returns file alignment
template<typename PEClassType>
DWORD pe<PEClassType>::get_file_alignment() const
{
	return nt_headers_.OptionalHeader.FileAlignment;
}

//Returns section alignment
template<typename PEClassType>
DWORD pe<PEClassType>::get_section_alignment() const
{
	return nt_headers_.OptionalHeader.SectionAlignment;
}

//Sets heap size commit for PE32
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_commit(DWORD size)
{
	nt_headers_.OptionalHeader.SizeOfHeapCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets heap size commit for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_commit(ULONGLONG size)
{
	nt_headers_.OptionalHeader.SizeOfHeapCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets heap size reserve for PE32
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_reserve(DWORD size)
{
	nt_headers_.OptionalHeader.SizeOfHeapReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets heap size reserve for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_heap_size_reserve(ULONGLONG size)
{
	nt_headers_.OptionalHeader.SizeOfHeapReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size commit for PE32
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_commit(DWORD size)
{
	nt_headers_.OptionalHeader.SizeOfStackCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size commit for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_commit(ULONGLONG size)
{
	nt_headers_.OptionalHeader.SizeOfStackCommit = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size reserve for PE32
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_reserve(DWORD size)
{
	nt_headers_.OptionalHeader.SizeOfStackReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Sets stack size reserve for PE32/PE64
template<typename PEClassType>
void pe<PEClassType>::set_stack_size_reserve(ULONGLONG size)
{
	nt_headers_.OptionalHeader.SizeOfStackReserve = static_cast<typename PEClassType::BaseSize>(size);
}

//Returns heap size commit for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::get_heap_size_commit_32() const
{
	return static_cast<DWORD>(nt_headers_.OptionalHeader.SizeOfHeapCommit);
}

//Returns heap size commit for PE32/PE64
template<typename PEClassType>
ULONGLONG pe<PEClassType>::get_heap_size_commit_64() const
{
	return static_cast<ULONGLONG>(nt_headers_.OptionalHeader.SizeOfHeapCommit);
}

//Returns heap size reserve for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::get_heap_size_reserve_32() const
{
	return static_cast<DWORD>(nt_headers_.OptionalHeader.SizeOfHeapReserve);
}

//Returns heap size reserve for PE32/PE64
template<typename PEClassType>
ULONGLONG pe<PEClassType>::get_heap_size_reserve_64() const
{
	return static_cast<ULONGLONG>(nt_headers_.OptionalHeader.SizeOfHeapReserve);
}

//Returns stack size commit for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::get_stack_size_commit_32() const
{
	return static_cast<DWORD>(nt_headers_.OptionalHeader.SizeOfStackCommit);
}

//Returns stack size commit for PE32/PE64
template<typename PEClassType>
ULONGLONG pe<PEClassType>::get_stack_size_commit_64() const
{
	return static_cast<ULONGLONG>(nt_headers_.OptionalHeader.SizeOfStackCommit);
}

//Returns stack size reserve for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::get_stack_size_reserve_32() const
{
	return static_cast<DWORD>(nt_headers_.OptionalHeader.SizeOfStackReserve);
}

//Returns stack size reserve for PE32/PE64
template<typename PEClassType>
ULONGLONG pe<PEClassType>::get_stack_size_reserve_64() const
{
	return static_cast<ULONGLONG>(nt_headers_.OptionalHeader.SizeOfStackReserve);
}

//Returns virtual size of image
template<typename PEClassType>
DWORD pe<PEClassType>::get_size_of_image() const
{
	return nt_headers_.OptionalHeader.SizeOfImage;
}

//Returns number of RVA and sizes (number of DATA_DIRECTORY entries)
template<typename PEClassType>
DWORD pe<PEClassType>::get_number_of_rvas_and_sizes() const
{
	return nt_headers_.OptionalHeader.NumberOfRvaAndSizes;
}

//Sets number of RVA and sizes (number of DATA_DIRECTORY entries)
template<typename PEClassType>
void pe<PEClassType>::set_number_of_rvas_and_sizes(DWORD number)
{
	nt_headers_.OptionalHeader.NumberOfRvaAndSizes = number;
}

//Returns PE characteristics
template<typename PEClassType>
WORD pe<PEClassType>::get_characteristics() const
{
	return nt_headers_.FileHeader.Characteristics;
}

//Returns checksum of PE file from header
template<typename PEClassType>
DWORD pe<PEClassType>::get_checksum() const
{
	return nt_headers_.OptionalHeader.CheckSum;
}

//Sets PE characteristics
template<typename PEClassType>
void pe<PEClassType>::set_characteristics(WORD ch)
{
	nt_headers_.FileHeader.Characteristics = ch;
}

//Returns size of headers
template<typename PEClassType>
DWORD pe<PEClassType>::get_size_of_headers() const
{
	return nt_headers_.OptionalHeader.SizeOfHeaders;
}

//Returns subsystem
template<typename PEClassType>
WORD pe<PEClassType>::get_subsystem() const
{
	return nt_headers_.OptionalHeader.Subsystem;
}

//Returns size of optional header
template<typename PEClassType>
WORD pe<PEClassType>::get_size_of_optional_header() const
{
	return nt_headers_.FileHeader.SizeOfOptionalHeader;
}

//Returns PE signature
template<typename PEClassType>
DWORD pe<PEClassType>::get_pe_signature() const
{
	return nt_headers_.Signature;
}

//Returns PE magic value
template<typename PEClassType>
DWORD pe<PEClassType>::get_magic() const
{
	return nt_headers_.OptionalHeader.Magic;
}

//Virtual Address (VA) to Relative Virtual Address (RVA) convertions for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::va_to_rva(DWORD va, bool bound_check) const
{
	if(bound_check && static_cast<ULONGLONG>(va) - nt_headers_.OptionalHeader.ImageBase > max_dword)
		throw pe_exception("Incorrect address conversion", pe_exception::incorrect_address_conversion);

	return static_cast<DWORD>(va - nt_headers_.OptionalHeader.ImageBase);
}

//Virtual Address (VA) to Relative Virtual Address (RVA) convertions for PE32/PE64
template<typename PEClassType>
DWORD pe<PEClassType>::va_to_rva(ULONGLONG va, bool bound_check) const
{
	if(bound_check && va - nt_headers_.OptionalHeader.ImageBase > max_dword)
		throw pe_exception("Incorrect address conversion", pe_exception::incorrect_address_conversion);

	return static_cast<DWORD>(va - nt_headers_.OptionalHeader.ImageBase);
}

//Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32
template<typename PEClassType>
DWORD pe<PEClassType>::rva_to_va_32(DWORD rva) const
{
	if(!is_sum_safe(rva, static_cast<DWORD>(nt_headers_.OptionalHeader.ImageBase)))
		throw pe_exception("Incorrect address conversion", pe_exception::incorrect_address_conversion);

	return static_cast<DWORD>(rva + nt_headers_.OptionalHeader.ImageBase);
}

//Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32/PE64
template<typename PEClassType>
ULONGLONG pe<PEClassType>::rva_to_va_64(DWORD rva) const
{
	return static_cast<ULONGLONG>(rva) + nt_headers_.OptionalHeader.ImageBase;
}

//Returns number of sections
template<typename PEClassType>
WORD pe<PEClassType>::get_number_of_sections() const
{
	return nt_headers_.FileHeader.NumberOfSections;
}

//Sets number of sections
template<typename PEClassType>
void pe<PEClassType>::set_number_of_sections(WORD number)
{
	nt_headers_.FileHeader.NumberOfSections = number;
}

//Sets virtual size of image
template<typename PEClassType>
void pe<PEClassType>::set_size_of_image(DWORD size)
{
	nt_headers_.OptionalHeader.SizeOfImage = size;
}

//Sets size of headers
template<typename PEClassType>
void pe<PEClassType>::set_size_of_headers(DWORD size)
{
	nt_headers_.OptionalHeader.SizeOfHeaders = size;
}

//Sets size of optional headers
template<typename PEClassType>
void pe<PEClassType>::set_size_of_optional_header(WORD size)
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
unsigned long pe<PEClassType>::get_sizeof_nt_header() const
{
	return sizeof(typename PEClassType::NtHeaders);
}

//Returns size of optional headers
template<typename PEClassType>
unsigned long pe<PEClassType>::get_sizeof_opt_headers() const
{
	return sizeof(typename PEClassType::OptHeaders);
}

//Sets file alignment (no checks)
template<typename PEClassType>
void pe<PEClassType>::set_file_alignment_unchecked(DWORD alignment) 
{
	nt_headers_.OptionalHeader.FileAlignment = alignment;
}

//Sets base of code
template<typename PEClassType>
void pe<PEClassType>::set_base_of_code(DWORD base)
{
	nt_headers_.OptionalHeader.BaseOfCode = base;
}

//Returns needed PE magic for PE or PE+ (from template parameters)
template<typename PEClassType>
DWORD pe<PEClassType>::get_needed_magic() const
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

	unsigned long current_descriptor_pos = get_directory_rva(IMAGE_DIRECTORY_ENTRY_IMPORT);
	//Get first IMAGE_IMPORT_DESCRIPTOR
	IMAGE_IMPORT_DESCRIPTOR import_descriptor = section_data_from_rva<IMAGE_IMPORT_DESCRIPTOR>(current_descriptor_pos, section_data_virtual, true);

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
		DWORD current_thunk_rva = import_descriptor.FirstThunk;
		typename PEClassType::BaseSize import_address_table = section_data_from_rva<typename PEClassType::BaseSize>(current_thunk_rva, section_data_virtual, true);

		//Get RVA to original IAT (lookup table), which must handle imported functions names
		//Some linkers leave this pointer zero-filled
		//Such image is valid, but it is not possible to restore imported functions names
		//afted image was loaded, because IAT becomes the only one table
		//containing both function names and function RVAs after loading
		DWORD current_original_thunk_rva = import_descriptor.OriginalFirstThunk;
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
					func.set_ordinal(static_cast<WORD>(lookup & 0xffff));
				}
				else
				{
					//Get byte count that we have for function name
					if(lookup > static_cast<DWORD>(-1) - sizeof(WORD))
						throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

					//Get maximum available length of function name
					if((max_name_length = section_data_length_from_rva(static_cast<DWORD>(lookup + sizeof(WORD)), static_cast<DWORD>(lookup + sizeof(WORD)), section_data_virtual, true)) < 2)
						throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

					//Get imported function name
					const char* func_name = section_data_from_rva(static_cast<DWORD>(lookup + sizeof(WORD)), section_data_virtual, true);

					//Check for null-termination
					if(!is_null_terminated(func_name, max_name_length))
						throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

					//HINT in import table is ORDINAL in export table
					WORD hint = section_data_from_rva<WORD>(static_cast<DWORD>(lookup), section_data_virtual, true);

					//Save hint and name
					func.set_name(func_name);
					func.set_hint(hint);
				}

				//Add function to list
				lib.add_import(func);
			}
		}

		//Check possible overflow
		if(!is_sum_safe(current_descriptor_pos, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
			throw pe_exception("Incorrect import directory", pe_exception::incorrect_import_directory);

		//Go to next library
		current_descriptor_pos += sizeof(IMAGE_IMPORT_DESCRIPTOR);
		import_descriptor = section_data_from_rva<IMAGE_IMPORT_DESCRIPTOR>(current_descriptor_pos, section_data_virtual, true);

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

	DWORD needed_size = 0; //Calculate needed size for import structures and strings
	DWORD needed_size_for_strings = 0; //Calculate needed size for import strings (library and function names and hints)
	DWORD size_of_iat = 0; //Size of IAT structures

	needed_size += static_cast<DWORD>((1 /* ending null descriptor */ + imports.size()) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
	
	//Enumerate imported functions
	for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
	{
		needed_size_for_strings += static_cast<DWORD>((*it).get_name().length() + 1 /* nullbyte */);

		const import_library::imported_list& funcs = (*it).get_imported_functions();

		//IMAGE_THUNK_DATA
		size_of_iat += static_cast<DWORD>(sizeof(typename PEClassType::BaseSize) * (1 /*ending null */ + funcs.size()));

		//Enumerate all imported functions in library
		for(import_library::imported_list::const_iterator f = funcs.begin(); f != funcs.end(); ++f)
		{
			if((*f).has_name())
				needed_size_for_strings += static_cast<DWORD>((*f).get_name().length() + 1 /* nullbyte */ + sizeof(WORD) /* hint */);
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
	
	DWORD current_string_pointer = import_settings.get_offset_from_section_start();/* we will paste structures after strings */
	
	//Position for IAT
	DWORD current_pos_for_iat = align_up(static_cast<DWORD>(needed_size_for_strings + import_settings.get_offset_from_section_start() + (1 + imports.size()) * sizeof(IMAGE_IMPORT_DESCRIPTOR)), sizeof(typename PEClassType::BaseSize));
	//Position for original IAT
	DWORD current_pos_for_original_iat = current_pos_for_iat + size_of_iat;
	//Position for import descriptors
	DWORD current_pos_for_descriptors = needed_size_for_strings + import_settings.get_offset_from_section_start();

	//Build imports
	for(imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
	{
		//Create import descriptor
		IMAGE_IMPORT_DESCRIPTOR descr = {0};
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
		DWORD original_first_thunk = 0;
		DWORD first_thunk = 0;

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
		current_string_pointer += static_cast<DWORD>((*it).get_name().length() + 1 /* nullbyte */);
		
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
				WORD hint = (*f).get_hint();
				memcpy(&raw_data[current_string_pointer], &hint, sizeof(hint));
				memcpy(&raw_data[current_string_pointer + sizeof(WORD)], (*f).get_name().c_str(), (*f).get_name().length() + 1 /* nullbyte */);
				current_string_pointer += static_cast<DWORD>((*f).get_name().length() + 1 /* nullbyte */ + sizeof(WORD) /* hint */);
			}
			else //Function is imported by ordinal
			{
				WORD ordinal = (*f).get_ordinal();
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
		IMAGE_IMPORT_DESCRIPTOR descr = {0};
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
		set_directory_rva(IMAGE_DIRECTORY_ENTRY_IMPORT, ret.get_rva());
		set_directory_size(IMAGE_DIRECTORY_ENTRY_IMPORT, ret.get_size());

		//If we are requested to zero IMAGE_DIRECTORY_ENTRY_IAT also
		if(import_settings.zero_directory_entry_iat())
		{
			set_directory_rva(IMAGE_DIRECTORY_ENTRY_IAT, 0);
			set_directory_size(IMAGE_DIRECTORY_ENTRY_IAT, 0);
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
	typename PEClassType::TLSStruct tls_directory_data = section_data_from_rva<typename PEClassType::TLSStruct>(get_directory_rva(IMAGE_DIRECTORY_ENTRY_TLS), section_data_virtual, true);

	//Check data addresses
	if(tls_directory_data.EndAddressOfRawData == tls_directory_data.StartAddressOfRawData)
	{
		try
		{
			va_to_rva(tls_directory_data.EndAddressOfRawData);
		}
		catch(const pe_exception&)
		{
			//Fix addressess on incorrect conversion
			tls_directory_data.EndAddressOfRawData = tls_directory_data.StartAddressOfRawData = 0;
		}
	}

	if(tls_directory_data.StartAddressOfRawData &&
		section_data_length_from_va(tls_directory_data.StartAddressOfRawData, tls_directory_data.StartAddressOfRawData, section_data_virtual, true)
		< (tls_directory_data.EndAddressOfRawData - tls_directory_data.StartAddressOfRawData))
		throw pe_exception("Incorrect TLS directory", pe_exception::incorrect_tls_directory);

	//Fill TLS info
	//VAs are not checked
	ret.set_raw_data_start_rva(tls_directory_data.StartAddressOfRawData ? va_to_rva(tls_directory_data.StartAddressOfRawData) : 0);
	ret.set_raw_data_end_rva(tls_directory_data.EndAddressOfRawData ? va_to_rva(tls_directory_data.EndAddressOfRawData) : 0);
	ret.set_index_rva(tls_directory_data.AddressOfIndex ? va_to_rva(tls_directory_data.AddressOfIndex) : 0);
	ret.set_callbacks_rva(tls_directory_data.AddressOfCallBacks ? va_to_rva(tls_directory_data.AddressOfCallBacks) : 0);
	ret.set_size_of_zero_fill(tls_directory_data.SizeOfZeroFill);
	ret.set_characteristics(tls_directory_data.Characteristics);

	if(tls_directory_data.StartAddressOfRawData && tls_directory_data.StartAddressOfRawData != tls_directory_data.EndAddressOfRawData)
	{
		//Read and save TLS RAW data
		ret.set_raw_data(std::string(
			section_data_from_va(tls_directory_data.StartAddressOfRawData, section_data_virtual, true),
			static_cast<DWORD>(tls_directory_data.EndAddressOfRawData - tls_directory_data.StartAddressOfRawData)));
	}

	//If file has TLS callbacks
	if(ret.get_callbacks_rva())
	{
		//Read callbacks VAs
		DWORD current_tls_callback = 0;

		while(true)
		{
			//Read TLS callback VA
			typename PEClassType::BaseSize va = section_data_from_va<typename PEClassType::BaseSize>(tls_directory_data.AddressOfCallBacks + current_tls_callback, section_data_virtual, true);
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
const pe_base::image_directory pe<PEClassType>::rebuild_tls(const tls_info& info, section& tls_section, DWORD offset_from_section_start, bool write_tls_callbacks, bool write_tls_data, tls_data_expand_type expand, bool save_to_pe_header, bool auto_strip_last_section)
{
	//Check that tls_section is attached to this PE image
	if(!section_attached(tls_section))
		throw pe_exception("TLS section must be attached to PE file", pe_exception::section_is_not_attached);

	DWORD needed_size = sizeof(typename PEClassType::TLSStruct) + sizeof(typename PEClassType::BaseSize); //Calculate needed size for TLS table
	//sizeof(typename PEClassType::BaseSize) = for DWORD/QWORD alignment
	
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

	DWORD tls_data_pos = align_up(offset_from_section_start, sizeof(typename PEClassType::BaseSize));

	//Create and fill TLS structure
	typename PEClassType::TLSStruct tls_struct = {0};

	if(info.get_raw_data_start_rva())
	{
		rva_to_va(info.get_raw_data_start_rva(), tls_struct.StartAddressOfRawData);
		tls_struct.SizeOfZeroFill = info.get_size_of_zero_fill();
	}

	if(info.get_raw_data_end_rva())
		rva_to_va(info.get_raw_data_end_rva(), tls_struct.EndAddressOfRawData);

	rva_to_va(info.get_index_rva(), tls_struct.AddressOfIndex);

	if(info.get_callbacks_rva())
		rva_to_va(info.get_callbacks_rva(), tls_struct.AddressOfCallBacks);

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
			typename PEClassType::BaseSize va = 0;
			rva_to_va(*it, va);
			callbacks_virtual_addresses.push_back(va);
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
		set_directory_rva(IMAGE_DIRECTORY_ENTRY_TLS, ret.get_rva());
		set_directory_size(IMAGE_DIRECTORY_ENTRY_TLS, ret.get_size());
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
	typename PEClassType::ConfigStruct config_info = section_data_from_rva<typename PEClassType::ConfigStruct>(get_directory_rva(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG), section_data_virtual);

	//Check size of config directory
	if(config_info.Size != sizeof(config_info))
		throw pe_exception("Incorrect load config directory", pe_exception::incorrect_config_directory);

	//Fill return structure
	image_config_info ret(config_info);

	//Check possible overflow
	if(config_info.SEHandlerCount >= max_dword / sizeof(DWORD)
		|| config_info.SEHandlerTable >= static_cast<typename PEClassType::BaseSize>(-1) - config_info.SEHandlerCount * sizeof(DWORD))
		throw pe_exception("Incorrect load config directory", pe_exception::incorrect_config_directory);

	//Read SE handler RVA list (if any)
	for(typename PEClassType::BaseSize i = 0; i != config_info.SEHandlerCount; ++i)
		ret.add_se_handler_rva(section_data_from_va<DWORD>(config_info.SEHandlerTable + i * sizeof(DWORD)));

	return ret;
}


//RELOCATIONS
//Recalculates image base with the help of relocation tables
//Recalculates VAs of DWORDS/QWORDS in image according to relocations
//Notice: if you move some critical structures like TLS, image relocations will not fix new
//positions of TLS VAs. Instead, some bytes that now doesn't belong to TLS will be fixed.
//It is recommended to rebase image in the very beginning and move all structures afterwards.
template<typename PEClassType>
void pe<PEClassType>::rebase_image(const relocation_table_list& tables, ULONGLONG new_base)
{
	//Get current image base value
	typename PEClassType::BaseSize image_base;
	get_image_base(image_base);

	//ImageBase difference
	typename PEClassType::BaseSize base_rel = static_cast<typename PEClassType::BaseSize>(static_cast<LONGLONG>(new_base) - image_base);

	//We need to fix addresses from relocation tables
	//Enumerate relocation tables
	for(relocation_table_list::const_iterator it = tables.begin(); it != tables.end(); ++it)
	{
		const relocation_table::relocation_list& relocs = (*it).get_relocations();

		DWORD base_rva = (*it).get_rva();

		//Enumerate relocations
		for(relocation_table::relocation_list::const_iterator rel = relocs.begin(); rel != relocs.end(); ++rel)
		{
			//Recalculate value by RVA and rewrite it
			DWORD current_rva = base_rva + (*rel).get_rva();
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
	return PEClassType::Id == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? pe_type_32 : pe_type_64;
}

//Two used instantiations for PE32 (PE) and PE64 (PE+)
template class pe<pe_class_type<IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32, IMAGE_NT_OPTIONAL_HDR32_MAGIC, DWORD, IMAGE_ORDINAL_FLAG32, IMAGE_TLS_DIRECTORY32, IMAGE_LOAD_CONFIG_DIRECTORY32> >;
template class pe<pe_class_type<IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, ULONGLONG, IMAGE_ORDINAL_FLAG64, IMAGE_TLS_DIRECTORY64, IMAGE_LOAD_CONFIG_DIRECTORY64> >;
