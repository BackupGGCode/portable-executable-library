#pragma once
#include <string>
#include <vector>
#include <istream>
#include <ostream>
#include <algorithm>
#include "pe_exception.h"
#include "pe_base.h"

namespace pe_bliss
{
//Helper class to reduce code size and ease its editing
template<
	typename NtHeadersType,
	typename OptHeadersType,
	uint16_t IdVal,
	typename BaseSizeType,
	BaseSizeType ImportSnapFlagVal,
	typename TLSStructType,
	typename ConfigStructType>
class pe_class_type
{
public:
	typedef NtHeadersType NtHeaders; //NT HEADERS type
	typedef OptHeadersType OptHeaders; //NT OPTIONAL HEADER type
	typedef BaseSizeType BaseSize; //Base size of different values: DWORD or ULONGLONG
	typedef TLSStructType TLSStruct; //TLS structure type
	typedef ConfigStructType ConfigStruct; //Configuration structure type

	static const uint16_t Id = IdVal; //Magic of PE or PE+
	static const BaseSize ImportSnapFlag = ImportSnapFlagVal; //Import snap flag value
};

//Portable Executable derived class for PE and PE+
//Describes PE/PE+ dependent things
template<typename PEClassType>
class pe : public pe_base
{
public:
	//Constructor from istream with PE raw data
	//If read_bound_import_raw_data, raw bound import data will be read (used to get bound import info)
	//If read_debug_raw_data, raw debug data will be read (used to get image debug info)
	explicit pe(std::istream& file, bool read_bound_import_raw_data = true, bool read_debug_raw_data = true);
	
	//Constructor of empty PE file
	explicit pe(uint32_t section_alignment = 0x1000, bool dll = false, uint16_t subsystem = pe_win::image_subsystem_windows_gui);
	
	//Destructor
	virtual ~pe();


public: //DIRECTORIES
	//Returns true if directory exists
	virtual bool directory_exists(uint32_t id) const;

	//Removes directory
	virtual void remove_directory(uint32_t id);

	//Returns directory RVA
	virtual uint32_t get_directory_rva(uint32_t id) const;
	//Returns directory size
	virtual uint32_t get_directory_size(uint32_t id) const;

	//Sets directory RVA (just a value of PE header, no moving occurs)
	virtual void set_directory_rva(uint32_t id, uint32_t rva);
	//Sets directory size (just a value of PE header, no moving occurs)
	virtual void set_directory_size(uint32_t id, uint32_t size);
	
	//Strips only zero DATA_DIRECTORY entries to count = min_count
	//Returns resulting number of data directories
	//strip_iat_directory - if true, even not empty IAT directory will be stripped
	virtual uint32_t strip_data_directories(uint32_t min_count = 1, bool strip_iat_directory = true);


public: //IMAGE
	//Returns PE type of this image
	virtual pe_type get_pe_type() const;


public: //PE HEADER
	//Returns image base for PE32 and PE64 respectively
	virtual uint32_t get_image_base_32() const;
	virtual uint64_t get_image_base_64() const;

	//Sets new image base for PE32
	virtual void set_image_base(uint32_t base);
	//Sets new image base for PE32/PE+
	virtual void set_image_base_64(uint64_t base);

	//Returns image entry point
	virtual uint32_t get_ep() const;
	//Sets image entry point
	virtual void set_ep(uint32_t new_ep);

	//Returns file alignment
	virtual uint32_t get_file_alignment() const;
	//Returns section alignment
	virtual uint32_t get_section_alignment() const;

	//Sets heap size commit for PE32 and PE64 respectively
	virtual void set_heap_size_commit(uint32_t size);
	virtual void set_heap_size_commit(uint64_t size);
	//Sets heap size reserve for PE32 and PE64 respectively
	virtual void set_heap_size_reserve(uint32_t size);
	virtual void set_heap_size_reserve(uint64_t size);
	//Sets stack size commit for PE32 and PE64 respectively
	virtual void set_stack_size_commit(uint32_t size);
	virtual void set_stack_size_commit(uint64_t size);
	//Sets stack size reserve for PE32 and PE64 respectively
	virtual void set_stack_size_reserve(uint32_t size);
	virtual void set_stack_size_reserve(uint64_t size);
	
	//Returns heap size commit for PE32 and PE64 respectively
	virtual uint32_t get_heap_size_commit_32() const;
	virtual uint64_t get_heap_size_commit_64() const;
	//Returns heap size reserve for PE32 and PE64 respectively
	virtual uint32_t get_heap_size_reserve_32() const;
	virtual uint64_t get_heap_size_reserve_64() const;
	//Returns stack size commit for PE32 and PE64 respectively
	virtual uint32_t get_stack_size_commit_32() const;
	virtual uint64_t get_stack_size_commit_64() const;
	//Returns stack size reserve for PE32 and PE64 respectively
	virtual uint32_t get_stack_size_reserve_32() const;
	virtual uint64_t get_stack_size_reserve_64() const;

	//Returns virtual size of image
	virtual uint32_t get_size_of_image() const;

	//Returns number of RVA and sizes (number of DATA_DIRECTORY entries)
	virtual uint32_t get_number_of_rvas_and_sizes() const;
	//Sets number of RVA and sizes (number of DATA_DIRECTORY entries)
	virtual void set_number_of_rvas_and_sizes(uint32_t number);

	//Returns PE characteristics
	virtual uint16_t get_characteristics() const;
	//Sets PE characteristics
	virtual void set_characteristics(uint16_t ch);

	//Returns size of headers
	virtual uint32_t get_size_of_headers() const;

	//Returns subsystem
	virtual uint16_t get_subsystem() const;

	//Sets subsystem
	virtual void set_subsystem(uint16_t subsystem);

	//Returns size of optional header
	virtual uint16_t get_size_of_optional_header() const;

	//Returns PE signature
	virtual uint32_t get_pe_signature() const;

	//Returns PE magic value
	virtual uint32_t get_magic() const;

	//Returns checksum of PE file from header
	virtual uint32_t get_checksum() const;
	
	//Sets checksum of PE file
	virtual void set_checksum(uint32_t checksum);
	
	//Returns timestamp of PE file from header
	virtual uint32_t get_time_date_stamp() const;
	
	//Sets timestamp of PE file
	virtual void set_time_date_stamp(uint32_t timestamp);
	
	//Returns Machine field value of PE file from header
	virtual uint16_t get_machine() const;

	//Sets Machine field value of PE file
	virtual void set_machine(uint16_t machine);

	//Returns DLL Characteristics
	virtual uint16_t get_dll_characteristics() const;
	
	//Sets DLL Characteristics
	virtual void set_dll_characteristics(uint16_t characteristics);
	
	//Sets required operation system version
	virtual void set_os_version(uint16_t major, uint16_t minor);

	//Returns required operation system version (minor word)
	virtual uint16_t get_minor_os_version() const;

	//Returns required operation system version (major word)
	virtual uint16_t get_major_os_version() const;

	//Sets required subsystem version
	virtual void set_subsystem_version(uint16_t major, uint16_t minor);

	//Returns required subsystem version (minor word)
	virtual uint16_t get_minor_subsystem_version() const;

	//Returns required subsystem version (major word)
	virtual uint16_t get_major_subsystem_version() const;

public: //ADDRESS CONVERTIONS
	//Virtual Address (VA) to Relative Virtual Address (RVA) convertions
	//for PE32 and PE64 respectively
	//bound_check checks integer overflow
	virtual uint32_t va_to_rva(uint32_t va, bool bound_check = true) const;
	virtual uint32_t va_to_rva(uint64_t va, bool bound_check = true) const;
	
	//Relative Virtual Address (RVA) to Virtual Address (VA) convertions
	//for PE32 and PE64 respectively
	virtual uint32_t rva_to_va_32(uint32_t rva) const;
	virtual uint64_t rva_to_va_64(uint32_t rva) const;


public: //SECTIONS
	//Returns number of sections
	virtual uint16_t get_number_of_sections() const;


public: //IMPORTS
	//Returns imported functions list with related libraries info
	virtual const imported_functions_list get_imported_functions() const;
	
	//Simple import directory rebuilder
	//You can get all image imports with get_imported_functions() function
	//You can use returned value to, for example, add new imported library with some functions
	//to the end of list of imported libraries
	//To keep PE file working, rebuild its imports with save_iat_and_original_iat_rvas = true (default)
	//Don't add new imported functions to existing imported library entries, because this can cause
	//rewriting of some used memory (or other IAT/orig.IAT fields) by system loader
	//The safest way is just adding import libraries with functions to the end of imported_functions_list array
	virtual const image_directory rebuild_imports(const imported_functions_list& imports, section& import_section, const import_rebuilder_settings& import_settings = import_rebuilder_settings());

public: //TLS
	//Get TLS info
	//If image does not have TLS, throws an exception
	virtual const tls_info get_tls_info() const;
	
	//Rebuilder of TLS structures
	//If write_tls_callbacks = true, TLS callbacks VAs will be written to their place
	//If write_tls_data = true, TLS data will be written to its place
	//If you have chosen to rewrite raw data, only (EndAddressOfRawData - StartAddressOfRawData) bytes will be written, not the full length of string
	//representing raw data content
	//auto_strip_last_section - if true and TLS are placed in the last section, it will be automatically stripped
	virtual const image_directory rebuild_tls(const tls_info& info, section& tls_section, uint32_t offset_from_section_start = 0, bool write_tls_callbacks = true, bool write_tls_data = true, tls_data_expand_type expand = tls_data_expand_raw, bool save_to_pe_header = true, bool auto_strip_last_section = true);

public: //IMAGE CONFIG
	//Returns image config info
	//If image does not have config info, throws an exception
	virtual const image_config_info get_image_config() const;
	
	//Image config directory rebuilder
	//auto_strip_last_section - if true and TLS are placed in the last section, it will be automatically stripped
	//If write_se_handlers = true, SE Handlers list will be written just after image config directory structure
	//If write_lock_prefixes = true, Lock Prefixes address list will be written just after image config directory structure
	virtual const image_directory rebuild_image_config(const image_config_info& info, section& image_config_section, uint32_t offset_from_section_start = 0, bool write_se_handlers = true, bool write_lock_prefixes = true, bool save_to_pe_header = true, bool auto_strip_last_section = true);

public: //RELOCATIONS
	//Recalculates image base with the help of relocation tables
	//Recalculates VAs of DWORDS/QWORDS in image according to relocations
	//Notice: if you move some critical structures like TLS, image relocations will not fix new
	//positions of TLS VAs. Instead, some bytes that now doesn't belong to TLS will be fixed.
	//It is recommended to rebase image in the very beginning and move all structures afterwards.
	virtual void rebase_image(const relocation_table_list& tables, uint64_t new_base);

protected:
	typename PEClassType::NtHeaders nt_headers_; //NT headers (PE32 or PE64)

protected:
	//Sets number of sections
	virtual void set_number_of_sections(uint16_t number);
	//Sets virtual size of image
	virtual void set_size_of_image(uint32_t size);
	//Sets size of headers
	virtual void set_size_of_headers(uint32_t size);
	//Sets size of optional headers
	virtual void set_size_of_optional_header(uint16_t size);
	//Returns nt headers data pointer
	virtual char* get_nt_headers_ptr();
	//Returns size of NT header
	virtual uint32_t get_sizeof_nt_header() const;
	//Returns size of optional headers
	virtual uint32_t get_sizeof_opt_headers() const;
	//Sets file alignment (no checks)
	virtual void set_file_alignment_unchecked(uint32_t alignment);
	//Sets base of code
	virtual void set_base_of_code(uint32_t base);
	//Returns needed PE magic for PE or PE+ (from template parameters)
	virtual uint32_t get_needed_magic() const;
};

//Two used typedefs for PE32 (PE) and PE64 (PE+)
typedef pe<pe_class_type<pe_win::image_nt_headers32,
	pe_win::image_optional_header32,
	pe_win::image_nt_optional_hdr32_magic,
	uint32_t,
	pe_win::image_ordinal_flag32,
	pe_win::image_tls_directory32,
	pe_win::image_load_config_directory32> > pe32;

typedef pe<pe_class_type<pe_win::image_nt_headers64,
	pe_win::image_optional_header64,
	pe_win::image_nt_optional_hdr64_magic,
	uint64_t,
	pe_win::image_ordinal_flag64,
	pe_win::image_tls_directory64,
	pe_win::image_load_config_directory64> > pe64;
}
