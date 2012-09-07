#pragma once
#include <string>
#include <vector>
#include <istream>
#include <ostream>
#include <algorithm>
#include "pe_exception.h"
#include "pe_base.h"

//Helper class to reduce code size and ease its editing
//Specializes
template<
	typename NtHeadersType,
	typename OptHeadersType,
	WORD IdVal,
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

	static const WORD Id = IdVal; //Magic of PE or PE+
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

	//Destructor
	virtual ~pe();


public: //DIRECTORIES
	//Returns true if directory exists
	virtual bool directory_exists(unsigned long id) const;

	//Removes directory
	virtual void remove_directory(unsigned long id);

	//Returns directory RVA
	virtual DWORD get_directory_rva(unsigned long id) const;
	//Returns directory size
	virtual DWORD get_directory_size(unsigned long id) const;

	//Sets directory RVA (just a value of PE header, no moving occurs)
	virtual void set_directory_rva(unsigned long id, DWORD va);
	//Sets directory size (just a value of PE header, no moving occurs)
	virtual void set_directory_size(unsigned long id, DWORD size);
	
	//Strips only zero DATA_DIRECTORY entries to count = min_count
	//Returns resulting number of data directories
	virtual unsigned long strip_data_directories(long min_count = 1);


public: //IMAGE
	//Returns PE type of this image
	virtual pe_type get_pe_type() const;


public: //PE HEADER
	//Returns image base for PE32 and PE64 respectively
	virtual DWORD get_image_base_32() const;
	virtual ULONGLONG get_image_base_64() const;

	//Sets new image base for PE32
	virtual void set_image_base(DWORD base);
	//Sets new image base for PE32/PE+
	virtual void set_image_base_64(ULONGLONG base);

	//Returns image entry point
	virtual DWORD get_ep() const;
	//Sets image entry point
	virtual void set_ep(DWORD new_ep);

	//Returns file alignment
	virtual DWORD get_file_alignment() const;
	//Returns section alignment
	virtual DWORD get_section_alignment() const;

	//Sets heap size commit for PE32 and PE64 respectively
	virtual void set_heap_size_commit(DWORD size);
	virtual void set_heap_size_commit(ULONGLONG size);
	//Sets heap size reserve for PE32 and PE64 respectively
	virtual void set_heap_size_reserve(DWORD size);
	virtual void set_heap_size_reserve(ULONGLONG size);
	//Sets stack size commit for PE32 and PE64 respectively
	virtual void set_stack_size_commit(DWORD size);
	virtual void set_stack_size_commit(ULONGLONG size);
	//Sets stack size reserve for PE32 and PE64 respectively
	virtual void set_stack_size_reserve(DWORD size);
	virtual void set_stack_size_reserve(ULONGLONG size);
	
	//Returns heap size commit for PE32 and PE64 respectively
	virtual DWORD get_heap_size_commit_32() const;
	virtual ULONGLONG get_heap_size_commit_64() const;
	//Returns heap size reserve for PE32 and PE64 respectively
	virtual DWORD get_heap_size_reserve_32() const;
	virtual ULONGLONG get_heap_size_reserve_64() const;
	//Returns stack size commit for PE32 and PE64 respectively
	virtual DWORD get_stack_size_commit_32() const;
	virtual ULONGLONG get_stack_size_commit_64() const;
	//Returns stack size reserve for PE32 and PE64 respectively
	virtual DWORD get_stack_size_reserve_32() const;
	virtual ULONGLONG get_stack_size_reserve_64() const;

	//Returns virtual size of image
	virtual DWORD get_size_of_image() const;

	//Returns number of RVA and sizes (number of DATA_DIRECTORY entries)
	virtual DWORD get_number_of_rvas_and_sizes() const;
	//Sets number of RVA and sizes (number of DATA_DIRECTORY entries)
	virtual void set_number_of_rvas_and_sizes(DWORD number);

	//Returns PE characteristics
	virtual WORD get_characteristics() const;
	//Sets PE characteristics
	virtual void set_characteristics(WORD ch);

	//Returns size of headers
	virtual DWORD get_size_of_headers() const;

	//Returns subsystem
	virtual WORD get_subsystem() const;

	//Returns size of optional header
	virtual WORD get_size_of_optional_header() const;

	//Returns PE signature
	virtual DWORD get_pe_signature() const;

	//Returns PE magic value
	virtual DWORD get_magic() const;

	//Returns checksum of PE file from header
	virtual DWORD get_checksum() const;


public: //ADDRESS CONVERTIONS
	//Virtual Address (VA) to Relative Virtual Address (RVA) convertions
	//for PE32 and PE64 respectively
	//bound_check checks integer overflow
	virtual DWORD va_to_rva(DWORD va, bool bound_check = true) const;
	virtual DWORD va_to_rva(ULONGLONG va, bool bound_check = true) const;
	
	//Relative Virtual Address (RVA) to Virtual Address (VA) convertions
	//for PE32 and PE64 respectively
	virtual DWORD rva_to_va_32(DWORD rva) const;
	virtual ULONGLONG rva_to_va_64(DWORD rva) const;


public: //SECTIONS
	//Returns number of sections
	virtual WORD get_number_of_sections() const;


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
	virtual const image_directory rebuild_tls(const tls_info& info, section& tls_section, DWORD offset_from_section_start = 0, bool write_tls_callbacks = true, bool write_tls_data = true, tls_data_expand_type expand = tls_data_expand_raw, bool save_to_pe_header = true);

public: //IMAGE CONFIG
	//Returns image config info
	//If image does not have config info, throws an exception
	virtual const image_config_info get_image_config() const;

public: //RELOCATIONS
	//Recalculates image base with the help of relocation tables
	//Recalculates VAs of DWORDS/QWORDS in image according to relocations
	//Notice: if you move some critical structures like TLS, image relocations will not fix new
	//positions of TLS VAs. Instead, some bytes that now doesn't belong to TLS will be fixed.
	//It is recommended to rebase image in the very beginning and move all structures afterwards.
	virtual void rebase_image(const relocation_table_list& tables, ULONGLONG new_base);

protected:
	typename PEClassType::NtHeaders nt_headers_; //NT headers (PE32 or PE64)

protected:
	//Sets number of sections
	virtual void set_number_of_sections(WORD number);
	//Sets virtual size of image
	virtual void set_size_of_image(DWORD size);
	//Sets size of headers
	virtual void set_size_of_headers(DWORD size);
	//Sets size of optional headers
	virtual void set_size_of_optional_header(WORD size);
	//Returns nt headers data pointer
	virtual char* get_nt_headers_ptr();
	//Returns size of NT header
	virtual unsigned long get_sizeof_nt_header() const;
	//Returns size of optional headers
	virtual unsigned long get_sizeof_opt_headers() const;
	//Sets file alignment (no checks)
	virtual void set_file_alignment_unchecked(DWORD alignment);
	//Sets base of code
	virtual void set_base_of_code(DWORD base);
	//Returns needed PE magic for PE or PE+ (from template parameters)
	virtual DWORD get_needed_magic() const;
};

//Two used typedefs for PE32 (PE) and PE64 (PE+)
typedef pe<pe_class_type<IMAGE_NT_HEADERS32, IMAGE_OPTIONAL_HEADER32, IMAGE_NT_OPTIONAL_HDR32_MAGIC, DWORD, IMAGE_ORDINAL_FLAG32, IMAGE_TLS_DIRECTORY32, IMAGE_LOAD_CONFIG_DIRECTORY32> > pe32;
typedef pe<pe_class_type<IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_NT_OPTIONAL_HDR64_MAGIC, ULONGLONG, IMAGE_ORDINAL_FLAG64, IMAGE_TLS_DIRECTORY64, IMAGE_LOAD_CONFIG_DIRECTORY64> > pe64;
