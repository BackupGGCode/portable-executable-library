#pragma once
#include <string>
#include <vector>
#include <istream>
#include <ostream>
#include <algorithm>
#include <utility>
#include <map>
#include <set>
#include "pe_exception.h"
#include "pe_structures.h"

//Please don't remove this information from header
//PE Library (c) DX 2011 - 2012, http://kaimi.ru
//Version: 0.1.4
//Free to use, modify and distribute

// == more important ==
//TODO: relocations that take more than one element (seems to be not possible in Windows PE, but anyway)
//TODO: create sample-based tests
//== less important ==
//TODO: delay import directory
//TODO: write message tables
//TODO: write string tables
//TODO: read security information
//TODO: read full .NET information

//Portable executable base class
class pe_base
{
public: //STUB OVERLAY
	//Rich data overlay structure of Microsoft Visual Studio
	struct rich_data
	{
	public:
		//Default constructor
		rich_data();

	public: //Getters
		//Who knows, what these fields mean...
		DWORD get_number() const;
		DWORD get_version() const;
		DWORD get_times() const;

	public: //Setters, user by PE library only
		void set_number(DWORD number);
		void set_version(DWORD version);
		void set_times(DWORD times);

	private:
		DWORD number_;
		DWORD version_;
		DWORD times_;
	};


public: //GENERAL
	//Destructor
	virtual ~pe_base();


public: //SECTIONS
	//Struct representing image section
	struct section
	{
	public: //Friends
		friend class pe_base;

	public:
		//Default constructor
		section();

		//Sets the name of section (stripped to 8 characters)
		void set_name(const std::string& name);

		//Returns the name of section
		const std::string get_name() const;

		//Changes attributes of section
		section& readable(bool readable);
		section& writeable(bool writeable);
		section& executable(bool executable);

		//Returns attributes of section
		bool readable() const;
		bool writeable() const;
		bool executable() const;

		//Returns true if section has no RAW data
		bool empty() const;

		//Returns raw section data from file image
		std::string& get_raw_data();
		//Returns raw section data from file image
		const std::string& get_raw_data() const;
		//Returns mapped virtual section data
		const std::string& get_virtual_data() const;
		//Returns mapped virtual section data
		std::string& get_virtual_data();

		//Header operations

		//Returns section virtual size
		DWORD get_virtual_size() const;
		//Returns section virtual address (RVA)
		DWORD get_virtual_address() const;
		//Returns size of section raw data
		DWORD get_size_of_raw_data() const;
		//Returns pointer to raw section data in PE file
		DWORD get_pointer_to_raw_data() const;
		//Returns section characteristics
		DWORD get_characteristics() const;

	public: //Setters
		//Sets size of raw section data
		void set_size_of_raw_data(DWORD size_of_raw_data);
		//Sets pointer to section raw data
		void set_pointer_to_raw_data(DWORD pointer_to_raw_data);
		//Sets section characteristics
		void set_characteristics(DWORD characteristics);
		//Sets raw section data from file image
		void set_raw_data(const std::string& data);

	public: //Setters, be careful
		//Sets section virtual size (doesn't set internal aligned virtual size, changes only header value)
		//Better use pe_base::set_section_virtual_size
		void set_virtual_size(DWORD virtual_size);
		//Sets section virtual address
		void set_virtual_address(DWORD virtual_address);

	private:
		//Section header
		IMAGE_SECTION_HEADER header_;

		//Aligned sizes of section
		DWORD raw_size_aligned_;
		DWORD virtual_size_aligned_;

		//Maps virtual section data
		void map_virtual() const;

		//Unmaps virtual section data
		void unmap_virtual() const;

		//Old size of section (stored after mapping of virtual section memory)
		mutable std::size_t old_size_;

		//Section raw/virtual data
		mutable std::string raw_data_;
	};


public: //STUB
	//Strips stub MSVS overlay, if any
	void strip_stub_overlay();
	//Fills stub MSVS overlay with specified byte
	void fill_stub_overlay(char c);
	//Returns stub overlay contents
	const std::string& get_stub_overlay() const;
	
	//Returns a vector with rich data (stub overlay)
	typedef std::vector<rich_data> rich_data_list;
	const rich_data_list get_rich_data() const;


public: //DIRECTORIES
	//Structure representing image directory data
	struct image_directory
	{
	public:
		//Default constructor
		image_directory();
		//Constructor from data
		image_directory(DWORD rva, DWORD size);

		//Returns RVA
		DWORD get_rva() const;
		//Returns size
		DWORD get_size() const;

		//Sets RVA
		void set_rva(DWORD rva);
		//Sets size
		void set_size(DWORD size);

	private:
		DWORD rva_;
		DWORD size_;
	};

	//Returns true if directory exists
	virtual bool directory_exists(unsigned long id) const = 0;
	//Removes directory
	virtual void remove_directory(unsigned long id) = 0;

	//Returns directory RVA
	virtual DWORD get_directory_rva(unsigned long id) const = 0;
	//Returns directory size
	virtual DWORD get_directory_size(unsigned long id) const = 0;

	//Sets directory RVA (just a value of PE header, no moving occurs)
	virtual void set_directory_rva(unsigned long id, DWORD va) = 0;
	//Sets directory size (just a value of PE header, no moving occurs)
	virtual void set_directory_size(unsigned long id, DWORD size) = 0;

	//Strips only zero DATA_DIRECTORY entries to count = min_count
	//Returns resulting number of data directories
	virtual unsigned long strip_data_directories(long min_count = 1) = 0;

	//Returns true if image has import directory
	bool has_imports() const;
	//Returns true if image has export directory
	bool has_exports() const;
	//Returns true if image has resource directory
	bool has_resources() const;
	//Returns true if image has security directory
	bool has_security() const;
	//Returns true if image has relocations
	bool has_reloc() const;
	//Returns true if image has TLS directory
	bool has_tls() const;
	//Returns true if image has config directory
	bool has_config() const;
	//Returns true if image has bound import directory
	bool has_bound_import() const;
	//Returns true if image has delay import directory
	bool has_delay_import() const;
	//Returns true if image has COM directory
	bool is_dotnet() const;
	//Returns true if image has exception directory
	bool has_exception_directory() const;
	//Returns true if image has debug directory
	bool has_debug() const;

	//Returns subsystem value
	virtual WORD get_subsystem() const = 0;
	//Returns true if image has console subsystem
	bool is_console() const;
	//Returns true if image has Windows GUI subsystem
	bool is_gui() const;


public: //PE HEADER
	//Returns DOS header
	const IMAGE_DOS_HEADER& get_dos_header() const;
	IMAGE_DOS_HEADER& get_dos_header();

	//returns PE header start (e_lfanew)
	LONG get_pe_header_start() const;

	//Returns file alignment
	virtual DWORD get_file_alignment() const = 0;
	//Sets file alignment, checking the correctness of its value
	void set_file_alignment(DWORD alignment);

	//Returns size of image
	virtual DWORD get_size_of_image() const = 0;

	//Returns image entry point
	virtual DWORD get_ep() const = 0;
	//Sets image entry point (just a value of PE header)
	virtual void set_ep(DWORD new_ep) = 0;

	//Returns number of RVA and sizes (number of DATA_DIRECTORY entries)
	virtual DWORD get_number_of_rvas_and_sizes() const = 0;
	//Sets number of RVA and sizes (number of DATA_DIRECTORY entries)
	virtual void set_number_of_rvas_and_sizes(DWORD number) = 0;

	//returns PE characteristics
	virtual WORD get_characteristics() const = 0;
	//Sets PE characteristics (a value inside header)
	virtual void set_characteristics(WORD ch) = 0;
	//Clears PE characteristics flag
	void clear_characteristics_flags(WORD flags);
	//Sets PE characteristics flag
	void set_characteristics_flags(WORD flags);
	//Returns true if PE characteristics flag set
	bool check_characteristics_flag(WORD flag) const;

	//Returns size of headers
	virtual DWORD get_size_of_headers() const = 0;
	//Returns size of optional header
	virtual WORD get_size_of_optional_header() const = 0;

	//Returns PE signature
	virtual DWORD get_pe_signature() const = 0;

	//Returns magic value
	virtual DWORD get_magic() const = 0;

	//Returns image base for PE32 and PE64 respectively
	virtual DWORD get_image_base_32() const = 0;
	void get_image_base(DWORD& base) const;
	//Sets image base for PE32 and PE64 respectively
	virtual ULONGLONG get_image_base_64() const = 0;
	void get_image_base(ULONGLONG& base) const;

	//Sets new image base
	virtual void set_image_base(DWORD base) = 0;
	virtual void set_image_base_64(ULONGLONG base) = 0;

	//Sets heap size commit for PE32 and PE64 respectively
	virtual void set_heap_size_commit(DWORD size) = 0;
	virtual void set_heap_size_commit(ULONGLONG size) = 0;
	//Sets heap size reserve for PE32 and PE64 respectively
	virtual void set_heap_size_reserve(DWORD size) = 0;
	virtual void set_heap_size_reserve(ULONGLONG size) = 0;
	//Sets stack size commit for PE32 and PE64 respectively
	virtual void set_stack_size_commit(DWORD size) = 0;
	virtual void set_stack_size_commit(ULONGLONG size) = 0;
	//Sets stack size reserve for PE32 and PE64 respectively
	virtual void set_stack_size_reserve(DWORD size) = 0;
	virtual void set_stack_size_reserve(ULONGLONG size) = 0;

	//Returns heap size commit for PE32 and PE64 respectively
	virtual DWORD get_heap_size_commit_32() const = 0;
	void get_heap_size_commit(DWORD& size) const;
	virtual ULONGLONG get_heap_size_commit_64() const = 0;
	void get_heap_size_commit(ULONGLONG& size) const;
	//Returns heap size reserve for PE32 and PE64 respectively
	virtual DWORD get_heap_size_reserve_32() const = 0;
	void get_heap_size_reserve(DWORD& size) const;
	virtual ULONGLONG get_heap_size_reserve_64() const = 0;
	void get_heap_size_reserve(ULONGLONG& size) const;
	//Returns stack size commit for PE32 and PE64 respectively
	virtual DWORD get_stack_size_commit_32() const = 0;
	void get_stack_size_commit(DWORD& size) const;
	virtual ULONGLONG get_stack_size_commit_64() const = 0;
	void get_stack_size_commit(ULONGLONG& size) const;
	//Returns stack size reserve for PE32 and PE64 respectively
	virtual DWORD get_stack_size_reserve_32() const = 0;
	void get_stack_size_reserve(DWORD& size) const;
	virtual ULONGLONG get_stack_size_reserve_64() const = 0;
	void get_stack_size_reserve(ULONGLONG& size) const;

	//Updates virtual size of image corresponding to section virtual sizes
	void update_image_size();

	//Returns checksum of PE file from header
	virtual DWORD get_checksum() const = 0;
	
	//Returns data from the beginning of image
	//Size = SizeOfHeaders
	const std::string& get_full_headers_data() const;


public: //ADDRESS CONVERTIONS
	//Virtual Address (VA) to Relative Virtual Address (RVA) convertions
	//for PE32 and PE64 respectively
	//bound_check checks integer overflow
	virtual DWORD va_to_rva(DWORD va, bool bound_check = true) const = 0;
	virtual DWORD va_to_rva(ULONGLONG va, bool bound_check = true) const = 0;

	//Relative Virtual Address (RVA) to Virtual Address (VA) convertions
	//for PE32 and PE64 respectively
	virtual DWORD rva_to_va_32(DWORD rva) const = 0;
	void rva_to_va(DWORD rva, DWORD& va) const;
	virtual ULONGLONG rva_to_va_64(DWORD rva) const = 0;
	void rva_to_va(DWORD rva, ULONGLONG& va) const;

	//RVA to RAW file offset convertion (4gb max)
	DWORD rva_to_file_offset(DWORD rva) const;
	//RAW file offset to RVA convertion (4gb max)
	DWORD file_offset_to_rva(DWORD offset) const;

	//RVA from section raw data offset
	static DWORD rva_from_section_offset(const section& s, DWORD raw_offset_from_section_start);

public: //IMAGE SECTIONS
	typedef std::vector<pe_base::section> section_list;

	//Enumeration of section data types, used in functions below
	enum section_data_type
	{
		section_data_raw,
		section_data_virtual
	};

	//Returns number of sections
	virtual WORD get_number_of_sections() const = 0;

	//Returns section alignment
	virtual DWORD get_section_alignment() const = 0;

	//Returns section list
	section_list& get_image_sections();
	const section_list& get_image_sections() const;

	//Realigns all sections, if you made any changes to sections or alignments
	void realign_all_sections();
	//Resligns section with specified index
	void realign_section(unsigned int index);

	//Returns section from RVA inside it
	section& section_from_rva(DWORD rva);
	const section& section_from_rva(DWORD rva) const;
	//Returns section from directory ID
	section& section_from_directory(unsigned long directory_id);
	const section& section_from_directory(unsigned long directory_id) const;
	//Returns section from VA inside it for PE32 and PE64 respectively
	section& section_from_va(DWORD va);
	const section& section_from_va(DWORD va) const;
	section& section_from_va(ULONGLONG va);
	const section& section_from_va(ULONGLONG va) const;
	//Returns section from file offset (4gb max)
	section& section_from_file_offset(DWORD offset);
	const section& section_from_file_offset(DWORD offset) const;

	//Returns section TOTAL RAW/VIRTUAL data length from RVA inside section
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	unsigned long section_data_length_from_rva(DWORD rva, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	//Returns section TOTAL RAW/VIRTUAL data length from VA inside section for PE32 and PE64 respectively
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	unsigned long section_data_length_from_va(DWORD va, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	unsigned long section_data_length_from_va(ULONGLONG va, section_data_type datatype = section_data_raw, bool include_headers = false) const;

	//Returns section remaining RAW/VIRTUAL data length from RVA to the end of section "s" (checks bounds)
	static unsigned long section_data_length_from_rva(const section& s, DWORD rva_inside, section_data_type datatype = section_data_raw);
	//Returns section remaining RAW/VIRTUAL data length from VA to the end of section "s" for PE32 and PE64 respectively (checks bounds)
	unsigned long section_data_length_from_va(const section& s, ULONGLONG va_inside, section_data_type datatype = section_data_raw) const;
	unsigned long section_data_length_from_va(const section& s, DWORD va_inside, section_data_type datatype = section_data_raw) const;

	//Returns section remaining RAW/VIRTUAL data length from RVA "rva_inside" to the end of section containing RVA "rva"
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	unsigned long section_data_length_from_rva(DWORD rva, DWORD rva_inside, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	//Returns section remaining RAW/VIRTUAL data length from VA "va_inside" to the end of section containing VA "va" for PE32 and PE64 respectively
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	unsigned long section_data_length_from_va(DWORD va, DWORD va_inside, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	unsigned long section_data_length_from_va(ULONGLONG va, ULONGLONG va_inside, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	//Returns corresponding section data pointer from RVA inside section
	char* section_data_from_rva(DWORD rva, bool include_headers = false);
	const char* section_data_from_rva(DWORD rva, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	//Returns corresponding section data pointer from VA inside section for PE32 and PE64 respectively
	char* section_data_from_va(DWORD va, bool include_headers = false);
	const char* section_data_from_va(DWORD va, section_data_type datatype = section_data_raw, bool include_headers = false) const;
	char* section_data_from_va(ULONGLONG va, bool include_headers = false);
	const char* section_data_from_va(ULONGLONG va, section_data_type datatype = section_data_raw, bool include_headers = false) const;

	//Returns corresponding section data pointer from RVA inside section "s" (checks bounds)
	static char* section_data_from_rva(section& s, DWORD rva);
	static const char* section_data_from_rva(const section& s, DWORD rva, section_data_type datatype = section_data_raw);

	//Returns corresponding section data pointer from VA inside section "s" for PE32 and PE64 respectively (checks bounds)
	char* section_data_from_va(section& s, DWORD va); //Always returns raw data
	const char* section_data_from_va(const section& s, DWORD va, section_data_type datatype = section_data_raw) const;
	char* section_data_from_va(section& s, ULONGLONG va); //Always returns raw data
	const char* section_data_from_va(const section& s, ULONGLONG va, section_data_type datatype = section_data_raw) const;

	//Returns corresponding section data pointer from RVA inside section "s" (checks bounds, checks sizes, the most safe function)
	template<typename T>
	static T section_data_from_rva(const section& s, DWORD rva, section_data_type datatype = section_data_raw)
	{
		if(rva >= s.header_.VirtualAddress && rva < s.header_.VirtualAddress + s.virtual_size_aligned_ && is_sum_safe(rva, sizeof(T)))
		{
			const std::string& data = datatype == section_data_raw ? s.get_raw_data() : s.get_virtual_data();
			//Don't check for underflow here, comparsion is unsigned
			if(data.size() < rva - s.header_.VirtualAddress + sizeof(T))
				throw pe_exception("RVA and requested data size does not exist inside section", pe_exception::rva_not_exists);

			return *reinterpret_cast<const T*>(data.data() + rva - s.header_.VirtualAddress);
		}

		throw pe_exception("RVA not found inside section", pe_exception::rva_not_exists);
	}

	//Returns corresponding section data pointer from RVA inside section (checks rva, checks sizes, the most safe function)
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	template<typename T>
	T section_data_from_rva(DWORD rva, section_data_type datatype = section_data_raw, bool include_headers = false) const
	{
		//if RVA is inside of headers and we're searching them too...
		if(include_headers && is_sum_safe(rva, sizeof(T)) && (rva + sizeof(T) < full_headers_data_.length()))
			return *reinterpret_cast<const T*>(&full_headers_data_[rva]);

		const section& s = section_from_rva(rva);
		const std::string& data = datatype == section_data_raw ? s.get_raw_data() : s.get_virtual_data();
		//Don't check for underflow here, comparsion is unsigned
		if(data.size() < rva - s.header_.VirtualAddress + sizeof(T))
			throw pe_exception("RVA and requested data size does not exist inside section", pe_exception::rva_not_exists);

		return *reinterpret_cast<const T*>(data.data() + rva - s.header_.VirtualAddress);
	}

	//Returns corresponding section data pointer from VA inside section "s" (checks bounds, checks sizes, the most safe function)
	template<typename T>
	static T section_data_from_va(const section& s, DWORD va, section_data_type datatype = section_data_raw)
	{
		return section_data_from_rva<T>(s, va_to_rva(va), datatype);
	}

	template<typename T>
	static T section_data_from_va(const section& s, ULONGLONG va, section_data_type datatype = section_data_raw)
	{
		return section_data_from_rva<T>(s, va_to_rva(va), datatype);
	}

	//Returns corresponding section data pointer from VA inside section (checks rva, checks sizes, the most safe function)
	//If include_headers = true, data from the beginning of PE file to SizeOfHeaders will be searched, too
	template<typename T>
	T section_data_from_va(DWORD va, section_data_type datatype = section_data_raw, bool include_headers = false) const
	{
		return section_data_from_rva<T>(va_to_rva(va), datatype, include_headers);
	}

	template<typename T>
	T section_data_from_va(ULONGLONG va, section_data_type datatype = section_data_raw, bool include_headers = false) const
	{
		return section_data_from_rva<T>(va_to_rva(va), datatype, include_headers);
	}

	//Returns section and offset (raw data only) from its start from RVA
	const std::pair<DWORD, const section*> section_and_offset_from_rva(DWORD rva) const;

	//Sets virtual size of section "s"
	//Section must be free (not bound to any image)
	//or the last section of this image
	//Function calls update_image_size automatically in second case
	void set_section_virtual_size(section& s, DWORD vsize);

	//Represents section expand type for expand_section function
	enum section_expand_type
	{
		expand_section_raw, //Section raw data size will be expanded
		expand_section_virtual //Section virtual data size will be expanded
	};

	//Expands section raw or virtual size to hold data from specified RVA with specified size
	//Section must be free (not bound to any image)
	//or the last section of this image
	//Returns true if section was expanded
	bool expand_section(section& s, DWORD needed_rva, DWORD needed_size, section_expand_type expand);

	//Adds section to image
	//Returns last section
	section& add_section(section s);
	//Prepares section to later add it to image (checks and recalculates virtual and raw section size)
	//Section must be prepared by this function before calling add_section
	void prepare_section(section& s);

	//Returns true if sectios "s" is already attached to this PE file
	bool section_attached(const section& s) const;


public: //IMAGE
	//Enumeration of PE types
	enum pe_type
	{
		pe_type_32,
		pe_type_64
	};

	//Returns PE type (PE or PE+) from pe_type enumeration (minimal correctness checks)
	static pe_type get_pe_type(std::istream& file);
	//Returns PE type of this image
	virtual pe_type get_pe_type() const = 0;

	//Returns true if image has overlay data at the end of file
	bool has_overlay() const;

	//Calculate checksum of image (performs no checks on PE structures)
	static DWORD calculate_checksum(std::istream& file);

	//Rebuilds PE image. If strip_dos_header == true, DOS header will be stripped a little
	//If change_size_of_headers == true, SizeOfHeaders will be recalculated automatically
	void rebuild_pe(bool strip_dos_header = false, bool change_size_of_headers = true);
	//Rebuilds PE image, writes resulting image to ostream "out". If strip_dos_header == true, DOS header will be stripped a little
	//If change_size_of_headers == true, SizeOfHeaders will be recalculated automatically
	void rebuild_pe(std::ostream& out, bool strip_dos_header = false, bool change_size_of_headers = true);

	//Realigns file (changes file alignment)
	void realign_file(unsigned long new_file_alignment);

public: //EXPORTS
	//Structure representing exported function
	struct exported_function
	{
	public:
		//Default constructor
		exported_function();

		//Returns ordinal of function (actually, ordinal = hint + ordinal base)
		WORD get_ordinal() const;

		//Returns RVA of function
		DWORD get_rva() const;

		//Returns true if function has name and name ordinal
		bool has_name() const;
		//Returns name of function
		const std::string& get_name() const;
		//Returns name ordinal of function
		WORD get_name_ordinal() const;

		//Returns true if function is forwarded to other library
		bool is_forwarded() const;
		//Returns the name of forwarded function
		const std::string& get_forwarded_name() const;

	public: //Setters do not change everything inside image, they are used by PE class
		//You can also use them to rebuild export directory

		//Sets ordinal of function
		void set_ordinal(WORD ordinal);

		//Sets RVA of function
		void set_rva(DWORD rva);

		//Sets name of function (or clears it, if empty name is passed)
		void set_name(const std::string& name);
		//Sets name ordinal
		void set_name_ordinal(WORD name_ordinal);

		//Sets forwarded function name (or clears it, if empty name is passed)
		void set_forwarded_name(const std::string& name);

	private:
		WORD ordinal_; //Function ordinal
		DWORD rva_; //Function RVA
		std::string name_; //Function name
		bool has_name_; //true == function has name
		WORD name_ordinal_; //Function name ordinal
		bool forward_; //true == function is forwarded
		std::string forward_name_; //Name of forwarded function
	};

	//Structure representing export information
	struct export_info
	{
	public:
		//Default constructor
		export_info();

		//Returns characteristics
		DWORD get_characteristics() const;
		//Returns timestamp
		DWORD get_timestamp() const;
		//Returns major version
		WORD get_major_version() const;
		//Returns minor version
		WORD get_minor_version() const;
		//Returns DLL name
		const std::string& get_name() const;
		//Returns ordinal base
		DWORD get_ordinal_base() const;
		//Returns number of functions
		DWORD get_number_of_functions() const;
		//Returns number of function names
		DWORD get_number_of_names() const;
		//Returns RVA of function address table
		DWORD get_rva_of_functions() const;
		//Returns RVA of function name address table
		DWORD get_rva_of_names() const;
		//Returns RVA of name ordinals table
		DWORD get_rva_of_name_ordinals() const;

	public: //Setters do not change everything inside image, they are used by PE class
		//You can also use them to rebuild export directory using rebuild_exports

		//Sets characteristics
		void set_characteristics(DWORD characteristics);
		//Sets timestamp
		void set_timestamp(DWORD timestamp);
		//Sets major version
		void set_major_version(WORD major_version);
		//Sets minor version
		void set_minor_version(WORD minor_version);
		//Sets DLL name
		void set_name(const std::string& name);
		//Sets ordinal base
		void set_ordinal_base(DWORD ordinal_base);
		//Sets number of functions
		void set_number_of_functions(DWORD number_of_functions);
		//Sets number of function names
		void set_number_of_names(DWORD number_of_names);
		//Sets RVA of function address table
		void set_rva_of_functions(DWORD rva_of_functions);
		//Sets RVA of function name address table
		void set_rva_of_names(DWORD rva_of_names);
		//Sets RVA of name ordinals table
		void set_rva_of_name_ordinals(DWORD rva_of_name_ordinals);

	private:
		DWORD characteristics_;
		DWORD timestamp_;
		WORD major_version_;
		WORD minor_version_;
		std::string name_;
		DWORD ordinal_base_;
		DWORD number_of_functions_;
		DWORD number_of_names_;
		DWORD address_of_functions_;
		DWORD address_of_names_;
		DWORD address_of_name_ordinals_;
	};


public: //EXPORTS
	typedef std::vector<exported_function> exported_functions_list;

	//Returns array of exported functions
	const exported_functions_list get_exported_functions() const;
	//Returns array of exported functions and information about export
	const exported_functions_list get_exported_functions(export_info& info) const;
	
	//Helper export functions
	//Returns pair: <ordinal base for supplied functions; maximum ordinal value for supplied functions>
	static const std::pair<WORD, WORD> get_export_ordinal_limits(const exported_functions_list& exports);

	//Checks if exported function name already exists
	static bool exported_name_exists(const std::string& function_name, const exported_functions_list& exports);

	//Checks if exported function ordinal already exists
	static bool exported_ordinal_exists(WORD ordinal, const exported_functions_list& exports);

	//Export directory rebuilder
	//info - export information
	//exported_functions_list - list of exported functions
	//exports_section - section where export directory will be placed (must be attached to PE image)
	//offset_from_section_start - offset from exports_section raw data start
	//save_to_pe_headers - if true, new export directory information will be saved to PE image headers
	//auto_strip_last_section - if true and exports are placed in the last section, it will be automatically stripped
	//number_of_functions and number_of_names parameters don't matter in "info" when rebuilding, they're calculated independently
	//characteristics, major_version, minor_version, timestamp and name are the only used members of "info" structure
	//Returns new export directory information
	//exported_functions_list is copied intentionally to be sorted by ordinal values later
	//Name ordinals in exported function doesn't matter, they will be recalculated
	const image_directory rebuild_exports(const export_info& info, exported_functions_list exports, section& exports_section, DWORD offset_from_section_start = 0, bool save_to_pe_header = true, bool auto_strip_last_section = true);


public: //IMPORTS
	//Structure representing imported function
	struct imported_function
	{
	public:
		//Default constructor
		imported_function();

		//Returns true if imported function has name (and hint)
		bool has_name() const;
		//Returns name of function
		const std::string& get_name() const;
		//Returns hint
		WORD get_hint() const;
		//Returns ordinal of function
		WORD get_ordinal() const;

		//Returns IAT entry VA (usable if image has both IAT and original IAT and is bound)
		ULONGLONG get_iat_va() const;

	public: //Setters do not change everything inside image, they are used by PE class
		//You also can use them to rebuild image imports
		//Sets name of function
		void set_name(const std::string& name);
		//Sets hint
		void set_hint(WORD hint);
		//Sets ordinal
		void set_ordinal(WORD ordinal);

		//Sets IAT entry VA (usable if image has both IAT and original IAT and is bound)
		void set_iat_va(ULONGLONG rva);

	private:
		std::string name_; //Function name
		WORD ordinal_; //Ordinal
		WORD hint_; //Hint
		ULONGLONG iat_va_;
	};

	//Structure representing imported library information
	struct import_library
	{
	public:
		typedef std::vector<imported_function> imported_list;

	public:
		//Default constructor
		import_library();

		//Returns name of library
		const std::string& get_name() const;
		//Returns RVA to Import Address Table (IAT)
		DWORD get_rva_to_iat() const;
		//Returns RVA to Original Import Address Table (Original IAT)
		DWORD get_rva_to_original_iat() const;
		//Returns timestamp
		DWORD get_timestamp() const;

		//Returns imported functions list
		const imported_list& get_imported_functions() const;

	public: //Setters do not change everything inside image, they are used by PE class
		//You also can use them to rebuild image imports
		//Sets name of library
		void set_name(const std::string& name);
		//Sets RVA to Import Address Table (IAT)
		void set_rva_to_iat(DWORD rva_to_iat);
		//Sets RVA to Original Import Address Table (Original IAT)
		void set_rva_to_original_iat(DWORD rva_to_original_iat);
		//Sets timestamp
		void set_timestamp(DWORD timestamp);

		//Adds imported function
		void add_import(const imported_function& func);
		//Clears imported functions list
		void clear_imports();

	private:
		std::string name_; //Library name
		DWORD rva_to_iat_; //RVA to IAT
		DWORD rva_to_original_iat_; //RVA to original IAT
		DWORD timestamp_; //DLL TimeStamp

		imported_list imports_;
	};

	typedef std::vector<import_library> imported_functions_list;

	//Returns imported functions list with related libraries info
	virtual const imported_functions_list get_imported_functions() const = 0;


	//Simple import directory rebuilder
	//Structure representing import rebuilder advanced settings
	struct import_rebuilder_settings
	{
	public:
		//Default constructor
		//Default constructor
		//If set_to_pe_headers = true, IMAGE_DIRECTORY_ENTRY_IMPORT entry will be reset
		//to new value after import rebuilding
		//If auto_zero_directory_entry_iat = true, IMAGE_DIRECTORY_ENTRY_IAT will be set to zero
		//IMAGE_DIRECTORY_ENTRY_IAT is used by loader to temporarily make section, where IMAGE_DIRECTORY_ENTRY_IAT RVA points, writeable
		//to be able to modify IAT thunks
		explicit import_rebuilder_settings(bool set_to_pe_headers = true, bool auto_zero_directory_entry_iat = false);

		//Returns offset from section start where import directory data will be placed
		DWORD get_offset_from_section_start() const;
		//Returns true if Original import address table (IAT) will be rebuilt
		bool build_original_iat() const;

		//Returns true if Original import address and import address tables will not be rebuilt,
		//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
		bool save_iat_and_original_iat_rvas() const;
		//Returns true if Original import address and import address tables contents will be rewritten
		//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
		//and save_iat_and_original_iat_rvas is true
		bool rewrite_iat_and_original_iat_contents() const;

		//Returns true if original missing IATs will be rebuilt
		//(only if IATs are saved)
		bool fill_missing_original_iats() const;
		//Returns true if PE headers should be updated automatically after rebuilding of imports
		bool auto_set_to_pe_headers() const;
		//Returns true if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
		bool zero_directory_entry_iat() const;

		//Returns true if the last section should be stripped automatically, if imports are inside it
		bool auto_strip_last_section_enabled() const;


	public: //Setters
		//Sets offset from section start where import directory data will be placed
		void set_offset_from_section_start(DWORD offset);
		//Sets if Original import address table (IAT) will be rebuilt
		void build_original_iat(bool enable);
		//Sets if Original import address and import address tables will not be rebuilt,
		//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
		//enable_rewrite_iat_and_original_iat_contents sets if Original import address and import address tables contents will be rewritten
		//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
		//and save_iat_and_original_iat_rvas is true
		void save_iat_and_original_iat_rvas(bool enable, bool enable_rewrite_iat_and_original_iat_contents = false);
		//Sets if original missing IATs will be rebuilt
		//(only if IATs are saved)
		void fill_missing_original_iats(bool enable);
		//Sets if PE headers should be updated automatically after rebuilding of imports
		void auto_set_to_pe_headers(bool enable);
		//Sets if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
		void zero_directory_entry_iat(bool enable);

		//Sets if the last section should be stripped automatically, if imports are inside it, default true
		void enable_auto_strip_last_section(bool enable);

	private:
		DWORD offset_from_section_start_;
		bool build_original_iat_;
		bool save_iat_and_original_iat_rvas_;
		bool fill_missing_original_iats_;
		bool set_to_pe_headers_;
		bool zero_directory_entry_iat_;
		bool rewrite_iat_and_original_iat_contents_;
		bool auto_strip_last_section_;
	};

	//You can get all image imports with get_imported_functions() function
	//You can use returned value to, for example, add new imported library with some functions
	//to the end of list of imported libraries
	//To keep PE file working, rebuild its imports with save_iat_and_original_iat_rvas = true (default)
	//Don't add new imported functions to existing imported library entries, because this can cause
	//rewriting of some used memory (or other IAT/orig.IAT fields) by system loader
	//The safest way is just adding import libraries with functions to the end of imported_functions_list array
	virtual const image_directory rebuild_imports(const imported_functions_list& imports, section& import_section, const import_rebuilder_settings& import_settings = import_rebuilder_settings()) = 0;


public: //RELOCATIONS
	//Structure representing relocation entry
	//RVA of relocation is not actually RVA, but
	//(real RVA) - (RVA of table)
	struct relocation_entry
	{
	public:
		//Default constructor
		relocation_entry();
		//Constructor from relocation item (WORD)
		explicit relocation_entry(WORD relocation_value);
		//Constructor from relative rva and relocation type
		relocation_entry(WORD rrva, WORD type);

		//Returns RVA of relocation (actually, relative RVA from relocation table RVA)
		WORD get_rva() const;
		//Returns type of relocation
		WORD get_type() const;

		//Returns relocation item (rrva + type)
		WORD get_item() const;

	public: //Setters do not change everything inside image, they are used by PE class
		//You can also use them to rebuild relocations using rebuild_relocations()

		//Sets RVA of relocation (actually, relative RVA from relocation table RVA)
		void set_rva(WORD rva);
		//Sets type of relocation
		void set_type(WORD type);
		
		//Sets relocation item (rrva + type)
		void set_item(WORD item);

	private:
		WORD rva_;
		WORD type_;
	};

	//Structure representing relocation table
	struct relocation_table
	{
	public:
		typedef std::vector<relocation_entry> relocation_list;

	public:
		//Default constructor
		relocation_table();
		//Constructor from RVA of relocation table
		explicit relocation_table(DWORD rva);

		//Returns relocation list
		const relocation_list& get_relocations() const;
		//Returns RVA of block
		DWORD get_rva() const;

	public: //These functions do not change everything inside image, they are used by PE class
		//You can also use them to rebuild relocations using rebuild_relocations()

		//Adds relocation to table
		void add_relocation(const relocation_entry& entry);
		//Returns changeable relocation list
		relocation_list& get_relocations();
		//Sets RVA of block
		void set_rva(DWORD rva);

	private:
		DWORD rva_;
		relocation_list relocations_;
	};

	typedef std::vector<relocation_table> relocation_table_list;

	//Get relocation list of pe file, supports one-word sized relocations only
	//If list_absolute_entries = true, IMAGE_REL_BASED_ABSOLUTE will be listed
	const relocation_table_list get_relocations(bool list_absolute_entries = false) const;

	//Simple relocations rebuilder
	//To keep PE file working, don't remove any of existing relocations in
	//relocation_table_list returned by a call to get_relocations() function
	//auto_strip_last_section - if true and relocations are placed in the last section, it will be automatically stripped
	//offset_from_section_start - offset from the beginning of reloc_section, where relocations data will be situated
	//If save_to_pe_header is true, PE header will be modified automatically
	const image_directory rebuild_relocations(const relocation_table_list& relocs, section& reloc_section, DWORD offset_from_section_start = 0, bool save_to_pe_header = true, bool auto_strip_last_section = true);

	//Recalculates image base with the help of relocation tables
	//Recalculates VAs of DWORDS/QWORDS in image according to relocations
	//Notice: if you move some critical structures like TLS, image relocations will not fix new
	//positions of TLS VAs. Instead, some bytes that now doesn't belong to TLS will be fixed.
	//It is recommended to rebase image in the very beginning and move all structures afterwards.
	virtual void rebase_image(const relocation_table_list& tables, ULONGLONG new_base) = 0;


public: //TLS
	//Structure representing TLS info
	//We use "DWORD" type to represent RVAs, because RVA is
	//always 32bit even in PE+
	struct tls_info
	{
	public:
		typedef std::vector<DWORD> tls_callback_list;

	public:
		//Default constructor
		tls_info();

		//Returns start RVA of TLS raw data
		DWORD get_raw_data_start_rva() const;
		//Returns end RVA of TLS raw data
		DWORD get_raw_data_end_rva() const;
		//Returns TLS index RVA
		DWORD get_index_rva() const;
		//Returns TLS callbacks RVA
		DWORD get_callbacks_rva() const;
		//Returns size of zero fill
		DWORD get_size_of_zero_fill() const;
		//Returns characteristics
		DWORD get_characteristics() const;
		//Returns raw TLS data
		const std::string& get_raw_data() const;
		//Returns TLS callbacks addresses
		const tls_callback_list& get_tls_callbacks() const;

	public: //These functions do not change everything inside image, they are used by PE class
		//You can also use them to rebuild TLS directory

		//Sets start RVA of TLS raw data
		void set_raw_data_start_rva(DWORD rva);
		//Sets end RVA of TLS raw data
		void set_raw_data_end_rva(DWORD rva);
		//Sets TLS index RVA
		void set_index_rva(DWORD rva);
		//Sets TLS callbacks RVA
		void set_callbacks_rva(DWORD rva);
		//Sets size of zero fill
		void set_size_of_zero_fill(DWORD size);
		//Sets characteristics
		void set_characteristics(DWORD characteristics);
		//Sets raw TLS data
		void set_raw_data(const std::string& data);
		//Returns TLS callbacks addresses
		tls_callback_list& get_tls_callbacks();
		//Adds TLS callback
		void add_tls_callback(DWORD rva);
		//Clears TLS callbacks list
		void clear_tls_callbacks();
		//Recalculates end address of raw TLS data
		void recalc_raw_data_end_rva();

	private:
		DWORD start_rva_, end_rva_, index_rva_, callbacks_rva_;
		DWORD size_of_zero_fill_, characteristics_;

		//Raw TLS data
		std::string raw_data_;

		//TLS callback RVAs
		tls_callback_list callbacks_;
	};

	//Get TLS info
	//If image does not have TLS, throws an exception
	virtual const tls_info get_tls_info() const = 0;
	
	//Rebuilder of TLS structures

	//Represents type of expanding of TLS section containing raw data
	//(Works only if you are writing TLS raw data to tls_section and it is the last one in the PE image on the moment of TLS rebuild)
	enum tls_data_expand_type
	{
		tls_data_expand_raw, //If there is not enough raw space for raw TLS data, it can be expanded
		tls_data_expand_virtual //If there is not enough virtual place for raw TLS data, it can be expanded
	};

	//If write_tls_callbacks = true, TLS callbacks VAs will be written to their place
	//If write_tls_data = true, TLS data will be written to its place
	//If you have chosen to rewrite raw data, only (EndAddressOfRawData - StartAddressOfRawData) bytes will be written, not the full length of string
	//representing raw data content
	//auto_strip_last_section - if true and TLS are placed in the last section, it will be automatically stripped
	virtual const image_directory rebuild_tls(const tls_info& info, section& tls_section, DWORD offset_from_section_start = 0, bool write_tls_callbacks = true, bool write_tls_data = true, tls_data_expand_type expand = tls_data_expand_raw, bool save_to_pe_header = true, bool auto_strip_last_section = true) = 0;


public: //IMAGE CONFIG
	//Structure representing image configuration information
	struct image_config_info
	{
	public:
		typedef std::vector<DWORD> se_handler_list;

	public:
		//Default constructor
		image_config_info();
		//Constructors from PE structures (no checks)
		template<typename ConfigStructure>
		explicit image_config_info(const ConfigStructure& info);

		//Returns the date and time stamp value
		DWORD get_time_stamp() const;
		//Returns major version number
		WORD get_major_version() const;
		//Returns minor version number
		WORD get_minor_version() const;
		//Returns clear global flags
		DWORD get_global_flags_clear() const;
		//Returns set global flags
		DWORD get_global_flags_set() const;
		//Returns critical section default timeout
		DWORD get_critical_section_default_timeout() const;
		//Get the size of the minimum block that
		//must be freed before it is freed (de-committed), in bytes
		ULONGLONG get_decommit_free_block_threshold() const;
		//Returns the size of the minimum total memory
		//that must be freed in the process heap before it is freed (de-committed), in bytes
		ULONGLONG get_decommit_total_free_threshold() const;
		//Returns VA of a list of addresses where the LOCK prefix is used
		ULONGLONG get_lock_prefix_table_va() const;
		//Returns the maximum allocation size, in bytes
		ULONGLONG get_max_allocation_size() const;
		//Returns the maximum block size that can be allocated from heap segments, in bytes
		ULONGLONG get_virtual_memory_threshold() const;
		//Returns process affinity mask
		ULONGLONG get_process_affinity_mask() const;
		//Returns process heap flags
		DWORD get_process_heap_flags() const;
		//Returns service pack version (CSDVersion)
		WORD get_service_pack_version() const;
		//Returns VA of edit list (reserved by system)
		ULONGLONG get_edit_list_va() const;
		//Returns a pointer to a cookie that is used by Visual C++ or GS implementation
		ULONGLONG get_security_cookie_va() const;
		//Returns VA of the sorted table of RVAs of each valid, unique handler in the image
		ULONGLONG get_se_handler_table_va() const;
		//Returns the count of unique handlers in the table
		ULONGLONG get_se_handler_count() const;

		//Returns SE Handler RVA list
		const se_handler_list& get_se_handler_rvas() const;

	public: //These functions do not change everything inside image, they are used by PE class
		//Adds SE Handler RVA to list
		void add_se_handler_rva(DWORD rva);
		//Clears SE Handler list
		void clear_se_handler_list();

	private:
		DWORD time_stamp_;
		WORD major_version_, minor_version_;
		DWORD global_flags_clear_, global_flags_set_;
		DWORD critical_section_default_timeout_;
		ULONGLONG decommit_free_block_threshold_, decommit_total_free_threshold_;
		ULONGLONG lock_prefix_table_va_;
		ULONGLONG max_allocation_size_;
		ULONGLONG virtual_memory_threshold_;
		ULONGLONG process_affinity_mask_;
		DWORD process_heap_flags_;
		WORD service_pack_version_;
		ULONGLONG edit_list_va_;
		ULONGLONG security_cookie_va_;
		ULONGLONG se_handler_table_va_;
		ULONGLONG se_handler_count_;

		se_handler_list se_handlers_;
	};

	//Returns image config info
	//If image does not have config info, throws an exception
	virtual const image_config_info get_image_config() const = 0;


public: //BOUND IMPORT
	//Structure representing bound import reference
	struct bound_import_ref
	{
	public:
		//Default constructor
		bound_import_ref();
		//Constructor from data
		bound_import_ref(const std::string& module_name, DWORD timestamp);

		//Returns imported module name
		const std::string& get_module_name() const;
		//Returns bound import date and time stamp
		DWORD get_timestamp() const;

	private:
		std::string module_name_; //Imported module name
		DWORD timestamp_; //Bound import timestamp
	};

	//Structure representing image bound import information
	struct bound_import
	{
	public:
		typedef std::vector<bound_import_ref> ref_list;

	public:
		//Default constructor
		bound_import();
		//Constructor from data
		bound_import(const std::string& module_name, DWORD timestamp);

		//Returns imported module name
		const std::string& get_module_name() const;
		//Returns bound import date and time stamp
		DWORD get_timestamp() const;

		//Returns bound references cound
		size_t get_module_ref_count() const;
		//Returns module references
		const ref_list& get_module_ref_list() const;

	public: //These functions do not change everything inside image, they are used by PE class
		//Adds module reference
		void add_module_ref(const bound_import_ref& ref);
		//Clears module references list
		void clear_module_refs();
		//Returns module references
		ref_list& get_module_ref_list();

	private:
		std::string module_name_; //Imported module name
		DWORD timestamp_; //Bound import timestamp
		ref_list refs_; //Module references list
	};

	typedef std::vector<bound_import> bound_import_module_list;

	//Returns bound import information
	const bound_import_module_list get_bound_import_module_list() const;


public: //RESOURCES
	//Structure representing resource data entry
	struct resource_data_entry
	{
	public:
		//Default constructor
		resource_data_entry();
		//Constructor from data
		resource_data_entry(const std::string& data, DWORD codepage);

		//Returns resource data codepage
		DWORD get_codepage() const;
		//Returns resource data
		const std::string& get_data() const;
		
	public: //These functions do not change everything inside image, they are used by PE class
		//You can also use them to rebuild resource directory
		
		//Sets resource data codepage
		void set_codepage(DWORD codepage);
		//Sets resource data
		void set_data(const std::string& data);

	private:
		DWORD codepage_; //Resource data codepage
		std::string data_; //Resource data
	};

	//Forward declaration
	struct resource_directory;

	//Structure representing resource directory entry
	struct resource_directory_entry
	{
	public:
		//Default constructor
		resource_directory_entry();
		//Copy constructor
		resource_directory_entry(const resource_directory_entry& other);
		//Copy assignment operator
		resource_directory_entry& operator=(const resource_directory_entry& other);

		//Returns entry ID
		DWORD get_id() const;
		//Returns entry name
		const std::wstring& get_name() const;
		//Returns true, if entry has name
		//Returns false, if entry has ID
		bool is_named() const;

		//Returns true, if entry includes resource_data_entry
		//Returns false, if entry includes resource_directory
		bool includes_data() const;
		//Returns resource_directory if entry includes it, otherwise throws an exception
		const resource_directory& get_resource_directory() const;
		//Returns resource_data_entry if entry includes it, otherwise throws an exception
		const resource_data_entry& get_data_entry() const;

		//Destructor
		~resource_directory_entry();

	public: //These functions do not change everything inside image, they are used by PE class
		//You can also use them to rebuild resource directory

		//Sets entry name
		void set_name(const std::wstring& name);
		//Sets entry ID
		void set_id(DWORD id);
		
		//Returns resource_directory if entry includes it, otherwise throws an exception
		resource_directory& get_resource_directory();
		//Returns resource_data_entry if entry includes it, otherwise throws an exception
		resource_data_entry& get_data_entry();

		//Adds resource_data_entry
		void add_data_entry(const resource_data_entry& entry);
		//Adds resource_directory
		void add_resource_directory(const resource_directory& dir);

	private:
		//Destroys included data
		void release();

	private:
		DWORD id_;
		std::wstring name_;

		union includes
		{
			//Default constructor
			includes();

			//We use pointers, we're doing manual copying here
			struct resource_data_entry* data_;
			struct resource_directory* dir_; //We use pointer, because structs include each other
		};

		includes ptr_;

		bool includes_data_, named_;
	};

	//Structure representing resource directory
	struct resource_directory
	{
	public:
		typedef std::vector<resource_directory_entry> entry_list;

	public:
		//Default constructor
		resource_directory();
		//Constructor from data
		explicit resource_directory(const IMAGE_RESOURCE_DIRECTORY& dir);

		//Returns characteristics of directory
		DWORD get_characteristics() const;
		//Returns date and time stamp of directory
		DWORD get_timestamp() const;
		//Returns number of named entries
		DWORD get_number_of_named_entries() const;
		//Returns number of ID entries
		DWORD get_number_of_id_entries() const;
		//Returns major version of directory
		WORD get_major_version() const;
		//Returns minor version of directory
		WORD get_minor_version() const;
		//Returns resource_directory_entry array
		const entry_list& get_entry_list() const;
		//Returns resource_directory_entry by ID. If not found - throws an exception
		const resource_directory_entry& entry_by_id(DWORD id) const;
		//Returns resource_directory_entry by name. If not found - throws an exception
		const resource_directory_entry& entry_by_name(const std::wstring& name) const;

	public: //These functions do not change everything inside image, they are used by PE class
		//You can also use them to rebuild resource directory

		//Adds resource_directory_entry
		void add_resource_directory_entry(const resource_directory_entry& entry);
		//Clears resource_directory_entry array
		void clear_resource_directory_entry_list();

		//Sets characteristics of directory
		void set_characteristics(DWORD characteristics);
		//Sets date and time stamp of directory
		void set_timestamp(DWORD timestamp);
		//Sets number of named entries
		void set_number_of_named_entries(DWORD number);
		//Sets number of ID entries
		void set_number_of_id_entries(DWORD number);
		//Sets major version of directory
		void set_major_version(WORD major_version);
		//Sets minor version of directory
		void get_minor_version(WORD minor_version);
		
		//Returns resource_directory_entry array
		entry_list& get_entry_list();

	private:
		DWORD characteristics_;
		DWORD timestamp_;
		WORD major_version_, minor_version_;
		DWORD number_of_named_entries_, number_of_id_entries_;
		entry_list entries_;

	public: //Finder helpers
		//Finds resource_directory_entry by ID
		struct id_entry_finder
		{
		public:
			explicit id_entry_finder(DWORD id);
			bool operator()(const resource_directory_entry& entry) const;

		private:
			DWORD id_;
		};

		//Finds resource_directory_entry by name
		struct name_entry_finder
		{
		public:
			explicit name_entry_finder(const std::wstring& name);
			bool operator()(const resource_directory_entry& entry) const;

		private:
			std::wstring name_;
		};

		//Finds resource_directory_entry by name or ID (universal)
		struct entry_finder
		{
		public:
			explicit entry_finder(const std::wstring& name);
			explicit entry_finder(DWORD id);
			bool operator()(const resource_directory_entry& entry) const;

		private:
			std::wstring name_;
			DWORD id_;
			bool named_;
		};
	};

	//Returns resources (root resource_directory) from PE file
	const resource_directory get_resources() const;

	//Resources rebuilder
	//resource_directory - root resource directory
	//resources_section - section where resource directory will be placed (must be attached to PE image)
	//resource_directory is non-constant, because it will be sorted
	//offset_from_section_start - offset from resources_section raw data start
	//save_to_pe_headers - if true, new resource directory information will be saved to PE image headers
	//auto_strip_last_section - if true and resources are placed in the last section, it will be automatically stripped
	//number_of_id_entries and number_of_named_entries for resource directories are recalculated and not used
	const image_directory rebuild_resources(resource_directory& info, section& resources_section, DWORD offset_from_section_start = 0, bool save_to_pe_header = true, bool auto_strip_last_section = true);


public: //EXCEPTION DIRECTORY (exists on PE+ only)
	//Structure representing exception directory entry
	struct exception_entry
	{
	public:
		//Default constructor
		exception_entry();
		//Constructor from data
		exception_entry(const IMAGE_RUNTIME_FUNCTION_ENTRY& entry, const UNWIND_INFO& unwind_info);

		//Returns starting address of function, affected by exception unwinding
		DWORD get_begin_address() const;
		//Returns ending address of function, affected by exception unwinding
		DWORD get_end_address() const;
		//Returns unwind info address
		DWORD get_unwind_info_address() const;

		//Returns UNWIND_INFO structure version
		BYTE get_unwind_info_version() const;

		//Returns unwind info flags
		BYTE get_flags() const;
		//The function has an exception handler that should be called
		//when looking for functions that need to examine exceptions
		bool has_exception_handler() const;
		//The function has a termination handler that should be called
		//when unwinding an exception
		bool has_termination_handler() const;
		//The unwind info structure is not the primary one for the procedure
		bool is_chaininfo() const;

		//Returns size of function prolog
		BYTE get_size_of_prolog() const;

		//Returns number of unwind slots
		BYTE get_number_of_unwind_slots() const;

		//If the function uses frame pointer
		bool uses_frame_pointer() const;
		//Number of the nonvolatile register used as the frame pointer,
		//using the same encoding for the operation info field of UNWIND_CODE nodes
		BYTE get_frame_pointer_register_number() const;
		//The scaled offset from RSP that is applied to the FP reg when it is established.
		//The actual FP reg is set to RSP + 16 * this number, allowing offsets from 0 to 240
		BYTE get_scaled_rsp_offset() const;

	private:
		DWORD begin_address_, end_address_, unwind_info_address_;
		BYTE unwind_info_version_;
		BYTE flags_;
		BYTE size_of_prolog_;
		BYTE count_of_codes_;
		BYTE frame_register_, frame_offset_;
	};

	typedef std::vector<exception_entry> exception_entry_list;

	//Returns exception directory data (exists on PE+ only)
	//Unwind opcodes are not listed, because their format and list are subject to change
	const exception_entry_list get_exception_directory_data() const;


public: //DEBUG
	//Structure representing advanced RSDS (PDB 7.0) information
	struct pdb_7_0_info
	{
	public:
		//Default constructor
		pdb_7_0_info();
		//Constructor from data
		explicit pdb_7_0_info(const CV_INFO_PDB70* info);

		//Returns debug PDB 7.0 structure GUID
		const GUID get_guid() const;
		//Returns age of build
		DWORD get_age() const;
		//Returns PDB file name / path
		const std::string& get_pdb_file_name() const;

	private:
		DWORD age_;
		GUID guid_;
		std::string pdb_file_name_;
	};

	//Structure representing advanced NB10 (PDB 2.0) information
	struct pdb_2_0_info
	{
	public:
		//Default constructor
		pdb_2_0_info();
		//Constructor from data
		explicit pdb_2_0_info(const CV_INFO_PDB20* info);

		//Returns debug PDB 2.0 structure signature
		DWORD get_signature() const;
		//Returns age of build
		DWORD get_age() const;
		//Returns PDB file name / path
		const std::string& get_pdb_file_name() const;

	private:
		DWORD age_;
		DWORD signature_;
		std::string pdb_file_name_;
	};

	//Structure representing advanced misc (IMAGE_DEBUG_TYPE_MISC) info
	struct misc_debug_info
	{
	public:
		//Default constructor
		misc_debug_info();
		//Constructor from data
		explicit misc_debug_info(const IMAGE_DEBUG_MISC* info);

		//Returns debug data type
		DWORD get_data_type() const;
		//Returns true if data type is exe name
		bool is_exe_name() const;

		//Returns true if debug data is UNICODE
		bool is_unicode() const;
		//Returns debug data (ANSI or UNICODE)
		const std::string& get_data_ansi() const;
		const std::wstring& get_data_unicode() const;

	private:
		DWORD data_type_;
		bool unicode_;
		std::string debug_data_ansi_;
		std::wstring debug_data_unicode_;
	};

	//Structure representing COFF (IMAGE_DEBUG_TYPE_COFF) debug info
	struct coff_debug_info
	{
	public:
		//Structure representing COFF symbol
		struct coff_symbol
		{
		public:
			//Default constructor
			coff_symbol();

			//Returns storage class
			DWORD get_storage_class() const;
			//Returns symbol index
			DWORD get_index() const;
			//Returns section number
			DWORD get_section_number() const;
			//Returns RVA
			DWORD get_rva() const;
			//Returns type
			WORD get_type() const;

			//Returns true if structure contains file name
			bool is_file() const;
			//Returns text data (symbol or file name)
			const std::string& get_symbol() const;

		public: //These functions do not change everything inside image, they are used by PE class
			//Sets storage class
			void set_storage_class(DWORD storage_class);
			//Sets symbol index
			void set_index(DWORD index);
			//Sets section number
			void set_section_number(DWORD section_number);
			//Sets RVA
			void set_rva(DWORD rva);
			//Sets type
			void set_type(WORD type);

			//Sets file name
			void set_file_name(const std::string& file_name);
			//Sets symbol name
			void set_symbol_name(const std::string& symbol_name);

		private:
			DWORD storage_class_;
			DWORD index_;
			DWORD section_number_, rva_;
			WORD type_;
			bool is_filename_;
			std::string name_;
		};

	public:
		typedef std::vector<coff_symbol> coff_symbols_list;

	public:
		//Default constructor
		coff_debug_info();
		//Constructor from data
		explicit coff_debug_info(const IMAGE_COFF_SYMBOLS_HEADER* info);

		//Returns number of symbols
		DWORD get_number_of_symbols() const;
		//Returns virtual address of the first symbol
		DWORD get_lva_to_first_symbol() const;
		//Returns number of line-number entries
		DWORD get_number_of_line_numbers() const;
		//Returns virtual address of the first line-number entry
		DWORD get_lva_to_first_line_number() const;
		//Returns relative virtual address of the first byte of code
		DWORD get_rva_to_first_byte_of_code() const;
		//Returns relative virtual address of the last byte of code
		DWORD get_rva_to_last_byte_of_code() const;
		//Returns relative virtual address of the first byte of data
		DWORD get_rva_to_first_byte_of_data() const;
		//Returns relative virtual address of the last byte of data
		DWORD get_rva_to_last_byte_of_data() const;

		//Returns COFF symbols list
		const coff_symbols_list& get_symbols() const;

	public: //These functions do not change everything inside image, they are used by PE class
		//Adds COFF symbol
		void add_symbol(const coff_symbol& sym);

	private:
		DWORD number_of_symbols_;
		DWORD lva_to_first_symbol_;
		DWORD number_of_line_numbers_;
		DWORD lva_to_first_line_number_;
		DWORD rva_to_first_byte_of_code_;
		DWORD rva_to_last_byte_of_code_;
		DWORD rva_to_first_byte_of_data_;
		DWORD rva_to_last_byte_of_data_;

	private:
		coff_symbols_list symbols_;
	};

	//Structure representing debug information
	struct debug_info
	{
	public:
		//Enumeration of debug information types
		enum debug_info_type
		{
			debug_type_unknown,
			debug_type_coff,
			debug_type_codeview,
			debug_type_fpo,
			debug_type_misc,
			debug_type_exception,
			debug_type_fixup,
			debug_type_omap_to_src,
			debug_type_omap_from_src,
			debug_type_borland,
			debug_type_reserved10,
			debug_type_clsid
		};

	public:
		//Enumeration of advanced debug information types
		enum advanced_info_type
		{
			advanced_info_none, //No advanced info
			advanced_info_pdb_7_0, //PDB 7.0
			advanced_info_pdb_2_0, //PDB 2.0
			advanced_info_misc, //MISC debug info
			advanced_info_coff, //COFF debug info
			//No advanced info structures available for types below
			advanced_info_codeview_4_0, //CodeView 4.0
			advanced_info_codeview_5_0, //CodeView 5.0
			advanced_info_codeview //CodeView
		};

	public:
		//Default constructor
		debug_info();
		//Constructor from data
		explicit debug_info(const IMAGE_DEBUG_DIRECTORY& debug);
		//Copy constructor
		debug_info(const debug_info& info);
		//Copy assignment operator
		debug_info& operator=(const debug_info& info);
		//Destructor
		~debug_info();

		//Returns debug characteristics
		DWORD get_characteristics() const;
		//Returns debug datetimestamp
		DWORD get_time_stamp() const;
		//Returns major version
		DWORD get_major_version() const;
		//Returns minor version
		DWORD get_minor_version() const;
		//Returns type of debug info (unchecked)
		DWORD get_type_raw() const;
		//Returns type of debug info from debug_info_type enumeration
		debug_info_type get_type() const;
		//Returns size of debug data (internal, .pdb or other file doesn't count)
		DWORD get_size_of_data() const;
		//Returns RVA of debug info when mapped to memory or zero, if info is not mapped
		DWORD get_rva_of_raw_data() const;
		//Returns raw file pointer to raw data
		DWORD get_pointer_to_raw_data() const;

		//Returns advanced debug information type
		advanced_info_type get_advanced_info_type() const;
		//Returns advanced debug information or throws an exception,
		//if requested information type is not contained by structure
		template<typename AdvancedInfo>
		const AdvancedInfo get_advanced_debug_info() const;

	public: //These functions do not change everything inside image, they are used by PE class
		//Sets advanced debug information
		void set_advanced_debug_info(const pdb_7_0_info& info);
		void set_advanced_debug_info(const pdb_2_0_info& info);
		void set_advanced_debug_info(const misc_debug_info& info);
		void set_advanced_debug_info(const coff_debug_info& info);

		//Sets advanced debug information type, if no advanced info structure available
		void set_advanced_info_type(advanced_info_type type);

	private:
		DWORD characteristics_;
		DWORD time_stamp_;
		DWORD major_version_, minor_version_;
		DWORD type_;
		DWORD size_of_data_;
		DWORD address_of_raw_data_; //RVA when mapped or 0
		DWORD pointer_to_raw_data_; //RAW file offset

		//Union containing advanced debug information pointer
		union advanced_info
		{
		public:
			//Default constructor
			advanced_info();

			//Returns true if advanced debug info is present
			bool is_present() const;

		public:
			pdb_7_0_info* adv_pdb_7_0_info;
			pdb_2_0_info* adv_pdb_2_0_info;
			misc_debug_info* adv_misc_info;
			coff_debug_info* adv_coff_info;
		};

		//Helper for advanced debug information copying
		void copy_advanced_info(const debug_info& info);
		//Helper for clearing any present advanced debug information
		void free_present_advanced_info();

		advanced_info advanced_debug_info_;
		//Advanced information type
		advanced_info_type advanced_info_type_;
	};

	typedef std::vector<debug_info> debug_info_list;

	//Returns debug information list
	const debug_info_list get_debug_information() const;


public: //.NET
	//Structure representing basic .NET header information
	struct basic_dotnet_info
	{
	public:
		//Default constructor
		basic_dotnet_info();
		//Constructor from data
		explicit basic_dotnet_info(const IMAGE_COR20_HEADER& header);

		//Returns major runtime version
		WORD get_major_runtime_version() const;
		//Returns minor runtime version
		WORD get_minor_runtime_version() const;

		//Returns RVA of metadata (symbol table and startup information)
		DWORD get_rva_of_metadata() const;
		//Returns size of metadata (symbol table and startup information)
		DWORD get_size_of_metadata() const;

		//Returns flags
		DWORD get_flags() const;

		//Returns true if entry point is native
		bool is_native_entry_point() const;
		//Returns true if 32 bit required
		bool is_32bit_required() const;
		//Returns true if image is IL library
		bool is_il_library() const;
		//Returns true if image uses IL only
		bool is_il_only() const;

		//Returns entry point RVA (if entry point is native)
		//Returns entry point managed token (if entry point is managed)
		DWORD get_entry_point_rva_or_token() const;

		//Returns RVA of managed resources
		DWORD get_rva_of_resources() const;
		//Returns size of managed resources
		DWORD get_size_of_resources() const;
		//Returns RVA of strong name signature
		DWORD get_rva_of_strong_name_signature() const;
		//Returns size of strong name signature
		DWORD get_size_of_strong_name_signature() const;
		//Returns RVA of code manager table
		DWORD get_rva_of_code_manager_table() const;
		//Returns size of code manager table
		DWORD get_size_of_code_manager_table() const;
		//Returns RVA of VTable fixups
		DWORD get_rva_of_vtable_fixups() const;
		//Returns size of VTable fixups
		DWORD get_size_of_vtable_fixups() const;
		//Returns RVA of export address table jumps
		DWORD get_rva_of_export_address_table_jumps() const;
		//Returns size of export address table jumps
		DWORD get_size_of_export_address_table_jumps() const;
		//Returns RVA of managed native header
		//(precompiled header info, usually set to zero, for internal use)
		DWORD get_rva_of_managed_native_header() const;
		//Returns size of managed native header
		//(precompiled header info, usually set to zero, for internal use)
		DWORD get_size_of_managed_native_header() const;

	private:
		IMAGE_COR20_HEADER header_;
	};

	//Returns basic .NET information
	//If image is not native, throws an exception
	const basic_dotnet_info get_basic_dotnet_info() const;


public: //ENTROPY
	//Calculates entropy for PE image section
	static double calculate_entropy(const section& s);

	//Calculates entropy for istream (from current position of stream)
	static double calculate_entropy(std::istream& file);

	//Calculates entropy for data block
	static double calculate_entropy(const char* data, size_t length);

	//Calculates entropy for this PE file (only section data)
	double calculate_entropy() const;


public: //UTILS
	//Returns true if string "data" with maximum length "raw_length" is null-terminated
	template<typename T>
	static bool is_null_terminated(const T* data, size_t raw_length)
	{
		raw_length /= sizeof(T);
		for(size_t l = 0; l < raw_length; l++)
		{
			if(data[l] == static_cast<T>(L'\0'))
				return true;
		}

		return false;
	}

	//Helper template function to strip nullbytes in the end of string
	template<typename T>
	static void strip_nullbytes(std::basic_string<T>& str)
	{
		while(!*(str.end() - 1) && !str.empty())
			str.erase(str.length() - 1);
	}

	//Helper function to determine if number is power of 2
	template<typename T>
	static inline bool is_power_of_2(T x)
	{
		return !(x & (x - 1));
	}

	//Helper function to align number down
	template<typename T>
	static inline T align_down(T x, DWORD align)
	{
		return x & ~(static_cast<T>(align) - 1);
	}

	//Helper function to align number up
	template<typename T>
	static inline T align_up(T x, DWORD align)
	{
		return (x & static_cast<T>(align - 1)) ? align_down(x, align) + static_cast<T>(align) : x;
	}

	//Returns true if sum of two unsigned integers is safe (no overflow occurs)
	static inline bool is_sum_safe(DWORD a, DWORD b)
	{
		return a <= static_cast<DWORD>(-1) - b;
	}

	//Two gigabytes value in bytes
	static const DWORD two_gb = 0x80000000;
	static const DWORD max_dword = 0xFFFFFFFF;
	static const DWORD max_word = 0x0000FFFF;
	static const double log_2; //instead of using M_LOG2E


	// ========== END OF PUBLIC MEMBERS AND STRUCTURES ========== //
protected:
	//Image DOS header
	IMAGE_DOS_HEADER dos_header_;
	//Rich (stub) overlay data (for MSVS)
	std::string rich_overlay_;
	//List of image sections
	section_list sections_;
	//Pointer to section data
	std::size_t ptr_to_section_data_;
	//True if image has overlay
	bool has_overlay_;
	//Calculated PE file checksum
	unsigned long long checksum;
	//Raw bound import structures data
	std::string bound_import_data_;
	//Raw SizeOfHeaders-sized data from the beginning of image
	std::string full_headers_data_;
	//Raw debug data for all directories
	//PointerToRawData; Data
	typedef std::multimap<DWORD, std::string> debug_data_list;
	debug_data_list debug_data_;

	//Reads and checks DOS header
	void read_dos_header(std::istream& file);
	//Reads and checks DOS header
	static void read_dos_header(std::istream& file, IMAGE_DOS_HEADER& header);
	//Returns stream size
	static std::streamoff get_file_size(std::istream& file);

	//Reads and checks PE headers and section headers, data
	void read_pe(std::istream& file, bool read_bound_import_raw_data, bool read_debug_raw_data);

	//Sets number of sections
	virtual void set_number_of_sections(WORD number) = 0;
	//Sets size of image
	virtual void set_size_of_image(DWORD number) = 0;
	//Sets size of headers
	virtual void set_size_of_headers(DWORD size) = 0;
	//Sets size of optional headers
	virtual void set_size_of_optional_header(WORD size) = 0;
	//Returns nt headers data pointer
	virtual char* get_nt_headers_ptr() = 0;
	//Returns sizeof() nt headers
	virtual unsigned long get_sizeof_nt_header() const = 0;
	//Returns sizeof() optional headers
	virtual unsigned long get_sizeof_opt_headers() const = 0;
	//Sets file alignment (no checks)
	virtual void set_file_alignment_unchecked(DWORD alignment) = 0;
	//Sets base of code
	virtual void set_base_of_code(DWORD base) = 0;
	//Returns needed magic of image
	virtual DWORD get_needed_magic() const = 0;

protected:
	static const WORD maximum_number_of_sections = 0x60;
	static const DWORD minimum_file_alignment = 512;
	
	//Helper function to recalculate RAW and virtual section sizes and strip it, if necessary
	//auto_strip = strip section, if necessary
	void recalculate_section_sizes(section& s, bool auto_strip);

private:
	//Returns array of exported functions and information about export (if info != 0)
	const exported_functions_list get_exported_functions(export_info* info) const;

	//Processes resource directory
	const resource_directory process_resource_directory(DWORD res_rva, DWORD offset_to_directory, std::set<DWORD>& processed) const;

	//Section by file offset finder helper (4gb max)
	struct section_by_raw_offset
	{
	public:
		explicit section_by_raw_offset(DWORD offset);
		bool operator()(const section& s) const;

	private:
		DWORD offset_;
	};

	//RAW file offset to section convertion helpers (4gb max)
	section_list::const_iterator file_offset_to_section(DWORD offset) const;
	section_list::iterator file_offset_to_section(DWORD offset);

	//Helper: finder of section* in sections list
	struct section_ptr_finder
	{
	public:
		explicit section_ptr_finder(const section& s);
		bool operator()(const section& s) const;

	private:
		const section& s_;
	};

	//Helper: sorts exported function list by ordinals
	struct ordinal_sorter
	{
	public:
		 bool operator()(const exported_function& func1, const exported_function& func2) const;
	};
	
	//Helper: sorts resource directory entries
	struct entry_sorter
	{
	public:
		bool operator()(const resource_directory_entry& entry1, const resource_directory_entry& entry2) const;
	};

	//Helper function to calculate needed space for resource data
	void calculate_resource_data_space(const resource_directory& root, DWORD& needed_size_for_structures, DWORD& needed_size_for_strings, DWORD& needed_size_for_data);

	//Helper function to rebuild resource directory
	void rebuild_resource_directory(section& resource_section, resource_directory& root, unsigned long& current_structures_pos, unsigned long& current_data_pos, unsigned long& current_strings_pos, unsigned long offset_from_section_start);

	//Calculates entropy from bytes count
	static double calculate_entropy(const DWORD byte_count[256], std::streamoff total_length);
};
