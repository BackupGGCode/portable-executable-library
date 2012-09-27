#pragma once
#include <string>
#include <vector>
#include <istream>
#include <ostream>
#include <algorithm>
#include <cmath>
#include <set>
#include "pe_exception.h"
#include "pe_base.h"

const double pe_base::log_2 = 1.44269504088896340736; //instead of using M_LOG2E

//Destructor
pe_base::~pe_base()
{}

//Section structure default constructor
pe_base::section::section()
	:raw_size_aligned_(0), virtual_size_aligned_(0), old_size_(static_cast<size_t>(-1))
{
	memset(&header_, 0, sizeof(IMAGE_SECTION_HEADER));
}

//Sets the name of section (8 characters maximum)
void pe_base::section::set_name(const std::string& name)
{
	memset(header_.Name, 0, sizeof(header_.Name));
	memcpy(header_.Name, name.c_str(), std::min<size_t>(name.length(), sizeof(header_.Name)));
}

//Returns section name
const std::string pe_base::section::get_name() const
{
	char buf[9] = {0};
	memcpy(buf, header_.Name, 8);
	return std::string(buf);
}

//Sets "readable" attribute of section
pe_base::section& pe_base::section::readable(bool readable)
{
	if(readable)
		header_.Characteristics |= IMAGE_SCN_MEM_READ;
	else
		header_.Characteristics &= ~IMAGE_SCN_MEM_READ;

	return *this;
}

//Sets "writeable" attribute of section
pe_base::section& pe_base::section::writeable(bool writeable)
{
	if(writeable)
		header_.Characteristics |= IMAGE_SCN_MEM_WRITE;
	else
		header_.Characteristics &= ~IMAGE_SCN_MEM_WRITE;

	return *this;
}

//Sets "executable" attribute of section
pe_base::section& pe_base::section::executable(bool executable)
{
	if(executable)
		header_.Characteristics |= IMAGE_SCN_MEM_EXECUTE;
	else
		header_.Characteristics &= ~IMAGE_SCN_MEM_EXECUTE;

	return *this;
}

//Returns true if section is readable
bool pe_base::section::readable() const
{
	return (header_.Characteristics & IMAGE_SCN_MEM_READ) != 0;
}

//Returns true if section is writeable
bool pe_base::section::writeable() const
{
	return (header_.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
}

//Returns true if section is executable
bool pe_base::section::executable() const
{
	return (header_.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

//Returns true if section has no RAW data
bool pe_base::section::empty() const
{
	if(old_size_ != static_cast<size_t>(-1)) //If virtual memory is mapped, check raw data length (old_size_)
		return old_size_ == 0;
	else
		return raw_data_.empty();
}

//Returns raw section data from file image
std::string& pe_base::section::get_raw_data()
{
	unmap_virtual();
	return raw_data_;
}

//Sets raw section data from file image
void pe_base::section::set_raw_data(const std::string& data)
{
	old_size_ = static_cast<size_t>(-1);
	raw_data_ = data;
}

//Returns raw section data from file image
const std::string& pe_base::section::get_raw_data() const
{
	unmap_virtual();
	return raw_data_;
}

//Returns mapped virtual section data
const std::string& pe_base::section::get_virtual_data() const
{
	map_virtual();
	return raw_data_;
}

//Returns mapped virtual section data
std::string& pe_base::section::get_virtual_data()
{
	map_virtual();
	return raw_data_;
}

//Maps virtual section data
void pe_base::section::map_virtual() const
{
	if(old_size_ == -1 && virtual_size_aligned_ && virtual_size_aligned_ > raw_data_.length())
	{
		old_size_ = raw_data_.length();
		raw_data_.resize(virtual_size_aligned_, 0);
	}
}

//Unmaps virtual section data
void pe_base::section::unmap_virtual() const
{
	if(old_size_ != static_cast<size_t>(-1))
	{
		raw_data_.resize(old_size_, 0);
		old_size_ = static_cast<size_t>(-1);
	}
}

//Returns section virtual size
DWORD pe_base::section::get_virtual_size() const
{
	return header_.Misc.VirtualSize;
}

//Returns section virtual address
DWORD pe_base::section::get_virtual_address() const
{
	return header_.VirtualAddress;
}

//Returns size of section raw data
DWORD pe_base::section::get_size_of_raw_data() const
{
	return header_.SizeOfRawData;
}

//Returns pointer to raw section data in PE file
DWORD pe_base::section::get_pointer_to_raw_data() const
{
	return header_.PointerToRawData;
}

//Returns section characteristics
DWORD pe_base::section::get_characteristics() const
{
	return header_.Characteristics;
}

//Sets size of raw section data
void pe_base::section::set_size_of_raw_data(DWORD size_of_raw_data)
{
	header_.SizeOfRawData = size_of_raw_data;
}

//Sets pointer to section raw data
void pe_base::section::set_pointer_to_raw_data(DWORD pointer_to_raw_data)
{
	header_.PointerToRawData = pointer_to_raw_data;
}

//Sets section characteristics
void pe_base::section::set_characteristics(DWORD characteristics)
{
	header_.Characteristics = characteristics;
}

//Sets section virtual size
void pe_base::section::set_virtual_size(DWORD virtual_size)
{
	header_.Misc.VirtualSize = virtual_size;
}

//Sets section virtual address
void pe_base::section::set_virtual_address(DWORD virtual_address)
{
	header_.VirtualAddress = virtual_address;
}

//Returns dos header
const IMAGE_DOS_HEADER& pe_base::get_dos_header() const
{
	return dos_header_;
}

//Returns dos header
IMAGE_DOS_HEADER& pe_base::get_dos_header()
{
	return dos_header_;
}

//Returns PE headers start position (e_lfanew)
LONG pe_base::get_pe_header_start() const
{
	return dos_header_.e_lfanew;
}

//Strips MSVC stub overlay
void pe_base::strip_stub_overlay()
{
	rich_overlay_.clear();
}

//Fills MSVC stub overlay with character c
void pe_base::fill_stub_overlay(char c)
{
	if(rich_overlay_.length())
		rich_overlay_.assign(rich_overlay_.length(), c);
}

//Returns stub overlay
const std::string& pe_base::get_stub_overlay() const
{
	return rich_overlay_;
}

//Realigns all sections
void pe_base::realign_all_sections()
{
	for(unsigned int i = 0; i < sections_.size(); i++)
		realign_section(i);
}

//Returns image sections list
pe_base::section_list& pe_base::get_image_sections()
{
	return sections_;
}

//Returns image sections list
const pe_base::section_list& pe_base::get_image_sections() const
{
	return sections_;
}

//Realigns section by index
void pe_base::realign_section(unsigned int index)
{
	//Check index
	if(sections_.size() <= index)
		throw pe_exception("Section not found", pe_exception::section_not_found);

	//Get section iterator
	section_list::iterator it = sections_.begin() + index;

	//Calculate, how many null bytes we have in the end of raw section data
	std::size_t strip = 0;
	for(std::size_t i = (*it).get_raw_data().length(); i >= 1; --i)
	{
		if((*it).get_raw_data()[i - 1] == 0)
			strip++;
		else
			break;
	}

	//Calculate aligned raw size of section
	(*it).raw_size_aligned_ = static_cast<DWORD>(align_up((*it).get_raw_data().length() - strip, get_file_alignment()));

	if(it == sections_.end() - 1) //If we're realigning the last section
	{
		//We can strip ending null bytes
		(*it).header_.SizeOfRawData = static_cast<DWORD>((*it).get_raw_data().length() - strip);
		(*it).get_raw_data().resize((*it).get_raw_data().length() - strip, 0);
	}
	else
	{
		//Else just set size of raw data
		(*it).header_.SizeOfRawData = (*it).raw_size_aligned_;
		(*it).get_raw_data().resize((*it).raw_size_aligned_, 0);
	}
}

//Sets file alignment
void pe_base::set_file_alignment(DWORD alignment)
{
	//Check alignment
	if(alignment < minimum_file_alignment)
		throw pe_exception("File alignment can't be less than 512", pe_exception::incorrect_file_alignment);

	if(!is_power_of_2(alignment))
		throw pe_exception("File alignment must be a power of 2", pe_exception::incorrect_file_alignment);

	if(alignment > get_section_alignment())
		throw pe_exception("File alignment must be <= section alignment", pe_exception::incorrect_file_alignment);

	//Set file alignment without any additional checks
	set_file_alignment_unchecked(alignment);
}

//Returns section from RVA
pe_base::section& pe_base::section_from_rva(DWORD rva)
{
	//Search for section
	for(section_list::iterator i = sections_.begin(); i != sections_.end(); ++i)
	{
		//Return section if found
		if(rva >= (*i).header_.VirtualAddress && rva < (*i).header_.VirtualAddress + (*i).virtual_size_aligned_)
			return *i;
	}

	throw pe_exception("No section found by presented address", pe_exception::no_section_found);
}

//Returns section from RVA
const pe_base::section& pe_base::section_from_rva(DWORD rva) const
{
	//Search for section
	for(section_list::const_iterator i = sections_.begin(); i != sections_.end(); ++i)
	{
		//Return section if found
		if(rva >= (*i).header_.VirtualAddress && rva < (*i).header_.VirtualAddress + (*i).virtual_size_aligned_)
			return *i;
	}

	throw pe_exception("No section found by presented address", pe_exception::no_section_found);
}

//Returns section from directory ID
pe_base::section& pe_base::section_from_directory(unsigned long directory_id)
{
	return section_from_rva(get_directory_rva(directory_id));		
}

//Returns section from directory ID
const pe_base::section& pe_base::section_from_directory(unsigned long directory_id) const
{
	return section_from_rva(get_directory_rva(directory_id));	
}

//Sets section virtual size (actual for the last one of this PE or for unbound section)
void pe_base::set_section_virtual_size(section& s, DWORD vsize)
{
	//Check if we're changing virtual size of the last section
	//Of course, we can change virtual size of section that's not bound to this PE file
	if(sections_.empty() || std::find_if(sections_.begin(), sections_.end() - 1, section_ptr_finder(s)) != sections_.end() - 1)
		throw pe_exception("Can't change virtual size of any section, except last one", pe_exception::error_changing_section_virtual_size);

	//If we're setting virtual size to zero
	if(vsize == 0)
	{
		//Set virtual size equal to aligned size of raw data
		s.virtual_size_aligned_ = align_up(s.header_.SizeOfRawData, get_section_alignment());
		s.header_.Misc.VirtualSize = s.header_.SizeOfRawData;
	}
	else
	{
		//Else set aligned virtual size
		s.virtual_size_aligned_ = align_up(vsize, get_section_alignment());
		s.header_.Misc.VirtualSize = s.virtual_size_aligned_;
	}

	//Update image size if we're changing virtual size for the last section of this PE
	if(!sections_.empty() || &s == &(*(sections_.end() - 1)))
		update_image_size();
}

//Expands section raw or virtual size to hold data from specified RVA with specified size
//Section must be free (not bound to any image)
//or the last section of this image
bool pe_base::expand_section(section& s, DWORD needed_rva, DWORD needed_size, section_expand_type expand)
{
	//Check if we're changing the last section
	//Of course, we can change the section that's not bound to this PE file
	if(sections_.empty() || std::find_if(sections_.begin(), sections_.end() - 1, section_ptr_finder(s)) != sections_.end() - 1)
		throw pe_exception("Can't expand any section, except last one", pe_exception::error_changing_section_virtual_size);

	//Check if we should expand our section
	if(expand == expand_section_raw && section_data_length_from_rva(s, needed_rva, section_data_raw) < needed_size)
	{
		//Expand section raw data
		s.get_raw_data().resize(needed_rva - s.get_virtual_address() + needed_size);
		return true;
	}
	else if(expand == expand_section_virtual && section_data_length_from_rva(s, needed_rva, section_data_virtual) < needed_size)
	{
		//Expand section virtual data
		set_section_virtual_size(s, needed_rva - s.get_virtual_address() + needed_size);
		return true;
	}
	
	return false;
}

//Updates image virtual size
void pe_base::update_image_size()
{
	//Write virtual size of image to headers
	if(!sections_.empty())
		set_size_of_image(sections_.back().header_.VirtualAddress + sections_.back().virtual_size_aligned_);
}

//Prepares section before attaching it
void pe_base::prepare_section(section& s)
{
	//Calculate its size of raw data
	s.header_.SizeOfRawData = static_cast<DWORD>(align_up(s.get_raw_data().length(), get_file_alignment()));
	s.raw_size_aligned_ = s.header_.SizeOfRawData;

	//Check section virtual and raw size
	if(!s.header_.SizeOfRawData && !s.header_.Misc.VirtualSize)
		throw pe_exception("Virtual and Physical sizes of section can't be 0 at the same time", pe_exception::zero_section_sizes);

	//If section virtual size is zero
	if(s.header_.Misc.VirtualSize == 0)
	{
		//Set its virtual size as aligned raw size
		s.virtual_size_aligned_ = align_up(s.header_.SizeOfRawData, get_section_alignment());
		s.header_.Misc.VirtualSize = s.header_.SizeOfRawData;
	}
	else
	{
		//Else calculate its virtual size
		s.virtual_size_aligned_ = std::max<DWORD>(align_up(s.header_.SizeOfRawData, get_file_alignment()),  align_up(s.header_.Misc.VirtualSize, get_section_alignment()));
	}
}

//Adds section to image
pe_base::section& pe_base::add_section(section s)
{
	if(sections_.size() >= maximum_number_of_sections)
		throw pe_exception("Maximum number of sections has been reached", pe_exception::no_more_sections_can_be_added);

	//Prepare section before adding it
	prepare_section(s);

	//Calculate section virtual address
	if(!sections_.empty())
	{
		s.header_.VirtualAddress = align_up(sections_.back().header_.VirtualAddress + sections_.back().virtual_size_aligned_, get_section_alignment());

		//We should align last section raw size, if it wasn't aligned
		section& last = sections_.back();
		last.header_.SizeOfRawData = static_cast<DWORD>(align_up(last.get_raw_data().length(), get_file_alignment()));
		s.raw_size_aligned_ = s.header_.SizeOfRawData;
	}
	else
	{
		s.header_.VirtualAddress = 
			s.header_.VirtualAddress == 0
			? align_up(get_size_of_headers(), get_section_alignment())
			: align_up(s.header_.VirtualAddress, get_section_alignment());
	}

	//Add section to the end of section list
	sections_.push_back(s);
	//Set number of sections in PE header
	set_number_of_sections(static_cast<WORD>(sections_.size()));
	//Recalculate virtual size of image
	set_size_of_image(get_size_of_image() + s.virtual_size_aligned_);
	//Return last section
	return sections_.back();
}

//Returns true if sectios "s" is already attached to this PE file
bool pe_base::section_attached(const section& s) const
{
	return sections_.end() != std::find_if(sections_.begin(), sections_.end(), section_ptr_finder(s));
}

//Returns true if image has import directory
bool pe_base::has_imports() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

//Returns true if image has export directory
bool pe_base::has_exports() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

//Returns true if image has resource directory
bool pe_base::has_resources() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

//Returns true if image has security directory
bool pe_base::has_security() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_SECURITY);
}

//Returns true if image has relocations
bool pe_base::has_reloc() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_BASERELOC) && !(get_characteristics() & IMAGE_FILE_RELOCS_STRIPPED);
}

//Returns true if image has TLS directory
bool pe_base::has_tls() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_TLS);
}

//Returns true if image has config directory
bool pe_base::has_config() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
}

//Returns true if image has bound import directory
bool pe_base::has_bound_import() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT);
}

//Returns true if image has delay import directory
bool pe_base::has_delay_import() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);
}

//Returns true if image has COM directory
bool pe_base::is_dotnet() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
}

//Returns true if image has exception directory
bool pe_base::has_exception_directory() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
}

//Returns true if image has debug directory
bool pe_base::has_debug() const
{
	return directory_exists(IMAGE_DIRECTORY_ENTRY_DEBUG);
}

//Returns corresponding section data pointer from RVA inside section "s" (checks bounds)
char* pe_base::section_data_from_rva(section& s, DWORD rva)
{
	//Check if RVA is inside section "s"
	if(rva >= s.header_.VirtualAddress && rva < s.header_.VirtualAddress + s.virtual_size_aligned_)
	{
		if(s.get_raw_data().empty())
			throw pe_exception("Section raw data is empty and cannot be changed", pe_exception::section_is_empty);

		return &s.get_raw_data()[rva - s.header_.VirtualAddress];
	}

	throw pe_exception("RVA not found inside section", pe_exception::rva_not_exists);
}

//Returns corresponding section data pointer from RVA inside section "s" (checks bounds)
const char* pe_base::section_data_from_rva(const section& s, DWORD rva, section_data_type datatype)
{
	//Check if RVA is inside section "s"
	if(rva >= s.header_.VirtualAddress && rva < s.header_.VirtualAddress + s.virtual_size_aligned_)
		return (datatype == section_data_raw ? s.get_raw_data().data() : s.get_virtual_data().c_str()) + rva - s.header_.VirtualAddress;

	throw pe_exception("RVA not found inside section", pe_exception::rva_not_exists);
}

//Returns section TOTAL RAW/VIRTUAL data length from RVA inside section
unsigned long pe_base::section_data_length_from_rva(DWORD rva, section_data_type datatype, bool include_headers) const
{
	//if RVA is inside of headers and we're searching them too...
	if(include_headers && rva < full_headers_data_.length())
		return static_cast<unsigned long>(full_headers_data_.length());

	const section& s = section_from_rva(rva);
	return static_cast<unsigned long>(datatype == section_data_raw ? s.get_raw_data().length() /* instead of SizeOfRawData */ : s.virtual_size_aligned_);
}

//Returns section TOTAL RAW/VIRTUAL data length from VA inside section for PE32
unsigned long pe_base::section_data_length_from_va(DWORD va, section_data_type datatype, bool include_headers) const
{
	return section_data_length_from_rva(va_to_rva(va), datatype, include_headers);
}

//Returns section TOTAL RAW/VIRTUAL data length from VA inside section for PE32/PE64
unsigned long pe_base::section_data_length_from_va(ULONGLONG va, section_data_type datatype, bool include_headers) const
{
	return section_data_length_from_rva(va_to_rva(va), datatype, include_headers);
}

//Returns section remaining RAW/VIRTUAL data length from RVA "rva_inside" to the end of section containing RVA "rva"
unsigned long pe_base::section_data_length_from_rva(DWORD rva, DWORD rva_inside, section_data_type datatype, bool include_headers) const
{
	//if RVAs are inside of headers and we're searching them too...
	if(include_headers && rva < full_headers_data_.length() && rva_inside < full_headers_data_.length())
		return static_cast<unsigned long>(full_headers_data_.length() - rva_inside);

	const section& s = section_from_rva(rva);
	//Calculate remaining length of section data from "rva" address
	long length = static_cast<long>(datatype == section_data_raw ? s.get_raw_data().length() /* instead of SizeOfRawData */ : s.virtual_size_aligned_)
		+ s.header_.VirtualAddress - rva_inside;

	if(length < 0)
		return 0;

	return static_cast<unsigned long>(length);
}

//Returns section remaining RAW/VIRTUAL data length from VA "va_inside" to the end of section containing VA "va" for PE32
unsigned long pe_base::section_data_length_from_va(DWORD va, DWORD va_inside, section_data_type datatype, bool include_headers) const
{
	return section_data_length_from_rva(va_to_rva(va), va_to_rva(va_inside), datatype, include_headers);
}

//Returns section remaining RAW/VIRTUAL data length from VA "va_inside" to the end of section containing VA "va" for PE32/PE64
unsigned long pe_base::section_data_length_from_va(ULONGLONG va, ULONGLONG va_inside, section_data_type datatype, bool include_headers) const
{
	return section_data_length_from_rva(va_to_rva(va), va_to_rva(va_inside), datatype, include_headers);
}

//Returns section remaining RAW/VIRTUAL data length from RVA to the end of section "s" (checks bounds)
unsigned long pe_base::section_data_length_from_rva(const section& s, DWORD rva_inside, section_data_type datatype)
{
	//Check rva_inside
	if(rva_inside >= s.header_.VirtualAddress && rva_inside < s.header_.VirtualAddress + s.virtual_size_aligned_)
	{
		//Calculate remaining length of section data from "rva" address
		long length = static_cast<int>(datatype == section_data_raw ? s.get_raw_data().length() /* instead of SizeOfRawData */ : s.virtual_size_aligned_)
			+ s.header_.VirtualAddress - rva_inside;

		if(length < 0)
			return 0;

		return static_cast<unsigned long>(length);
	}

	throw pe_exception("RVA not found inside section", pe_exception::rva_not_exists);
}

//Returns section remaining RAW/VIRTUAL data length from VA to the end of section "s" for PE32 (checks bounds)
unsigned long pe_base::section_data_length_from_va(const section& s, DWORD va_inside, section_data_type datatype) const
{
	return section_data_length_from_rva(s, va_to_rva(va_inside), datatype);
}

//Returns section remaining RAW/VIRTUAL data length from VA to the end of section "s" for PE32/PE64 (checks bounds)
unsigned long pe_base::section_data_length_from_va(const section& s, ULONGLONG va_inside, section_data_type datatype) const
{
	return section_data_length_from_rva(s, va_to_rva(va_inside), datatype);
}

//Returns corresponding section data pointer from RVA inside section
char* pe_base::section_data_from_rva(DWORD rva, bool include_headers)
{
	//if RVA is inside of headers and we're searching them too...
	if(include_headers && rva < full_headers_data_.length())
		return &full_headers_data_[rva];

	section& s = section_from_rva(rva);

	if(s.get_raw_data().empty())
		throw pe_exception("Section raw data is empty and cannot be changed", pe_exception::section_is_empty);

	return &s.get_raw_data()[rva - s.header_.VirtualAddress];
}

//Returns corresponding section data pointer from RVA inside section
const char* pe_base::section_data_from_rva(DWORD rva, section_data_type datatype, bool include_headers) const
{
	//if RVA is inside of headers and we're searching them too...
	if(include_headers && rva < full_headers_data_.length())
		return &full_headers_data_[rva];

	const section& s = section_from_rva(rva);
	return (datatype == section_data_raw ? s.get_raw_data().data() : s.get_virtual_data().c_str()) + rva - s.header_.VirtualAddress;
}


//STUB OVERLAY
//Default constructor
pe_base::rich_data::rich_data()
	:number_(0), version_(0), times_(0)
{}

//Who knows, what these fields mean...
DWORD pe_base::rich_data::get_number() const
{
	return number_;
}

DWORD pe_base::rich_data::get_version() const
{
	return version_;
}

DWORD pe_base::rich_data::get_times() const
{
	return times_;
}

void pe_base::rich_data::set_number(DWORD number)
{
	number_ = number;
}

void pe_base::rich_data::set_version(DWORD version)
{
	version_ = version;
}

void pe_base::rich_data::set_times(DWORD times)
{
	times_ = times;
}

//Returns MSVC rich data
const pe_base::rich_data_list pe_base::get_rich_data() const
{
	//Returned value
	rich_data_list ret;

	//If there's no rich overlay, return empty vector
	if(rich_overlay_.size() < sizeof(DWORD))
		return ret;

	//True if rich data was found
	bool found = false;

	//Rich overlay ID ("Rich" word)
	static const DWORD rich_overlay_id = 0x68636952;

	//Search for rich data overlay ID
	const char* begin = &rich_overlay_[0];
	const char* end = begin + rich_overlay_.length();
	for(; begin != end; ++begin)
	{
		if(*reinterpret_cast<const DWORD*>(begin) == rich_overlay_id)
		{
			found = true; //We've found it!
			break;
		}
	}

	//If we found it
	if(found)
	{
		//Check remaining length
		if(end - begin < sizeof(DWORD))
			return ret;

		//The XOR key is after "Rich" word, we should get it
		DWORD xorkey = *reinterpret_cast<const DWORD*>(begin + sizeof(DWORD));

		//True if rich data was found
		found = false;

		//Second search for signature "DanS"
		begin = &rich_overlay_[0];
		for(; begin != end; ++begin)
		{
			if((*reinterpret_cast<const DWORD*>(begin) ^ xorkey) == 'SnaD')
			{
				found = true;
				break;
			}
		}

		//If second signature is found
		if(found)
		{
			begin += sizeof(DWORD) * 3;
			//List all rich data structures
			while(begin < end)
			{
				begin += sizeof(DWORD);
				if(begin >= end)
					break;

				//Check for rich overlay data end ("Rich" word reached)
				if(*reinterpret_cast<const DWORD*>(begin) == rich_overlay_id)
					break;

				//Create rich_data structure
				rich_data data;
				data.set_number((*reinterpret_cast<const DWORD*>(begin) ^ xorkey) >> 16);
				data.set_version((*reinterpret_cast<const DWORD*>(begin) ^ xorkey) & 0xFFFF);

				begin += sizeof(DWORD);
				if(begin >= end)
					break;

				data.set_times(*reinterpret_cast<const DWORD*>(begin) ^ xorkey);

				//Save rich data structure
				ret.push_back(data);
			}
		}
	}

	//Return rich data structures list
	return ret;
}

//Rebuilds PE image headers
//If strip_dos_header is true, DOS headers partially will be used for PE headers
void pe_base::rebuild_pe(bool strip_dos_header, bool change_size_of_headers)
{
	//Set start of PE headers
	dos_header_.e_lfanew = sizeof(IMAGE_DOS_HEADER) + static_cast<DWORD>(rich_overlay_.size());

	if(strip_dos_header)
	{
		//Set base of code as 8 * sizeof(WORD)
		//Leave first 8 WORDs of DOS header untouched
		set_base_of_code(8 * sizeof(WORD));
		//Strip stub overlay
		strip_stub_overlay();
	}

	//Calculate pointer to section data
	ptr_to_section_data_ = align_up((strip_dos_header ? 8 * sizeof(WORD) : sizeof(IMAGE_DOS_HEADER)) + get_sizeof_nt_header() + rich_overlay_.size()
		- sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - get_number_of_rvas_and_sizes())
		+ sections_.size() * sizeof(IMAGE_SECTION_HEADER), get_file_alignment());

	//Set size of headers and size of optional header
	if(!sections_.empty() && change_size_of_headers)
		set_size_of_headers(std::min<DWORD>(static_cast<DWORD>(ptr_to_section_data_), (*sections_.begin()).header_.VirtualAddress));

	set_size_of_optional_header(static_cast<WORD>(get_sizeof_opt_headers() - sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - get_number_of_rvas_and_sizes())));

	//Recalculate pointer to raw data according to section list
	for(section_list::iterator it = sections_.begin(); it != sections_.end(); ++it)
	{
		//Save section headers PointerToRawData
		(*it).header_.PointerToRawData = static_cast<DWORD>(ptr_to_section_data_);
		ptr_to_section_data_ += (*it).raw_size_aligned_;
	}
}

//Rebuild PE image and write it to "out" ostream
//If strip_dos_header is true, DOS headers partially will be used for PE headers
void pe_base::rebuild_pe(std::ostream& out, bool strip_dos_header, bool change_size_of_headers)
{
	if(out.bad())
		throw pe_exception("Stream is bad", pe_exception::stream_is_bad);

	//Change ostream state
	out.exceptions(0);
	out.clear();

	//Rebuild PE image headers
	rebuild_pe(strip_dos_header, change_size_of_headers);

	//Write DOS header
	out.write(reinterpret_cast<const char*>(&dos_header_), strip_dos_header ? 8 * sizeof(WORD) : sizeof(IMAGE_DOS_HEADER));
	//If we have rich overlay, write it too
	if(rich_overlay_.size())
		out.write(rich_overlay_.data(), rich_overlay_.size());

	//Write NT headers
	out.write(get_nt_headers_ptr(), get_sizeof_nt_header() - sizeof(IMAGE_DATA_DIRECTORY) * (IMAGE_NUMBEROF_DIRECTORY_ENTRIES - get_number_of_rvas_and_sizes()));

	//Write section headers
	for(section_list::iterator it = sections_.begin(); it != sections_.end(); ++it)
	{
		if(it == sections_.end() - 1) //If last section encountered
		{
			IMAGE_SECTION_HEADER header = (*it).header_;
			header.SizeOfRawData = static_cast<DWORD>((*it).get_raw_data().length()); //Set non-aligned actual data length for it
			out.write(reinterpret_cast<const char*>(&header), sizeof(IMAGE_SECTION_HEADER));
		}
		else
		{
			out.write(reinterpret_cast<const char*>(&(*it).header_), sizeof(IMAGE_SECTION_HEADER));
		}
	}

	//Write section data finally
	for(section_list::iterator it = sections_.begin(); it != sections_.end(); ++it)
	{
		//Get current write position of stream
		std::streamoff wpos = out.tellp();
		//Fill unused overlay data between sections with null bytes
		for(unsigned int i = 0; i < (*it).header_.PointerToRawData - wpos; i++)
			out.put(0);

		//Write raw section data
		out.write((*it).get_raw_data().data(), (*it).get_raw_data().length());
	}
}

//Reads DOS headers from istream
void pe_base::read_dos_header(std::istream& file, IMAGE_DOS_HEADER& header)
{
	//Check istream flags
	if(file.bad() || file.eof())
		throw pe_exception("PE file stream is bad or closed.", pe_exception::bad_pe_file);

	//Read DOS header and check istream
	file.read(reinterpret_cast<char*>(&header), sizeof(IMAGE_DOS_HEADER));
	if(file.bad() || file.eof())
		throw pe_exception("Unable to read IMAGE_DOS_HEADER", pe_exception::bad_dos_header);

	//Check DOS header magic
	if(header.e_magic != 'ZM')
		throw pe_exception("IMAGE_DOS_HEADER signature is incorrect", pe_exception::bad_dos_header);
}

//Reads DOS headers from istream
void pe_base::read_dos_header(std::istream& file)
{
	read_dos_header(file, dos_header_);
}

//Reads PE image from istream
void pe_base::read_pe(std::istream& file, bool read_bound_import_raw_data, bool read_debug_raw_data)
{
	//Get istream size
	std::streamoff filesize = get_file_size(file);

	//Check if PE header is DWORD-aligned
	if((dos_header_.e_lfanew % sizeof(DWORD)) != 0)
		throw pe_exception("PE header is not DWORD-aligned", pe_exception::bad_dos_header);

	//Seek to NT headers
	file.seekg(dos_header_.e_lfanew);
	if(file.bad() || file.fail())
		throw pe_exception("Cannot reach IMAGE_NT_HEADERS", pe_exception::image_nt_headers_not_found);

	//Read NT headers
	file.read(get_nt_headers_ptr(), get_sizeof_nt_header() - sizeof(IMAGE_DATA_DIRECTORY) * 16);
	if(file.bad() || file.eof())
		throw pe_exception("Error reading IMAGE_NT_HEADERS", pe_exception::error_reading_image_nt_headers);

	//Check PE signature
	if(get_pe_signature() != 'EP')
		throw pe_exception("Incorrect PE signature", pe_exception::pe_signature_incorrect);

	//Check number of directories
	if(get_number_of_rvas_and_sizes() > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		set_number_of_rvas_and_sizes(IMAGE_NUMBEROF_DIRECTORY_ENTRIES);

	if(get_number_of_rvas_and_sizes() > 0)
	{
		//Read data directory headers, if any
		file.read(get_nt_headers_ptr() + (get_sizeof_nt_header() - sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES), sizeof(IMAGE_DATA_DIRECTORY) * get_number_of_rvas_and_sizes());
		if(file.bad() || file.eof())
			throw pe_exception("Error reading DATA_DIRECTORY headers", pe_exception::error_reading_data_directories);
	}

	//Check section number
	//Images with zero section number accepted
	if(get_number_of_sections() > maximum_number_of_sections)
		throw pe_exception("Incorrect number of sections", pe_exception::section_number_incorrect);

	//Check PE magic
	if(get_magic() != get_needed_magic())
		throw pe_exception("Incorrect PE signature", pe_exception::pe_signature_incorrect);

	//Check section alignment
	if(!is_power_of_2(get_section_alignment()))
		throw pe_exception("Incorrect section alignment", pe_exception::incorrect_section_alignment);

	//Check file alignment
	if(!is_power_of_2(get_file_alignment()))
		throw pe_exception("Incorrect file alignment", pe_exception::incorrect_file_alignment);

	if(get_file_alignment() != get_section_alignment() && (get_file_alignment() < minimum_file_alignment || get_file_alignment() > get_section_alignment()))
		throw pe_exception("Incorrect file alignment", pe_exception::incorrect_file_alignment);

	//Check size of image
	if(align_up(get_size_of_image(), get_section_alignment()) == 0)
		throw pe_exception("Incorrect size of image", pe_exception::incorrect_size_of_image);
	
	//Read rich data overlay / DOS stub (if any)
	if(dos_header_.e_lfanew > sizeof(IMAGE_DOS_HEADER))
	{
		rich_overlay_.resize(dos_header_.e_lfanew - sizeof(IMAGE_DOS_HEADER));
		file.seekg(sizeof(IMAGE_DOS_HEADER));
		file.read(&rich_overlay_[0], dos_header_.e_lfanew - sizeof(IMAGE_DOS_HEADER));
		if(file.bad() || file.eof())
			throw pe_exception("Error reading 'Rich' & 'DOS stub' overlay", pe_exception::error_reading_overlay);
	}

	//Calculate first section raw position
	//Sum is safe here
	DWORD first_section = dos_header_.e_lfanew + get_size_of_optional_header() + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) /* Signature */;

	if(get_number_of_sections() > 0)
	{
		//Go to first section
		file.seekg(first_section);
		if(file.bad() || file.fail())
			throw pe_exception("Cannot reach section headers", pe_exception::image_section_headers_not_found);
	}

	DWORD last_raw_size = 0;

	//Read all sections
	for(int i = 0; i < get_number_of_sections(); i++)
	{
		section s;
		//Read section header
		file.read(reinterpret_cast<char*>(&s.header_), sizeof(IMAGE_SECTION_HEADER));
		if(file.bad() || file.eof())
			throw pe_exception("Error reading section header", pe_exception::error_reading_section_header);

		//Save next section header position
		std::streamoff next_sect = file.tellg();

		//Check section virtual and raw sizes
		if(!s.header_.SizeOfRawData && !s.header_.Misc.VirtualSize)
			throw pe_exception("Virtual and Physical sizes of section can't be 0 at the same time", pe_exception::zero_section_sizes);

		//Check for adequate values of section fields
		if(!is_sum_safe(s.header_.VirtualAddress, s.header_.Misc.VirtualSize) || s.header_.Misc.VirtualSize > two_gb
			|| !is_sum_safe(s.header_.PointerToRawData, s.header_.SizeOfRawData) || s.header_.SizeOfRawData > two_gb)
			throw pe_exception("Incorrect section address or size", pe_exception::section_incorrect_addr_or_size);

		if(s.header_.SizeOfRawData != 0)
		{
			//If section has raw data

			//If section raw data size is greater than virtual, fix it
			last_raw_size = s.header_.SizeOfRawData;
			if(align_up(s.header_.SizeOfRawData, get_file_alignment()) > align_up(s.header_.Misc.VirtualSize, get_section_alignment()))
				s.header_.SizeOfRawData = s.header_.Misc.VirtualSize;

			//Check virtual and raw section sizes and addresses
			if(s.header_.VirtualAddress + align_up(s.header_.Misc.VirtualSize, get_section_alignment()) > align_up(get_size_of_image(), get_section_alignment())
				||
				align_down(s.header_.PointerToRawData, get_file_alignment()) + s.header_.SizeOfRawData > static_cast<DWORD>(filesize))
				throw pe_exception("Incorrect section address or size", pe_exception::section_incorrect_addr_or_size);

			//Seek to section raw data
			file.seekg(align_down(s.header_.PointerToRawData, get_file_alignment()));
			if(file.bad() || file.fail())
				throw pe_exception("Cannot reach section data", pe_exception::image_section_data_not_found);

			if(s.header_.Misc.VirtualSize == 0)
			{
				//If section virtual size is zero
				//Set aligned virtual size of section as aligned raw size
				s.virtual_size_aligned_ = align_up(s.header_.SizeOfRawData, get_section_alignment());
			}
			else
			{
				//If section virtual size is not zero
				//Set aligned virtual size of section as aligned virtual size
				s.virtual_size_aligned_ = align_up(s.header_.Misc.VirtualSize, get_section_alignment());
			}

			//Set aligned raw size of section
			s.raw_size_aligned_ = align_up(s.header_.SizeOfRawData, get_file_alignment());

			//Read section raw data
			s.get_raw_data().resize(s.header_.SizeOfRawData);
			file.read(&s.get_raw_data()[0], s.header_.SizeOfRawData);
			if(file.bad() || file.fail())
				throw pe_exception("Error reading section data", pe_exception::image_section_data_not_found);
		}
		else
		{
			//If section doesn't have raw data
			//Set raw size to zero
			s.raw_size_aligned_ = 0;
			//Calculate aligned virtual size of section
			s.virtual_size_aligned_ = align_up(s.header_.Misc.VirtualSize, get_section_alignment());
		}

		//Check virtual address and size of section
		if(s.header_.VirtualAddress + s.virtual_size_aligned_ > align_up(get_size_of_image(), get_section_alignment()))
			throw pe_exception("Incorrect section address or size", pe_exception::section_incorrect_addr_or_size);

		//Save section
		sections_.push_back(s);

		//Seek to the next section header
		file.seekg(next_sect);
	}

	//Check size of headers: SizeOfHeaders can't be larger than first section VA
	if(!sections_.empty() && get_size_of_headers() > sections_.front().header_.VirtualAddress)
		throw pe_exception("Incorrect size of headers", pe_exception::incorrect_size_of_headers);

	//If image has more than two sections
	if(sections_.size() >= 2)
	{
		//Check sections virtual sizes
		for(section_list::const_iterator i = sections_.begin() + 1; i != sections_.end(); ++i)
		{
			if((*i).header_.VirtualAddress != (*(i - 1)).header_.VirtualAddress + (*(i - 1)).virtual_size_aligned_)
				throw pe_exception("Section table is incorrect", pe_exception::image_section_table_incorrect);
		}
	}

	//Check if image has overlay in the end of file
	has_overlay_ = !sections_.empty() && filesize > static_cast<std::streamoff>(sections_.back().header_.PointerToRawData + last_raw_size);

	//If image has bound import
	if(read_bound_import_raw_data && has_bound_import())
	{
		//RVA of IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT is actually RAW address
		//So we need to read this RAW data
		file.seekg(get_directory_rva(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));

		try
		{
			bound_import_data_.resize(get_directory_size(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));
			file.read(&bound_import_data_[0], get_directory_size(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT));
			if(file.bad() || file.eof())
				bound_import_data_.resize(0); //Don't throw error here, we'll throw it at request of bound import info
		}
		catch(const std::bad_alloc&) //bad_alloc error
		{
			bound_import_data_.resize(0); //Don't throw error here, we'll throw it at request of bound import info
		}
	}

	//Additionally, read data from the beginning of istream to size of headers
	file.seekg(0);
	full_headers_data_.resize(get_size_of_headers());
	file.read(&full_headers_data_[0], get_size_of_headers());
	if(file.bad() || file.eof())
		throw pe_exception("Error reading file", pe_exception::error_reading_file);

	//Moreover, if there's debug directory, read its raw data for some debug info types
	while(read_debug_raw_data && has_debug())
	{
		try
		{
			//Check the length in bytes of the section containing debug directory
			if(section_data_length_from_rva(get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG), get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG), section_data_virtual, true) < sizeof(IMAGE_DEBUG_DIRECTORY))
				break;

			unsigned long current_pos = get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG);

			//First IMAGE_DEBUG_DIRECTORY table
			IMAGE_DEBUG_DIRECTORY directory = section_data_from_rva<IMAGE_DEBUG_DIRECTORY>(current_pos, section_data_virtual, true);

			//Iterate over all IMAGE_DEBUG_DIRECTORY directories
			while(directory.PointerToRawData
				&& current_pos < get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG) + get_directory_size(IMAGE_DIRECTORY_ENTRY_DEBUG))
			{
				//If we have something to read
				if((directory.Type == IMAGE_DEBUG_TYPE_CODEVIEW
					|| directory.Type == IMAGE_DEBUG_TYPE_MISC
					|| directory.Type == IMAGE_DEBUG_TYPE_COFF)
					&& directory.SizeOfData)
				{
					std::string data;
					data.resize(directory.SizeOfData);
					file.seekg(directory.PointerToRawData);
					file.read(&data[0], directory.SizeOfData);
					if(file.bad() || file.eof())
						throw pe_exception("Error reading file", pe_exception::error_reading_file);

					debug_data_.insert(std::make_pair(directory.PointerToRawData, data));
				}

				//Go to next debug entry
				current_pos += sizeof(IMAGE_DEBUG_DIRECTORY);
				directory = section_data_from_rva<IMAGE_DEBUG_DIRECTORY>(current_pos, section_data_virtual, true);
			}

			break;
		}
		catch(const pe_exception&)
		{
			//Don't throw any exception here, if debug info is corrupted or incorrect
			break;
		}
		catch(const std::bad_alloc&)
		{
			//Don't throw any exception here, if debug info is corrupted or incorrect
			break;
		}
	}
}

//Returns PE type (PE or PE+) from pe_type enumeration (minimal correctness checks)
pe_base::pe_type pe_base::get_pe_type(std::istream& file)
{
	//Save state of the istream
	std::ios_base::iostate state = file.exceptions();
	std::streamoff old_offset = file.tellg();
	IMAGE_NT_HEADERS32 nt_headers;
	IMAGE_DOS_HEADER header;

	try
	{
		//Read dos header
		file.exceptions(0);
		read_dos_header(file, header);

		//Seek to the NT headers start
		file.seekg(header.e_lfanew);
		if(file.bad() || file.fail())
			throw pe_exception("Cannot reach IMAGE_NT_HEADERS", pe_exception::image_nt_headers_not_found);

		//Read NT headers (we're using 32-bit version, because there's no significant differencies between 32 and 64 bit version structures)
		file.read(reinterpret_cast<char*>(&nt_headers), sizeof(IMAGE_NT_HEADERS32) - sizeof(IMAGE_DATA_DIRECTORY) * 16);
		if(file.bad() || file.eof())
			throw pe_exception("Error reading IMAGE_NT_HEADERS", pe_exception::error_reading_image_nt_headers);

		//Check NT headers signature
		if(nt_headers.Signature != 'EP')
			throw pe_exception("Incorrect PE signature", pe_exception::pe_signature_incorrect);

		//Check NT headers magic
		if(nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			throw pe_exception("Incorrect PE signature", pe_exception::pe_signature_incorrect);
	}
	catch(const std::exception&)
	{
		//If something went wrong, restore istream state
		file.exceptions(state);
		file.seekg(old_offset);
		file.clear();
		//Retrhow exception
		throw;
	}

	//Restore stream state
	file.exceptions(state);
	file.seekg(old_offset);
	file.clear();

	//Determine PE type and return it
	return nt_headers.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? pe_type_64 : pe_type_32;
}

//Returns stream size
std::streamoff pe_base::get_file_size(std::istream& file)
{
	//Get old istream offset
	std::streamoff old_offset = file.tellg();
	file.seekg(0, std::ios::end);
	std::streamoff filesize = file.tellg();
	//Set old istream offset
	file.seekg(old_offset);
	return filesize;
}

//Calculate checksum of image
DWORD pe_base::calculate_checksum(std::istream& file)
{
	//Save istream state
	std::ios_base::iostate state = file.exceptions();
	std::streamoff old_offset = file.tellg();

	//Checksum value
	unsigned long long checksum = 0;

	try
	{
		IMAGE_DOS_HEADER header;

		file.exceptions(0);

		//Read DOS header
		read_dos_header(file, header);

		//Calculate PE checksum
		file.seekg(0);
		unsigned long long top = 0xFFFFFFFF;
		top++;

		//"CheckSum" field position in optional PE headers - it's always 64 for PE and PE+
		static const unsigned long checksum_pos_in_optional_headers = 64;
		//Calculate real PE headers "CheckSum" field position
		//Sum is safe here
		unsigned long pe_checksum_pos = header.e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) + checksum_pos_in_optional_headers;

		//Calculate checksum for each byte of file
		std::streamoff filesize = get_file_size(file);
		for(long long i = 0; i < filesize; i += 4)
		{
			unsigned long dw = 0;

			//Read DWORD from file
			file.read(reinterpret_cast<char*>(&dw), sizeof(unsigned long));
			//Skip "CheckSum" DWORD
			if(i == pe_checksum_pos)
				continue;

			//Calculate checksum
			checksum = (checksum & 0xffffffff) + dw + (checksum >> 32);
			if(checksum > top)
				checksum = (checksum & 0xffffffff) + (checksum >> 32);
		}

		//Finish checksum
		checksum = (checksum & 0xffff) + (checksum >> 16);
		checksum = (checksum) + (checksum >> 16);
		checksum = checksum & 0xffff;

		checksum += static_cast<unsigned long>(filesize);
	}
	catch(const std::exception&)
	{
		//If something went wrong, restore istream state
		file.exceptions(state);
		file.seekg(old_offset);
		file.clear();
		//Rethrow
		throw;
	}

	//Restore istream state
	file.exceptions(state);
	file.seekg(old_offset);
	file.clear();

	//Return checksum
	return static_cast<DWORD>(checksum);	
}

//Returns true if image has overlay data at the end of file
bool pe_base::has_overlay() const
{
	return has_overlay_;
}

//Clears PE characteristics flag
void pe_base::clear_characteristics_flags(WORD flags)
{
	set_characteristics(get_characteristics() & ~flags);
}

//Sets PE characteristics flag
void pe_base::set_characteristics_flags(WORD flags)
{
	set_characteristics(get_characteristics() | flags);
}

//Returns true if PE characteristics flag set
bool pe_base::check_characteristics_flag(WORD flag) const
{
	return (get_characteristics() & flag) ? true : false;
}

//Returns true if image has console subsystem
bool pe_base::is_console() const
{
	return (get_subsystem() & IMAGE_SUBSYSTEM_WINDOWS_CUI) ? true : false;
}

//Returns true if image has Windows GUI subsystem
bool pe_base::is_gui() const
{
	return (get_subsystem() & IMAGE_SUBSYSTEM_WINDOWS_GUI) ? true : false;
}

//Returns corresponding section data pointer from VA inside section "s" for PE32 (checks bounds)
char* pe_base::section_data_from_va(section& s, DWORD va) //Always returns raw data
{
	return section_data_from_rva(s, va_to_rva(va));
}

//Returns corresponding section data pointer from VA inside section "s" for PE32 (checks bounds)
const char* pe_base::section_data_from_va(const section& s, DWORD va, section_data_type datatype) const
{
	return section_data_from_rva(s, va_to_rva(va), datatype);
}

//Returns corresponding section data pointer from VA inside section for PE32
char* pe_base::section_data_from_va(DWORD va, bool include_headers) //Always returns raw data
{
	return section_data_from_rva(va_to_rva(va), include_headers);
}

//Returns corresponding section data pointer from VA inside section for PE32
const char* pe_base::section_data_from_va(DWORD va, section_data_type datatype, bool include_headers) const
{
	return section_data_from_rva(va_to_rva(va), datatype, include_headers);
}

//Returns corresponding section data pointer from VA inside section "s" for PE32/PE64 (checks bounds)
char* pe_base::section_data_from_va(section& s, ULONGLONG va)  //Always returns raw data
{
	return section_data_from_rva(s, va_to_rva(va));
}

//Returns corresponding section data pointer from VA inside section "s" for PE32/PE64 (checks bounds)
const char* pe_base::section_data_from_va(const section& s, ULONGLONG va, section_data_type datatype) const
{
	return section_data_from_rva(s, va_to_rva(va), datatype);
}

//Returns corresponding section data pointer from VA inside section for PE32/PE64
char* pe_base::section_data_from_va(ULONGLONG va, bool include_headers)  //Always returns raw data
{
	return section_data_from_rva(va_to_rva(va), include_headers);
}

//Returns corresponding section data pointer from VA inside section for PE32/PE64
const char* pe_base::section_data_from_va(ULONGLONG va, section_data_type datatype, bool include_headers) const
{
	return section_data_from_rva(va_to_rva(va), datatype, include_headers);
}

//Returns section from VA inside it for PE32
pe_base::section& pe_base::section_from_va(DWORD va)
{
	return section_from_rva(va_to_rva(va));
}

//Returns section from VA inside it for PE32/PE64
pe_base::section& pe_base::section_from_va(ULONGLONG va)
{
	return section_from_rva(va_to_rva(va));
}

//Returns section from RVA inside it for PE32
const pe_base::section& pe_base::section_from_va(DWORD va) const
{
	return section_from_rva(va_to_rva(va));
}

//Returns section from RVA inside it for PE32/PE64
const pe_base::section& pe_base::section_from_va(ULONGLONG va) const
{
	return section_from_rva(va_to_rva(va));
}

//Relative Virtual Address (RVA) to Virtual Address (VA) convertion for PE32
void pe_base::rva_to_va(DWORD rva, DWORD& va) const
{
	va = rva_to_va_32(rva);
}

//Relative Virtual Address (RVA) to Virtual Address (VA) convertions for PE32/PE64
void pe_base::rva_to_va(DWORD rva, ULONGLONG& va) const
{
	va = rva_to_va_64(rva);
}

//Returns section from file offset (4gb max)
pe_base::section& pe_base::section_from_file_offset(DWORD offset)
{
	return *file_offset_to_section(offset);
}

//Returns section from file offset (4gb max)
const pe_base::section& pe_base::section_from_file_offset(DWORD offset) const
{
	return *file_offset_to_section(offset);
}

//Returns section and offset (raw data only) from its start from RVA
const std::pair<DWORD, const pe_base::section*> pe_base::section_and_offset_from_rva(DWORD rva) const
{
	const section& s = section_from_rva(rva);
	return std::make_pair(rva - s.get_virtual_address(), &s);
}

//Returns image base for PE32
void pe_base::get_image_base(DWORD& base) const
{
	base = get_image_base_32();
}

//RVA to RAW file offset convertion (4gb max)
DWORD pe_base::rva_to_file_offset(DWORD rva) const
{
	const section& s = section_from_rva(rva);
	return s.get_pointer_to_raw_data() + rva - s.get_virtual_address();
}

//RAW file offset to RVA convertion (4gb max)
DWORD pe_base::file_offset_to_rva(DWORD offset) const
{
	const section_list::const_iterator it = file_offset_to_section(offset);
	return offset - (*it).get_pointer_to_raw_data() + (*it).get_virtual_address();
}

//RAW file offset to section convertion helper (4gb max)
pe_base::section_list::const_iterator pe_base::file_offset_to_section(DWORD offset) const
{
	section_list::const_iterator it = std::find_if(sections_.begin(), sections_.end(), section_by_raw_offset(offset));
	if(it == sections_.end())
		throw pe_exception("No section found by presented file offset", pe_exception::no_section_found);

	return it;
}

//RAW file offset to section convertion helper (4gb max)
pe_base::section_list::iterator pe_base::file_offset_to_section(DWORD offset)
{
	section_list::iterator it = std::find_if(sections_.begin(), sections_.end(), section_by_raw_offset(offset));
	if(it == sections_.end())
		throw pe_exception("No section found by presented file offset", pe_exception::no_section_found);

	return it;
}

//Section by file offset finder helper (4gb max)
pe_base::section_by_raw_offset::section_by_raw_offset(DWORD offset)
	:offset_(offset)
{}

bool pe_base::section_by_raw_offset::operator()(const section& s) const
{
	return (s.get_pointer_to_raw_data() <= offset_)
		&& (s.get_pointer_to_raw_data() + s.get_size_of_raw_data() > offset_);
}

//RVA from section raw data offset
DWORD pe_base::rva_from_section_offset(const section& s, DWORD raw_offset_from_section_start)
{
	return s.get_virtual_address() + raw_offset_from_section_start;
}

//Returns image base for PE32/PE64
void pe_base::get_image_base(ULONGLONG& base) const
{
	base = get_image_base_64();
}

//Returns heap size commit for PE32
void pe_base::get_heap_size_commit(DWORD& size) const
{
	size = get_heap_size_commit_32();
}

//Returns heap size commit for PE32/PE64
void pe_base::get_heap_size_commit(ULONGLONG& size) const
{
	size = get_heap_size_commit_64();
}

//Returns heap size reserve for PE32
void pe_base::get_heap_size_reserve(DWORD& size) const
{
	size = get_heap_size_reserve_32();
}

//Returns heap size reserve for PE32/PE64
void pe_base::get_heap_size_reserve(ULONGLONG& size) const
{
	size = get_heap_size_reserve_64();
}

//Returns stack size commit for PE32
void pe_base::get_stack_size_commit(DWORD& size) const
{
	size = get_stack_size_commit_32();
}

//Returns stack size commit for PE32/PE64
void pe_base::get_stack_size_commit(ULONGLONG& size) const
{
	size = get_stack_size_commit_64();
}

//Returns stack size reserve for PE32
void pe_base::get_stack_size_reserve(DWORD& size) const
{
	size = get_stack_size_reserve_32();
}

//Returns stack size reserve for PE32/PE64
void pe_base::get_stack_size_reserve(ULONGLONG& size) const
{
	size = get_stack_size_reserve_64();
}


//EXPORTS
//Default constructor
pe_base::exported_function::exported_function()
	:ordinal_(0), rva_(0), has_name_(false), name_ordinal_(0), forward_(false)
{}

//Returns ordinal of function (actually, ordinal = hint + ordinal base)
WORD pe_base::exported_function::get_ordinal() const
{
	return ordinal_;
}

//Returns RVA of function
DWORD pe_base::exported_function::get_rva() const
{
	return rva_;
}

//Returns name of function
const std::string& pe_base::exported_function::get_name() const
{
	return name_;
}

//Returns true if function has name and name ordinal
bool pe_base::exported_function::has_name() const
{
	return has_name_;
}

//Returns name ordinal of function
WORD pe_base::exported_function::get_name_ordinal() const
{
	return name_ordinal_;
}

//Returns true if function is forwarded to other library
bool pe_base::exported_function::is_forwarded() const
{
	return forward_;
}

//Returns the name of forwarded function
const std::string& pe_base::exported_function::get_forwarded_name() const
{
	return forward_name_;
}

//Sets ordinal of function
void pe_base::exported_function::set_ordinal(WORD ordinal)
{
	ordinal_ = ordinal;
}

//Sets RVA of function
void pe_base::exported_function::set_rva(DWORD rva)
{
	rva_ = rva;
}

//Sets name of function (or clears it, if empty name is passed)
void pe_base::exported_function::set_name(const std::string& name)
{
	name_ = name;
	has_name_ = !name.empty();
}

//Sets name ordinal
void pe_base::exported_function::set_name_ordinal(WORD name_ordinal)
{
	name_ordinal_ = name_ordinal;
}

//Sets forwarded function name (or clears it, if empty name is passed)
void pe_base::exported_function::set_forwarded_name(const std::string& name)
{
	forward_name_ = name;
	forward_ = !name.empty();
}

//Default constructor
pe_base::export_info::export_info()
	:characteristics_(0),
	timestamp_(0),
	major_version_(0),
	minor_version_(0),
	ordinal_base_(0),
	number_of_functions_(0),
	number_of_names_(0),
	address_of_functions_(0),
	address_of_names_(0),
	address_of_name_ordinals_(0)
{}

//Returns characteristics
DWORD pe_base::export_info::get_characteristics() const
{
	return characteristics_;
}

//Returns timestamp
DWORD pe_base::export_info::get_timestamp() const
{
	return timestamp_;
}

//Returns major version
WORD pe_base::export_info::get_major_version() const
{
	return major_version_;
}

//Returns minor version
WORD pe_base::export_info::get_minor_version() const
{
	return minor_version_;
}

//Returns DLL name
const std::string& pe_base::export_info::get_name() const
{
	return name_;
}

//Returns ordinal base
DWORD pe_base::export_info::get_ordinal_base() const
{
	return ordinal_base_;
}

//Returns number of functions
DWORD pe_base::export_info::get_number_of_functions() const
{
	return number_of_functions_;
}

//Returns number of function names
DWORD pe_base::export_info::get_number_of_names() const
{
	return number_of_names_;
}

//Returns RVA of function address table
DWORD pe_base::export_info::get_rva_of_functions() const
{
	return address_of_functions_;
}

//Returns RVA of function name address table
DWORD pe_base::export_info::get_rva_of_names() const
{
	return address_of_names_;
}

//Returns RVA of name ordinals table
DWORD pe_base::export_info::get_rva_of_name_ordinals() const
{
	return address_of_name_ordinals_;
}

//Sets characteristics
void pe_base::export_info::set_characteristics(DWORD characteristics)
{
	characteristics_ = characteristics;
}

//Sets timestamp
void pe_base::export_info::set_timestamp(DWORD timestamp)
{
	timestamp_ = timestamp;
}

//Sets major version
void pe_base::export_info::set_major_version(WORD major_version)
{
	major_version_ = major_version;
}

//Sets minor version
void pe_base::export_info::set_minor_version(WORD minor_version)
{
	minor_version_ = minor_version;
}

//Sets DLL name
void pe_base::export_info::set_name(const std::string& name)
{
	name_ = name;
}

//Sets ordinal base
void pe_base::export_info::set_ordinal_base(DWORD ordinal_base)
{
	ordinal_base_ = ordinal_base;
}

//Sets number of functions
void pe_base::export_info::set_number_of_functions(DWORD number_of_functions)
{
	number_of_functions_ = number_of_functions;
}

//Sets number of function names
void pe_base::export_info::set_number_of_names(DWORD number_of_names)
{
	number_of_names_ = number_of_names;
}

//Sets RVA of function address table
void pe_base::export_info::set_rva_of_functions(DWORD rva_of_functions)
{
	address_of_functions_ = rva_of_functions;
}

//Sets RVA of function name address table
void pe_base::export_info::set_rva_of_names(DWORD rva_of_names)
{
	address_of_names_ = rva_of_names;
}

//Sets RVA of name ordinals table
void pe_base::export_info::set_rva_of_name_ordinals(DWORD rva_of_name_ordinals)
{
	address_of_name_ordinals_ = rva_of_name_ordinals;
}

//Returns array of exported functions
const pe_base::exported_functions_list pe_base::get_exported_functions() const
{
	return get_exported_functions(0);
}

//Returns array of exported functions and information about export
const pe_base::exported_functions_list pe_base::get_exported_functions(export_info& info) const
{
	return get_exported_functions(&info);
}

//Returns array of exported functions and information about export (if info != 0)
const std::vector<pe_base::exported_function> pe_base::get_exported_functions(export_info* info) const
{
	//Returned exported functions info array
	std::vector<exported_function> ret;

	if(has_exports())
	{
		//Check the length in bytes of the section containing export directory
		if(section_data_length_from_rva(get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT), get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT), section_data_virtual, true) < sizeof(IMAGE_EXPORT_DIRECTORY))
			throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

		IMAGE_EXPORT_DIRECTORY exports = section_data_from_rva<IMAGE_EXPORT_DIRECTORY>(get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT), section_data_virtual, true);

		unsigned long max_name_length;

		if(info)
		{
			//Save some export info data
			info->set_characteristics(exports.Characteristics);
			info->set_major_version(exports.MajorVersion);
			info->set_minor_version(exports.MinorVersion);

			//Get byte count that we have for dll name
			if((max_name_length = section_data_length_from_rva(exports.Name, exports.Name, section_data_virtual, true)) < 2)
				throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

			//Get dll name pointer
			const char* dll_name = section_data_from_rva(exports.Name, section_data_virtual, true);

			//Check for null-termination
			if(!is_null_terminated(dll_name, max_name_length))
				throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

			//Save the rest of export information data
			info->set_name(dll_name);
			info->set_number_of_functions(exports.NumberOfFunctions);
			info->set_number_of_names(exports.NumberOfNames);
			info->set_ordinal_base(exports.Base);
			info->set_rva_of_functions(exports.AddressOfFunctions);
			info->set_rva_of_names(exports.AddressOfNames);
			info->set_rva_of_name_ordinals(exports.AddressOfNameOrdinals);
			info->set_timestamp(exports.TimeDateStamp);
		}

		if(!exports.NumberOfFunctions)
			return ret;

		//Check IMAGE_EXPORT_DIRECTORY fields
		if(exports.NumberOfNames > exports.NumberOfFunctions)
			throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

		//Check some export directory fields
		if((!exports.AddressOfNameOrdinals && exports.AddressOfNames) ||
			(exports.AddressOfNameOrdinals && !exports.AddressOfNames) ||
			!exports.AddressOfFunctions
			|| exports.NumberOfFunctions >= max_dword / sizeof(DWORD)
			|| exports.NumberOfNames > max_dword / sizeof(DWORD)
			|| !is_sum_safe(exports.AddressOfFunctions, exports.NumberOfFunctions * sizeof(DWORD))
			|| !is_sum_safe(exports.AddressOfNames, exports.NumberOfNames * sizeof(DWORD))
			|| !is_sum_safe(exports.AddressOfNameOrdinals, exports.NumberOfFunctions * sizeof(DWORD))
			|| !is_sum_safe(get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT), get_directory_size(IMAGE_DIRECTORY_ENTRY_EXPORT)))
			throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

		//Check if it is enough bytes to hold AddressOfFunctions table
		if(section_data_length_from_rva(exports.AddressOfFunctions, exports.AddressOfFunctions, section_data_virtual, true) < exports.NumberOfFunctions * sizeof(DWORD))
			throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

		if(exports.AddressOfNames)
		{
			//Check if it is enough bytes to hold name and ordinal tables
			if(section_data_length_from_rva(exports.AddressOfNameOrdinals, exports.AddressOfNameOrdinals, section_data_virtual, true) < exports.NumberOfNames * sizeof(WORD))
				throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

			if(section_data_length_from_rva(exports.AddressOfNames, exports.AddressOfNames, section_data_virtual, true) < exports.NumberOfNames * sizeof(DWORD))
				throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);
		}
		
		for(DWORD ordinal = 0; ordinal < exports.NumberOfFunctions; ordinal++)
		{
			//Get function address
			//Sum and multiplication are safe (checked above)
			DWORD rva = section_data_from_rva<DWORD>(exports.AddressOfFunctions + ordinal * sizeof(DWORD), section_data_virtual, true);

			//If we have a skip
			if(!rva)
				continue;

			exported_function func;
			func.set_rva(rva);

			if(!is_sum_safe(exports.Base, ordinal) || exports.Base + ordinal > max_word)
				throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

			func.set_ordinal(static_cast<WORD>(ordinal + exports.Base));

			//Scan for function name ordinal
			for(DWORD i = 0; i < exports.NumberOfNames; i++)
			{
				WORD ordinal2 = section_data_from_rva<WORD>(exports.AddressOfNameOrdinals + i * sizeof(WORD), section_data_virtual, true);

				//If function has name (and name ordinal)
				if(ordinal == ordinal2)
				{
					//Get function name
					//Sum and multiplication are safe (checked above)
					DWORD function_name_rva = section_data_from_rva<DWORD>(exports.AddressOfNames + i * sizeof(DWORD), section_data_virtual, true);

					//Get byte count that we have for function name
					if((max_name_length = section_data_length_from_rva(function_name_rva, function_name_rva, section_data_virtual, true)) < 2)
						throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

					//Get function name pointer
					const char* func_name = section_data_from_rva(function_name_rva, section_data_virtual, true);

					//Check for null-termination
					if(!is_null_terminated(func_name, max_name_length))
						throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

					//Save function info
					func.set_name(func_name);
					func.set_name_ordinal(ordinal2);

					//If the function is just a redirect, save its name
					if(rva >= get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT) + sizeof(IMAGE_DIRECTORY_ENTRY_EXPORT) &&
						rva < get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT) + get_directory_size(IMAGE_DIRECTORY_ENTRY_EXPORT))
					{
						if((max_name_length = section_data_length_from_rva(rva, rva, section_data_virtual, true)) < 2)
							throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

						//Get forwarded function name pointer
						const char* forwarded_func_name = section_data_from_rva(rva, section_data_virtual, true);

						//Check for null-termination
						if(!is_null_terminated(forwarded_func_name, max_name_length))
							throw pe_exception("Incorrect export directory", pe_exception::incorrect_export_directory);

						//Set the name of forwarded function
						func.set_forwarded_name(forwarded_func_name);
					}

					break;
				}
			}

			//Add function info to output array
			ret.push_back(func);
		}
	}

	return ret;
}

//Helper export functions
//Returns pair: <ordinal base for supplied functions; maximum ordinal value for supplied functions>
const std::pair<WORD, WORD> pe_base::get_export_ordinal_limits(const exported_functions_list& exports)
{
	if(exports.empty())
		return std::make_pair(0, 0);

	WORD max_ordinal = 0; //Maximum ordinal number
	WORD ordinal_base = max_word; //Minimum ordinal value
	for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
	{
		const exported_function& func = (*it);

		//Calculate maximum and minimum ordinal numbers
		max_ordinal = std::max<WORD>(max_ordinal, func.get_ordinal());
		ordinal_base = std::min<WORD>(ordinal_base, func.get_ordinal());
	}

	return std::make_pair(ordinal_base, max_ordinal);
}

//Checks if exported function name already exists
bool pe_base::exported_name_exists(const std::string& function_name, const exported_functions_list& exports)
{
	for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
	{
		if((*it).has_name() && (*it).get_name() == function_name)
			return true;
	}

	return false;
}

//Checks if exported function name already exists
bool pe_base::exported_ordinal_exists(WORD ordinal, const exported_functions_list& exports)
{
	for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
	{
		if((*it).get_ordinal() == ordinal)
			return true;
	}

	return false;
}

//Helper: sorts exported function list by ordinals
bool pe_base::ordinal_sorter::operator()(const exported_function& func1, const exported_function& func2) const
{
	return func1.get_ordinal() < func2.get_ordinal();
}

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
const pe_base::image_directory pe_base::rebuild_exports(const export_info& info, exported_functions_list exports, section& exports_section, DWORD offset_from_section_start, bool save_to_pe_header, bool auto_strip_last_section)
{
	//Check that exports_section is attached to this PE image
	if(!section_attached(exports_section))
		throw pe_exception("Exports section must be attached to PE file", pe_exception::section_is_not_attached);

	//Needed space for strings
	DWORD needed_size_for_strings = static_cast<DWORD>(info.get_name().length() + 1);
	DWORD number_of_names = 0; //Number of named functions
	DWORD max_ordinal = 0; //Maximum ordinal number
	DWORD ordinal_base = static_cast<DWORD>(-1); //Minimum ordinal value
	
	if(exports.empty())
		ordinal_base = info.get_ordinal_base();

	DWORD needed_size_for_function_names = 0; //Needed space for function name strings
	DWORD needed_size_for_function_forwards = 0; //Needed space for function forwards names
	
	//List all exported functions
	//Calculate needed size for function list
	{
		//Also check that there're no duplicate names and ordinals
		std::set<std::string> used_function_names;
		std::set<WORD> used_function_ordinals;

		for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
		{
			const exported_function& func = (*it);
			//Calculate maximum and minimum ordinal numbers
			max_ordinal = std::max<DWORD>(max_ordinal, func.get_ordinal());
			ordinal_base = std::min<DWORD>(ordinal_base, func.get_ordinal());

			//Check if ordinal is unique
			if(!used_function_ordinals.insert(func.get_ordinal()).second)
				throw pe_exception("Duplicate exported function ordinal", pe_exception::duplicate_exported_function_ordinal);
			
			if(func.has_name())
			{
				//If function is named
				++number_of_names;
				needed_size_for_function_names += static_cast<DWORD>(func.get_name().length() + 1);
				
				//Check if it's name and name ordinal are unique
				if(!used_function_names.insert(func.get_name()).second)
					throw pe_exception("Duplicate exported function name", pe_exception::duplicate_exported_function_name);
			}

			//If function is forwarded to another DLL
			if(func.is_forwarded())
				needed_size_for_function_forwards += static_cast<DWORD>(func.get_forwarded_name().length() + 1);
		}
	}
	
	//Sort functions by ordinal value
	std::sort(exports.begin(), exports.end(), ordinal_sorter());

	//Calculate needed space for different things...
	needed_size_for_strings += needed_size_for_function_names;
	needed_size_for_strings += needed_size_for_function_forwards;
	DWORD needed_size_for_function_name_ordinals = number_of_names * sizeof(WORD);
	DWORD needed_size_for_function_name_rvas = number_of_names * sizeof(DWORD);
	DWORD needed_size_for_function_addresses = (max_ordinal - ordinal_base + 1) * sizeof(DWORD);
	
	DWORD needed_size = sizeof(IMAGE_EXPORT_DIRECTORY) + sizeof(DWORD); //Calculate needed size for export tables and strings
	//sizeof(IMAGE_EXPORT_DIRECTORY) = export directory header
	//sizeof(DWORD) = for DWORD alignment

	//Total needed space...
	needed_size += needed_size_for_function_name_ordinals; //For list of names ordinals
	needed_size += needed_size_for_function_addresses; //For function RVAs
	needed_size += needed_size_for_strings; //For all strings
	needed_size += needed_size_for_function_name_rvas; //For function name strings RVAs

	//Check if exports_section is last one. If it's not, check if there's enough place for exports data
	if(&exports_section != &*(sections_.end() - 1) && 
		(exports_section.empty() || align_up(exports_section.get_size_of_raw_data(), get_file_alignment()) < needed_size + offset_from_section_start))
		throw pe_exception("Insufficient space for export directory", pe_exception::insufficient_space);

	std::string& raw_data = exports_section.get_raw_data();

	//This will be done only is exports_section is the last section of image or for section with unaligned raw length of data
	if(raw_data.length() < needed_size + offset_from_section_start)
		raw_data.resize(needed_size + offset_from_section_start); //Expand section raw data

	//Export directory header will be placed first
	DWORD directory_pos = align_up(offset_from_section_start, sizeof(DWORD));
	//Library name will be placed after it
	DWORD current_pos_of_function_names = static_cast<DWORD>(info.get_name().length() + 1 + directory_pos + sizeof(IMAGE_EXPORT_DIRECTORY));
	//Next - function names
	DWORD current_pos_of_function_name_ordinals = current_pos_of_function_names + needed_size_for_function_names;
	//Next - function name ordinals
	DWORD current_pos_of_function_forwards = current_pos_of_function_name_ordinals + needed_size_for_function_name_ordinals;
	//Finally - function addresses
	DWORD current_pos_of_function_addresses = current_pos_of_function_forwards + needed_size_for_function_forwards;
	//Next - function names RVAs
	DWORD current_pos_of_function_names_rvas = current_pos_of_function_addresses + needed_size_for_function_addresses;

	{
		//Create export directory and fill it
		IMAGE_EXPORT_DIRECTORY dir = {0};
		dir.Characteristics = info.get_characteristics();
		dir.MajorVersion = info.get_major_version();
		dir.MinorVersion = info.get_minor_version();
		dir.TimeDateStamp = info.get_timestamp();
		dir.NumberOfFunctions = max_ordinal - ordinal_base + 1;
		dir.NumberOfNames = number_of_names;
		dir.Base = ordinal_base;
		dir.AddressOfFunctions = rva_from_section_offset(exports_section, current_pos_of_function_addresses);
		dir.AddressOfNameOrdinals = rva_from_section_offset(exports_section, current_pos_of_function_name_ordinals);
		dir.AddressOfNames = rva_from_section_offset(exports_section, current_pos_of_function_names_rvas);
		dir.Name = rva_from_section_offset(exports_section, directory_pos + sizeof(IMAGE_EXPORT_DIRECTORY));

		//Save it
		memcpy(&raw_data[directory_pos], &dir, sizeof(dir));
	}

	//Sve library name
	memcpy(&raw_data[directory_pos + sizeof(IMAGE_EXPORT_DIRECTORY)], info.get_name().c_str(), info.get_name().length() + 1);

	//A map to sort function names alphabetically
	typedef std::map<std::string, WORD> funclist; //function name; function name ordinal
	funclist funcs;

	DWORD last_ordinal = ordinal_base;
	//Enumerate all exported functions
	for(exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
	{
		const exported_function& func = (*it);

		//If we're skipping some ordinals...
		if(func.get_ordinal() > last_ordinal)
		{
			//Fill this function RVAs data with zeros
			DWORD len = sizeof(DWORD) * (func.get_ordinal() - last_ordinal - 1);
			if(len)
			{
				memset(&raw_data[current_pos_of_function_addresses], 0, len);
				current_pos_of_function_addresses += len;
			}
			
			//Save last encountered ordinal
			last_ordinal = func.get_ordinal();
		}
		
		//If function is named, save its name ordinal and name in sorted alphabetically order
		if(func.has_name())
			funcs.insert(std::make_pair(func.get_name(), static_cast<WORD>(func.get_ordinal() - ordinal_base))); //Calculate name ordinal

		//If function is forwarded to another DLL
		if(func.is_forwarded())
		{
			//Write its forwarded name and its RVA
			DWORD function_rva = rva_from_section_offset(exports_section, current_pos_of_function_forwards);
			memcpy(&raw_data[current_pos_of_function_addresses], &function_rva, sizeof(function_rva));
			current_pos_of_function_addresses += sizeof(function_rva);

			memcpy(&raw_data[current_pos_of_function_forwards], func.get_forwarded_name().c_str(), func.get_forwarded_name().length() + 1);
			current_pos_of_function_forwards += static_cast<DWORD>(func.get_forwarded_name().length() + 1);
		}
		else
		{
			//Write actual function RVA
			DWORD function_rva = func.get_rva();
			memcpy(&raw_data[current_pos_of_function_addresses], &function_rva, sizeof(function_rva));
			current_pos_of_function_addresses += sizeof(function_rva);
		}
	}
	
	//Enumerate sorted function names
	for(funclist::const_iterator it = funcs.begin(); it != funcs.end(); ++it)
	{
		//Save function name RVA
		DWORD function_name_rva = rva_from_section_offset(exports_section, current_pos_of_function_names);
		memcpy(&raw_data[current_pos_of_function_names_rvas], &function_name_rva, sizeof(function_name_rva));
		current_pos_of_function_names_rvas += sizeof(function_name_rva);

		//Save function name
		memcpy(&raw_data[current_pos_of_function_names], (*it).first.c_str(), (*it).first.length() + 1);
		current_pos_of_function_names += static_cast<DWORD>((*it).first.length() + 1);

		//Save function name ordinal
		WORD name_ordinal = (*it).second;
		memcpy(&raw_data[current_pos_of_function_name_ordinals], &name_ordinal, sizeof(name_ordinal));
		current_pos_of_function_name_ordinals += sizeof(name_ordinal);
	}
	
	//Adjust section raw and virtual sizes
	recalculate_section_sizes(exports_section, auto_strip_last_section);
	
	image_directory ret(rva_from_section_offset(exports_section, offset_from_section_start), needed_size);

	//If auto-rewrite of PE headers is required
	if(save_to_pe_header)
	{
		set_directory_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, ret.get_rva());
		set_directory_size(IMAGE_DIRECTORY_ENTRY_EXPORT, ret.get_size());
	}

	return ret;
}


//IMPORTS
//Default constructor
//If set_to_pe_headers = true, IMAGE_DIRECTORY_ENTRY_IMPORT entry will be reset
//to new value after import rebuilding
//If auto_zero_directory_entry_iat = true, IMAGE_DIRECTORY_ENTRY_IAT will be set to zero
//IMAGE_DIRECTORY_ENTRY_IAT is used by loader to temporarily make section, where IMAGE_DIRECTORY_ENTRY_IAT RVA points, writeable
//to be able to modify IAT thunks
pe_base::import_rebuilder_settings::import_rebuilder_settings(bool set_to_pe_headers, bool auto_zero_directory_entry_iat)
	:offset_from_section_start_(0),
	build_original_iat_(true),
	save_iat_and_original_iat_rvas_(true),
	fill_missing_original_iats_(false),
	set_to_pe_headers_(set_to_pe_headers),
	zero_directory_entry_iat_(auto_zero_directory_entry_iat),
	rewrite_iat_and_original_iat_contents_(false),
	auto_strip_last_section_(true)
{}

//Returns offset from section start where import directory data will be placed
DWORD pe_base::import_rebuilder_settings::get_offset_from_section_start() const
{
	return offset_from_section_start_;
}

//Returns true if Original import address table (IAT) will be rebuilt
bool pe_base::import_rebuilder_settings::build_original_iat() const
{
	return build_original_iat_;
}

//Returns true if Original import address and import address tables will not be rebuilt,
//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
bool pe_base::import_rebuilder_settings::save_iat_and_original_iat_rvas() const
{
	return save_iat_and_original_iat_rvas_;
}

//Returns true if Original import address and import address tables contents will be rewritten
//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
//and save_iat_and_original_iat_rvas is true
bool pe_base::import_rebuilder_settings::rewrite_iat_and_original_iat_contents() const
{
	return rewrite_iat_and_original_iat_contents_;
}

//Returns true if original missing IATs will be rebuilt
//(only if IATs are saved)
bool pe_base::import_rebuilder_settings::fill_missing_original_iats() const
{
	return fill_missing_original_iats_;
}

//Returns true if PE headers should be updated automatically after rebuilding of imports
bool pe_base::import_rebuilder_settings::auto_set_to_pe_headers() const
{
	return set_to_pe_headers_;
}

//Returns true if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
bool pe_base::import_rebuilder_settings::zero_directory_entry_iat() const
{
	return zero_directory_entry_iat_;	
}

//Returns true if the last section should be stripped automatically, if imports are inside it
bool pe_base::import_rebuilder_settings::auto_strip_last_section_enabled() const
{
	return auto_strip_last_section_;
}

//Sets offset from section start where import directory data will be placed
void pe_base::import_rebuilder_settings::set_offset_from_section_start(DWORD offset)
{
	offset_from_section_start_ = offset;
}

//Sets if Original import address table (IAT) will be rebuilt
void pe_base::import_rebuilder_settings::build_original_iat(bool enable)
{
	build_original_iat_ = enable;
}

//Sets if Original import address and import address tables will not be rebuilt,
//works only if import descriptor IAT (and orig.IAT, if present) RVAs are not zero
void pe_base::import_rebuilder_settings::save_iat_and_original_iat_rvas(bool enable, bool enable_rewrite_iat_and_original_iat_contents)
{
	save_iat_and_original_iat_rvas_ = enable;
	if(save_iat_and_original_iat_rvas_)
		rewrite_iat_and_original_iat_contents_ = enable_rewrite_iat_and_original_iat_contents;
	else
		rewrite_iat_and_original_iat_contents_ = false;
}

//Sets if original missing IATs will be rebuilt
//(only if IATs are saved)
void pe_base::import_rebuilder_settings::fill_missing_original_iats(bool enable)
{
	fill_missing_original_iats_ = enable;
}

//Sets if PE headers should be updated automatically after rebuilding of imports
void pe_base::import_rebuilder_settings::auto_set_to_pe_headers(bool enable)
{
	set_to_pe_headers_ = enable;
}

//Sets if IMAGE_DIRECTORY_ENTRY_IAT must be zeroed, works only if auto_set_to_pe_headers = true
void pe_base::import_rebuilder_settings::zero_directory_entry_iat(bool enable)
{
	zero_directory_entry_iat_ = enable;
}

//Sets if the last section should be stripped automatically, if imports are inside it, default true
void pe_base::import_rebuilder_settings::enable_auto_strip_last_section(bool enable)
{
	auto_strip_last_section_ = enable;
}

//Default constructor
pe_base::imported_function::imported_function()
	:hint_(0), ordinal_(0), iat_va_(0)
{}

//Returns name of function
const std::string& pe_base::imported_function::get_name() const
{
	return name_;
}

//Returns true if imported function has name (and hint)
bool pe_base::imported_function::has_name() const
{
	return !name_.empty();
}

//Returns hint
WORD pe_base::imported_function::get_hint() const
{
	return hint_;
}

//Returns ordinal of function
WORD pe_base::imported_function::get_ordinal() const
{
	return ordinal_;
}

//Returns IAT entry VA (usable if image has both IAT and original IAT and is bound)
ULONGLONG pe_base::imported_function::get_iat_va() const
{
	return iat_va_;
}

//Sets name of function
void pe_base::imported_function::set_name(const std::string& name)
{
	name_ = name;
}

//Sets hint
void pe_base::imported_function::set_hint(WORD hint)
{
	hint_ = hint;
}

//Sets ordinal
void pe_base::imported_function::set_ordinal(WORD ordinal)
{
	ordinal_ = ordinal;
}

//Sets IAT entry VA (usable if image has both IAT and original IAT and is bound)
void pe_base::imported_function::set_iat_va(ULONGLONG va)
{
	iat_va_ = va;
}

//Default constructor
pe_base::import_library::import_library()
	:rva_to_iat_(0), rva_to_original_iat_(0), timestamp_(0)
{}

//Returns name of library
const std::string& pe_base::import_library::get_name() const
{
	return name_;
}

//Returns RVA to Import Address Table (IAT)
DWORD pe_base::import_library::get_rva_to_iat() const
{
	return rva_to_iat_;
}

//Returns RVA to Original Import Address Table (Original IAT)
DWORD pe_base::import_library::get_rva_to_original_iat() const
{
	return rva_to_original_iat_;
}

//Returns timestamp
DWORD pe_base::import_library::get_timestamp() const
{
	return timestamp_;
}

//Sets name of library
void pe_base::import_library::set_name(const std::string& name)
{
	name_ = name;
}

//Sets RVA to Import Address Table (IAT)
void pe_base::import_library::set_rva_to_iat(DWORD rva_to_iat)
{
	rva_to_iat_ = rva_to_iat;
}

//Sets RVA to Original Import Address Table (Original IAT)
void pe_base::import_library::set_rva_to_original_iat(DWORD rva_to_original_iat)
{
	rva_to_original_iat_ = rva_to_original_iat;
}

//Sets timestamp
void pe_base::import_library::set_timestamp(DWORD timestamp)
{
	timestamp_ = timestamp;
}

//Returns imported functions list
const pe_base::import_library::imported_list& pe_base::import_library::get_imported_functions() const
{
	return imports_;
}

//Adds imported function
void pe_base::import_library::add_import(const imported_function& func)
{
	imports_.push_back(func);
}

//Clears imported functions list
void pe_base::import_library::clear_imports()
{
	imports_.clear();
}

//RELOCATIONS
//Default constructor
pe_base::relocation_entry::relocation_entry()
	:rva_(0), type_(0)
{}

//Constructor from relocation item (WORD)
pe_base::relocation_entry::relocation_entry(WORD relocation_value)
	:rva_(relocation_value & ((1 << 12) - 1)), type_(relocation_value >> 12)
{}

//Constructor from relative rva and relocation type
pe_base::relocation_entry::relocation_entry(WORD rrva, WORD type)
	:rva_(rrva), type_(type)
{}

//Returns RVA of relocation
WORD pe_base::relocation_entry::get_rva() const
{
	return rva_;
}

//Returns type of relocation
WORD pe_base::relocation_entry::get_type() const
{
	return type_;
}

//Sets RVA of relocation
void pe_base::relocation_entry::set_rva(WORD rva)
{
	rva_ = rva;
}

//Sets type of relocation
void pe_base::relocation_entry::set_type(WORD type)
{
	type_ = type;
}

//Returns relocation item (rrva + type)
WORD pe_base::relocation_entry::get_item() const
{
	return rva_ | (type_ << 12);
}

//Sets relocation item (rrva + type)
void pe_base::relocation_entry::set_item(WORD item)
{
	rva_ = item & ((1 << 12) - 1);
	type_ = item >> 12;
}

//Returns relocation list
const pe_base::relocation_table::relocation_list& pe_base::relocation_table::get_relocations() const
{
	return relocations_;
}

//Adds relocation to table
void pe_base::relocation_table::add_relocation(const relocation_entry& entry)
{
	relocations_.push_back(entry);
}

//Default constructor
pe_base::relocation_table::relocation_table()
	:rva_(0)
{}

//Constructor from RVA of relocation table
pe_base::relocation_table::relocation_table(DWORD rva)
	:rva_(rva)
{}

//Returns RVA of block
DWORD pe_base::relocation_table::get_rva() const
{
	return rva_;
}

//Sets RVA of block
void pe_base::relocation_table::set_rva(DWORD rva)
{
	rva_ = rva;
}

//Returns changeable relocation list
pe_base::relocation_table::relocation_list& pe_base::relocation_table::get_relocations()
{
	return relocations_;
}

//Get relocation list of pe file, supports one-word sized relocations only
	//If list_absolute_entries = true, IMAGE_REL_BASED_ABSOLUTE will be listed
const pe_base::relocation_table_list pe_base::get_relocations(bool list_absolute_entries) const
{
	relocation_table_list ret;

	//If image does not have relocations
	if(!has_reloc())
		return ret;

	//Check the length in bytes of the section containing relocation directory
	if(section_data_length_from_rva(get_directory_rva(IMAGE_DIRECTORY_ENTRY_BASERELOC), get_directory_rva(IMAGE_DIRECTORY_ENTRY_BASERELOC), section_data_virtual, true) < sizeof(IMAGE_BASE_RELOCATION))
		throw pe_exception("Incorrect relocation directory", pe_exception::incorrect_relocation_directory);

	unsigned long current_pos = get_directory_rva(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	//First IMAGE_BASE_RELOCATION table
	IMAGE_BASE_RELOCATION reloc_table = section_data_from_rva<IMAGE_BASE_RELOCATION>(current_pos, section_data_virtual, true);

	if(reloc_table.SizeOfBlock % 2)
		throw pe_exception("Incorrect relocation directory", pe_exception::incorrect_relocation_directory);

	unsigned long reloc_size = get_directory_size(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	unsigned long read_size = 0;

	//reloc_table.VirtualAddress is not checked (not so important)
	while(reloc_table.SizeOfBlock && read_size < reloc_size)
	{
		//Create relocation table
		relocation_table table;
		//Save RVA
		table.set_rva(reloc_table.VirtualAddress);

		if(!is_sum_safe(current_pos, reloc_table.SizeOfBlock))
			throw pe_exception("Incorrect relocation directory", pe_exception::incorrect_relocation_directory);

		//List all relocations
		for(unsigned long i = sizeof(IMAGE_BASE_RELOCATION); i < reloc_table.SizeOfBlock; i += sizeof(WORD))
		{
			relocation_entry entry(section_data_from_rva<WORD>(current_pos + i, section_data_virtual, true));
			if(list_absolute_entries || entry.get_type() != IMAGE_REL_BASED_ABSOLUTE)
				table.add_relocation(entry);
		}

		//Save table
		ret.push_back(table);
		
		//Go to next relocation block
		if(!is_sum_safe(current_pos, reloc_table.SizeOfBlock))
			throw pe_exception("Incorrect relocation directory", pe_exception::incorrect_relocation_directory);

		current_pos += reloc_table.SizeOfBlock;
		read_size += reloc_table.SizeOfBlock;
		reloc_table = section_data_from_rva<IMAGE_BASE_RELOCATION>(current_pos, section_data_virtual, true);
	}

	return ret;
}

//Simple relocations rebuilder
//To keep PE file working, don't remove any of existing relocations in
//relocation_table_list returned by a call to get_relocations() function
//auto_strip_last_section - if true and relocations are placed in the last section, it will be automatically stripped
//offset_from_section_start - offset from the beginning of reloc_section, where relocations data will be situated
//If save_to_pe_header is true, PE header will be modified automatically
const pe_base::image_directory pe_base::rebuild_relocations(const relocation_table_list& relocs, section& reloc_section, DWORD offset_from_section_start, bool save_to_pe_header, bool auto_strip_last_section)
{
	//Check that reloc_section is attached to this PE image
	if(!section_attached(reloc_section))
		throw pe_exception("Relocations section must be attached to PE file", pe_exception::section_is_not_attached);
	
	DWORD current_reloc_data_pos = align_up(offset_from_section_start, sizeof(DWORD));

	DWORD needed_size = current_reloc_data_pos - offset_from_section_start; //Calculate needed size for relocation tables
	DWORD size_delta = needed_size;

	DWORD start_reloc_pos = current_reloc_data_pos;

	//Enumerate relocation tables
	for(relocation_table_list::const_iterator it = relocs.begin(); it != relocs.end(); ++it)
	{
		needed_size += static_cast<DWORD>((*it).get_relocations().size() * sizeof(WORD) /* relocations */ + sizeof(IMAGE_BASE_RELOCATION) /* table header */);
		//End of each table will be DWORD-aligned
		if((start_reloc_pos + needed_size - size_delta) % sizeof(DWORD))
			needed_size += sizeof(WORD); //Align it with IMAGE_REL_BASED_ABSOLUTE relocation
	}

	//Check if reloc_section is last one. If it's not, check if there's enough place for relocations data
	if(&reloc_section != &*(sections_.end() - 1) && 
		(reloc_section.empty() || align_up(reloc_section.get_size_of_raw_data(), get_file_alignment()) < needed_size + offset_from_section_start))
		throw pe_exception("Insufficient space for relocations directory", pe_exception::insufficient_space);

	std::string& raw_data = reloc_section.get_raw_data();

	//This will be done only is reloc_section is the last section of image or for section with unaligned raw length of data
	if(raw_data.length() < needed_size + offset_from_section_start)
		raw_data.resize(needed_size + offset_from_section_start); //Expand section raw data

	//Enumerate relocation tables
	for(relocation_table_list::const_iterator it = relocs.begin(); it != relocs.end(); ++it)
	{
		//Create relocation table header
		IMAGE_BASE_RELOCATION reloc;
		reloc.VirtualAddress = (*it).get_rva();
		const relocation_table::relocation_list& reloc_list = (*it).get_relocations();
		reloc.SizeOfBlock = static_cast<DWORD>(sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD) * reloc_list.size());
		if((reloc_list.size() * sizeof(WORD)) % sizeof(DWORD)) //If we must align end of relocation table
			reloc.SizeOfBlock += sizeof(WORD);

		memcpy(&raw_data[current_reloc_data_pos], &reloc, sizeof(reloc));
		current_reloc_data_pos += sizeof(reloc);

		//Enumerate relocations in table
		for(relocation_table::relocation_list::const_iterator r = reloc_list.begin(); r != reloc_list.end(); ++r)
		{
			//Save relocations
			WORD reloc_value = (*r).get_item();
			memcpy(&raw_data[current_reloc_data_pos], &reloc_value, sizeof(reloc_value));
			current_reloc_data_pos += sizeof(reloc_value);
		}

		if(current_reloc_data_pos % sizeof(DWORD)) //If end of table is not DWORD-aligned
		{
			memset(&raw_data[current_reloc_data_pos], 0, sizeof(WORD)); //Align it with IMAGE_REL_BASED_ABSOLUTE relocation
			current_reloc_data_pos += sizeof(WORD);
		}
	}

	image_directory ret(rva_from_section_offset(reloc_section, start_reloc_pos), needed_size - size_delta);
	
	//Adjust section raw and virtual sizes
	recalculate_section_sizes(reloc_section, auto_strip_last_section);

	//If auto-rewrite of PE headers is required
	if(save_to_pe_header)
	{
		set_directory_rva(IMAGE_DIRECTORY_ENTRY_BASERELOC, ret.get_rva());
		set_directory_size(IMAGE_DIRECTORY_ENTRY_BASERELOC, ret.get_size());
	}

	return ret;
}


//TLS
//Default constructor
pe_base::tls_info::tls_info()
	:start_rva_(0), end_rva_(0), index_rva_(0), callbacks_rva_(0),
	size_of_zero_fill_(0), characteristics_(0)
{}

//Returns start RVA of TLS raw data
DWORD pe_base::tls_info::get_raw_data_start_rva() const
{
	return start_rva_;
}

//Returns end RVA of TLS raw data
DWORD pe_base::tls_info::get_raw_data_end_rva() const
{
	return end_rva_;
}

//Returns TLS index RVA
DWORD pe_base::tls_info::get_index_rva() const
{
	return index_rva_;
}

//Returns TLS callbacks RVA
DWORD pe_base::tls_info::get_callbacks_rva() const
{
	return callbacks_rva_;
}

//Returns size of zero fill
DWORD pe_base::tls_info::get_size_of_zero_fill() const
{
	return size_of_zero_fill_;
}

//Returns characteristics
DWORD pe_base::tls_info::get_characteristics() const
{
	return characteristics_;
}

//Returns raw TLS data
const std::string& pe_base::tls_info::get_raw_data() const
{
	return raw_data_;
}

//Returns TLS callbacks addresses
const pe_base::tls_info::tls_callback_list& pe_base::tls_info::get_tls_callbacks() const
{
	return callbacks_;
}

//Returns TLS callbacks addresses
pe_base::tls_info::tls_callback_list& pe_base::tls_info::get_tls_callbacks()
{
	return callbacks_;
}

//Adds TLS callback
void pe_base::tls_info::add_tls_callback(DWORD rva)
{
	callbacks_.push_back(rva);
}

//Clears TLS callbacks list
void pe_base::tls_info::clear_tls_callbacks()
{
	callbacks_.clear();
}

//Recalculates end address of raw TLS data
void pe_base::tls_info::recalc_raw_data_end_rva()
{
	end_rva_ = static_cast<DWORD>(start_rva_ + raw_data_.length());
}

//Sets start RVA of TLS raw data
void pe_base::tls_info::set_raw_data_start_rva(DWORD rva)
{
	start_rva_ = rva;
}

//Sets end RVA of TLS raw data
void pe_base::tls_info::set_raw_data_end_rva(DWORD rva)
{
	end_rva_ = rva;
}

//Sets TLS index RVA
void pe_base::tls_info::set_index_rva(DWORD rva)
{
	index_rva_ = rva;
}

//Sets TLS callbacks RVA
void pe_base::tls_info::set_callbacks_rva(DWORD rva)
{
	callbacks_rva_ = rva;
}

//Sets size of zero fill
void pe_base::tls_info::set_size_of_zero_fill(DWORD size)
{
	size_of_zero_fill_ = size;
}

//Sets characteristics
void pe_base::tls_info::set_characteristics(DWORD characteristics)
{
	characteristics_ = characteristics;
}

//Sets raw TLS data
void pe_base::tls_info::set_raw_data(const std::string& data)
{
	raw_data_ = data;
}

//IMAGE CONFIG
//Default constructor
pe_base::image_config_info::image_config_info()
	:time_stamp_(0),
	major_version_(0), minor_version_(0),
	global_flags_clear_(0), global_flags_set_(0),
	critical_section_default_timeout_(0),
	decommit_free_block_threshold_(0), decommit_total_free_threshold_(0),
	lock_prefix_table_va_(0),
	max_allocation_size_(0),
	virtual_memory_threshold_(0),
	process_affinity_mask_(0),
	process_heap_flags_(0),
	service_pack_version_(0),
	edit_list_va_(0),
	security_cookie_va_(0),
	se_handler_table_va_(0),
	se_handler_count_(0)
{}

//Constructors from PE structures
template<typename ConfigStructure>
pe_base::image_config_info::image_config_info(const ConfigStructure& info)
	:time_stamp_(info.TimeDateStamp),
	major_version_(info.MajorVersion), minor_version_(info.MinorVersion),
	global_flags_clear_(info.GlobalFlagsClear), global_flags_set_(info.GlobalFlagsSet),
	critical_section_default_timeout_(info.CriticalSectionDefaultTimeout),
	decommit_free_block_threshold_(info.DeCommitFreeBlockThreshold), decommit_total_free_threshold_(info.DeCommitTotalFreeThreshold),
	lock_prefix_table_va_(info.LockPrefixTable),
	max_allocation_size_(info.MaximumAllocationSize),
	virtual_memory_threshold_(info.VirtualMemoryThreshold),
	process_affinity_mask_(info.ProcessAffinityMask),
	process_heap_flags_(info.ProcessHeapFlags),
	service_pack_version_(info.CSDVersion),
	edit_list_va_(info.EditList),
	security_cookie_va_(info.SecurityCookie),
	se_handler_table_va_(info.SEHandlerTable),
	se_handler_count_(info.SEHandlerCount)
{}

//Instantiate template constructor with needed structures
template pe_base::image_config_info::image_config_info(const IMAGE_LOAD_CONFIG_DIRECTORY32& info);
template pe_base::image_config_info::image_config_info(const IMAGE_LOAD_CONFIG_DIRECTORY64& info);

//Returns the date and time stamp value
DWORD pe_base::image_config_info::get_time_stamp() const
{
	return time_stamp_;
}

//Returns major version number
WORD pe_base::image_config_info::get_major_version() const
{
	return major_version_;
}

//Returns minor version number
WORD pe_base::image_config_info::get_minor_version() const
{
	return minor_version_;
}

//Returns clear global flags
DWORD pe_base::image_config_info::get_global_flags_clear() const
{
	return global_flags_clear_;
}

//Returns set global flags
DWORD pe_base::image_config_info::get_global_flags_set() const
{
	return global_flags_set_;
}

//Returns critical section default timeout
DWORD pe_base::image_config_info::get_critical_section_default_timeout() const
{
	return critical_section_default_timeout_;
}

//Get the size of the minimum block that
//must be freed before it is freed (de-committed), in bytes
ULONGLONG pe_base::image_config_info::get_decommit_free_block_threshold() const
{
	return decommit_free_block_threshold_;
}

//Returns the size of the minimum total memory
//that must be freed in the process heap before it is freed (de-committed), in bytes
ULONGLONG pe_base::image_config_info::get_decommit_total_free_threshold() const
{
	return decommit_total_free_threshold_;
}

//Returns VA of a list of addresses where the LOCK prefix is used
ULONGLONG pe_base::image_config_info::get_lock_prefix_table_va() const
{
	return lock_prefix_table_va_;
}

//Returns the maximum allocation size, in bytes
ULONGLONG pe_base::image_config_info::get_max_allocation_size() const
{
	return max_allocation_size_;
}

//Returns the maximum block size that can be allocated from heap segments, in bytes
ULONGLONG pe_base::image_config_info::get_virtual_memory_threshold() const
{
	return virtual_memory_threshold_;
}

//Returns process affinity mask
ULONGLONG pe_base::image_config_info::get_process_affinity_mask() const
{
	return process_affinity_mask_;
}

//Returns process heap flags
DWORD pe_base::image_config_info::get_process_heap_flags() const
{
	return process_heap_flags_;
}

//Returns service pack version (CSDVersion)
WORD pe_base::image_config_info::get_service_pack_version() const
{
	return service_pack_version_;
}

//Returns VA of edit list (reserved by system)
ULONGLONG pe_base::image_config_info::get_edit_list_va() const
{
	return edit_list_va_;
}

//Returns a pointer to a cookie that is used by Visual C++ or GS implementation
ULONGLONG pe_base::image_config_info::get_security_cookie_va() const
{
	return security_cookie_va_;
}

//Returns VA of the sorted table of RVAs of each valid, unique handler in the image
ULONGLONG pe_base::image_config_info::get_se_handler_table_va() const
{
	return se_handler_table_va_;
}

//Returns the count of unique handlers in the table
ULONGLONG pe_base::image_config_info::get_se_handler_count() const
{
	return se_handler_count_;
}

//Returns SE Handler RVA list
const pe_base::image_config_info::se_handler_list& pe_base::image_config_info::get_se_handler_rvas() const
{
	return se_handlers_;
}

//Returns Lock Prefix RVA list
const pe_base::image_config_info::lock_prefix_rva_list& pe_base::image_config_info::get_lock_prefix_rvas() const
{
	return lock_prefixes_;
}

//Adds SE Handler RVA to list
void pe_base::image_config_info::add_se_handler_rva(DWORD rva)
{
	se_handlers_.push_back(rva);
}

//Clears SE Handler list
void pe_base::image_config_info::clear_se_handler_list()
{
	se_handlers_.clear();
}

//Adds Lock Prefix RVA to list
void pe_base::image_config_info::add_lock_prefix_rva(DWORD rva)
{
	lock_prefixes_.push_back(rva);
}

//Clears Lock Prefix list
void pe_base::image_config_info::clear_lock_prefix_list()
{
	lock_prefixes_.clear();
}

//Sets the date and time stamp value
void pe_base::image_config_info::set_time_stamp(DWORD time_stamp)
{
	time_stamp_ = time_stamp;
}

//Sets major version number
void pe_base::image_config_info::set_major_version(WORD major_version)
{
	major_version_ = major_version;
}

//Sets minor version number
void pe_base::image_config_info::set_minor_version(WORD minor_version)
{
	minor_version_ = minor_version;
}

//Sets clear global flags
void pe_base::image_config_info::set_global_flags_clear(DWORD global_flags_clear)
{
	global_flags_clear_ = global_flags_clear;
}

//Sets set global flags
void pe_base::image_config_info::set_global_flags_set(DWORD global_flags_set)
{
	global_flags_set_ = global_flags_set;
}

//Sets critical section default timeout
void pe_base::image_config_info::set_critical_section_default_timeout(DWORD critical_section_default_timeout)
{
	critical_section_default_timeout_ = critical_section_default_timeout;
}

//Sets the size of the minimum block that
//must be freed before it is freed (de-committed), in bytes
void pe_base::image_config_info::set_decommit_free_block_threshold(ULONGLONG decommit_free_block_threshold)
{
	decommit_free_block_threshold_ = decommit_free_block_threshold;
}

//Sets the size of the minimum total memory
//that must be freed in the process heap before it is freed (de-committed), in bytes
void pe_base::image_config_info::set_decommit_total_free_threshold(ULONGLONG decommit_total_free_threshold)
{
	decommit_total_free_threshold_ = decommit_total_free_threshold;
}

//Sets VA of a list of addresses where the LOCK prefix is used
//If you rebuild this list, VA will be re-assigned automatically
void pe_base::image_config_info::set_lock_prefix_table_va(ULONGLONG lock_prefix_table_va)
{
	lock_prefix_table_va_ = lock_prefix_table_va;
}

//Sets the maximum allocation size, in bytes
void pe_base::image_config_info::set_max_allocation_size(ULONGLONG max_allocation_size)
{
	max_allocation_size_ = max_allocation_size;
}

//Sets the maximum block size that can be allocated from heap segments, in bytes
void pe_base::image_config_info::set_virtual_memory_threshold(ULONGLONG virtual_memory_threshold)
{
	virtual_memory_threshold_ = virtual_memory_threshold;
}

//Sets process affinity mask
void pe_base::image_config_info::set_process_affinity_mask(ULONGLONG process_affinity_mask)
{
	process_affinity_mask_ = process_affinity_mask;
}

//Sets process heap flags
void pe_base::image_config_info::set_process_heap_flags(DWORD process_heap_flags)
{
	process_heap_flags_ = process_heap_flags;
}

//Sets service pack version (CSDVersion)
void pe_base::image_config_info::set_service_pack_version(WORD service_pack_version)
{
	service_pack_version_ = service_pack_version;
}

//Sets VA of edit list (reserved by system)
void pe_base::image_config_info::set_edit_list_va(ULONGLONG edit_list_va)
{
	edit_list_va_ = edit_list_va;
}

//Sets a pointer to a cookie that is used by Visual C++ or GS implementation
void pe_base::image_config_info::set_security_cookie_va(ULONGLONG security_cookie_va)
{
	security_cookie_va_ = security_cookie_va;
}

//Sets VA of the sorted table of RVAs of each valid, unique handler in the image
//If you rebuild this list, VA will be re-assigned automatically
void pe_base::image_config_info::set_se_handler_table_va(ULONGLONG se_handler_table_va)
{
	se_handler_table_va_ = se_handler_table_va;
}

//Returns SE Handler RVA list
pe_base::image_config_info::se_handler_list& pe_base::image_config_info::get_se_handler_rvas()
{
	return se_handlers_;
}

//Returns Lock Prefix RVA list
pe_base::image_config_info::lock_prefix_rva_list& pe_base::image_config_info::get_lock_prefix_rvas()
{
	return lock_prefixes_;
}

//BOUND IMPORT
//Default constructor
pe_base::bound_import_ref::bound_import_ref()
	:timestamp_(0)
{}

//Constructor from data
pe_base::bound_import_ref::bound_import_ref(const std::string& module_name, DWORD timestamp)
	:module_name_(module_name), timestamp_(timestamp)
{}

//Returns imported module name
const std::string& pe_base::bound_import_ref::get_module_name() const
{
	return module_name_;
}

//Returns bound import date and time stamp
DWORD pe_base::bound_import_ref::get_timestamp() const
{
	return timestamp_;
}

//Default constructor
pe_base::bound_import::bound_import()
	:timestamp_(0)
{}

//Constructor from data
pe_base::bound_import::bound_import(const std::string& module_name, DWORD timestamp)
	:module_name_(module_name), timestamp_(timestamp)
{}

//Returns imported module name
const std::string& pe_base::bound_import::get_module_name() const
{
	return module_name_;
}

//Returns bound import date and time stamp
DWORD pe_base::bound_import::get_timestamp() const
{
	return timestamp_;
}

//Returns bound references cound
size_t pe_base::bound_import::get_module_ref_count() const
{
	return refs_.size();
}

//Returns module references
const pe_base::bound_import::ref_list& pe_base::bound_import::get_module_ref_list() const
{
	return refs_;
}

//Adds module reference
void pe_base::bound_import::add_module_ref(const bound_import_ref& ref)
{
	refs_.push_back(ref);
}

//Clears module references list
void pe_base::bound_import::clear_module_refs()
{
	refs_.clear();
}

//Returns module references
pe_base::bound_import::ref_list& pe_base::bound_import::get_module_ref_list()
{
	return refs_;
}

const pe_base::bound_import_module_list pe_base::get_bound_import_module_list() const
{
	//Returned bound import modules list
	bound_import_module_list ret;

	//If image has no bound imports
	if(!has_bound_import())
		return ret;

	//Check read in "read_pe" function raw bound import data size
	if(bound_import_data_.size() < sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR))
		throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

	//current bound_import_data_ in-string position
	unsigned long current_pos = 0;
	//first bound import descriptor
	//so, we're working with raw data here, no section helpers available
	const IMAGE_BOUND_IMPORT_DESCRIPTOR* descriptor = reinterpret_cast<const IMAGE_BOUND_IMPORT_DESCRIPTOR*>(&bound_import_data_[current_pos]);

	//Enumerate until zero
	while(descriptor->OffsetModuleName)
	{
		//Check module name offset
		if(descriptor->OffsetModuleName >= bound_import_data_.size())
			throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

		//Check module name for null-termination
		if(!is_null_terminated(&bound_import_data_[descriptor->OffsetModuleName], bound_import_data_.size() - descriptor->OffsetModuleName))
			throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

		//Create bound import descriptor structure
		bound_import elem(&bound_import_data_[descriptor->OffsetModuleName], descriptor->TimeDateStamp);

		//Check DWORDs
		if(descriptor->NumberOfModuleForwarderRefs >= max_dword / sizeof(IMAGE_BOUND_FORWARDER_REF)
			|| !is_sum_safe(current_pos, 2 /* this descriptor and the next one */ * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) + descriptor->NumberOfModuleForwarderRefs * sizeof(IMAGE_BOUND_FORWARDER_REF)))
			throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

		//Move after current descriptor
		current_pos += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

		//Enumerate referenced bound import descriptors
		for(unsigned long i = 0; i != descriptor->NumberOfModuleForwarderRefs; ++i)
		{
			//They're just after parent descriptor
			//Check size of structure
			if(current_pos + sizeof(IMAGE_BOUND_FORWARDER_REF) > bound_import_data_.size())
				throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

			//Get IMAGE_BOUND_FORWARDER_REF pointer
			const IMAGE_BOUND_FORWARDER_REF* ref_descriptor = reinterpret_cast<const IMAGE_BOUND_FORWARDER_REF*>(&bound_import_data_[current_pos]);

			//Check referenced module name
			if(ref_descriptor->OffsetModuleName >= bound_import_data_.size())
				throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

			//And its null-termination
			if(!is_null_terminated(&bound_import_data_[ref_descriptor->OffsetModuleName], bound_import_data_.size() - ref_descriptor->OffsetModuleName))
				throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

			//Add referenced module to current bound import structure
			elem.add_module_ref(bound_import_ref(&bound_import_data_[ref_descriptor->OffsetModuleName], ref_descriptor->TimeDateStamp));

			//Move after referenced bound import descriptor
			current_pos += sizeof(IMAGE_BOUND_FORWARDER_REF);
		}

		//Check structure size
		if(current_pos + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) > bound_import_data_.size())
			throw pe_exception("Incorrect bound import directory", pe_exception::incorrect_bound_import_directory);

		//Move to next bound import descriptor
		descriptor = reinterpret_cast<const IMAGE_BOUND_IMPORT_DESCRIPTOR*>(&bound_import_data_[current_pos]);

		//Save created descriptor structure and references
		ret.push_back(elem);
	}

	//Return result
	return ret;
}

//RESOURCES
//Default constructor
pe_base::resource_data_entry::resource_data_entry()
	:codepage_(0)
{}

//Constructor from data
pe_base::resource_data_entry::resource_data_entry(const std::string& data, DWORD codepage)
	:codepage_(codepage), data_(data)
{}

//Returns resource data codepage
DWORD pe_base::resource_data_entry::get_codepage() const
{
	return codepage_;
}

//Returns resource data
const std::string& pe_base::resource_data_entry::get_data() const
{
	return data_;
}

//Sets resource data codepage
void pe_base::resource_data_entry::set_codepage(DWORD codepage)
{
	codepage_ = codepage;
}

//Sets resource data
void pe_base::resource_data_entry::set_data(const std::string& data)
{
	data_ = data;
}

//Default constructor
pe_base::resource_directory_entry::includes::includes()
	:data_(0)
{}

//Default constructor
pe_base::resource_directory_entry::resource_directory_entry()
	:id_(0), includes_data_(false), named_(false)
{}

//Copy constructor
pe_base::resource_directory_entry::resource_directory_entry(const resource_directory_entry& other)
	:id_(other.id_), name_(other.name_), includes_data_(other.includes_data_), named_(other.named_)
{
	//If union'ed pointer is not zero
	if(other.ptr_.data_)
	{
		if(other.includes_data())
			ptr_.data_ = new resource_data_entry(*other.ptr_.data_);
		else
			ptr_.dir_ = new resource_directory(*other.ptr_.dir_);
	}
}

//Copy assignment operator
pe_base::resource_directory_entry& pe_base::resource_directory_entry::operator=(const resource_directory_entry& other)
{
	release();

	id_ = other.id_;
	name_ = other.name_;
	includes_data_ = other.includes_data_;
	named_ = other.named_;

	//If other union'ed pointer is not zero
	if(other.ptr_.data_)
	{
		if(other.includes_data())
			ptr_.data_ = new resource_data_entry(*other.ptr_.data_);
		else
			ptr_.dir_ = new resource_directory(*other.ptr_.dir_);
	}

	return *this;
}

//Destroys included data
void pe_base::resource_directory_entry::release()
{
	//If union'ed pointer is not zero
	if(ptr_.data_)
	{
		if(includes_data())
			delete ptr_.data_;
		else
			delete ptr_.dir_;

		ptr_.data_ = 0;
	}
}

//Destructor
pe_base::resource_directory_entry::~resource_directory_entry()
{
	release();
}

//Returns entry ID
DWORD pe_base::resource_directory_entry::get_id() const
{
	return id_;
}

//Returns entry name
const std::wstring& pe_base::resource_directory_entry::get_name() const
{
	return name_;
}

//Returns true, if entry has name
//Returns false, if entry has ID
bool pe_base::resource_directory_entry::is_named() const
{
	return named_;
}

//Returns true, if entry includes resource_data_entry
//Returns false, if entry includes resource_directory
bool pe_base::resource_directory_entry::includes_data() const
{
	return includes_data_;
}

//Returns resource_directory if entry includes it, otherwise throws an exception
const pe_base::resource_directory& pe_base::resource_directory_entry::get_resource_directory() const
{
	if(!ptr_.dir_ || includes_data_)
		throw pe_exception("Resource directory entry does not contain resource directory", pe_exception::resource_directory_entry_error);

	return *ptr_.dir_;
}

//Returns resource_data_entry if entry includes it, otherwise throws an exception
const pe_base::resource_data_entry& pe_base::resource_directory_entry::get_data_entry() const
{
	if(!ptr_.data_ || !includes_data_)
		throw pe_exception("Resource directory entry does not contain resource data entry", pe_exception::resource_directory_entry_error);

	return *ptr_.data_;
}

//Returns resource_directory if entry includes it, otherwise throws an exception
pe_base::resource_directory& pe_base::resource_directory_entry::get_resource_directory()
{
	if(!ptr_.dir_ || includes_data_)
		throw pe_exception("Resource directory entry does not contain resource directory", pe_exception::resource_directory_entry_error);

	return *ptr_.dir_;
}

//Returns resource_data_entry if entry includes it, otherwise throws an exception
pe_base::resource_data_entry& pe_base::resource_directory_entry::get_data_entry()
{
	if(!ptr_.data_ || !includes_data_)
		throw pe_exception("Resource directory entry does not contain resource data entry", pe_exception::resource_directory_entry_error);

	return *ptr_.data_;
}

//Sets entry name
void pe_base::resource_directory_entry::set_name(const std::wstring& name)
{
	name_ = name;
	named_ = true;
	id_ = 0;
}

//Sets entry ID
void pe_base::resource_directory_entry::set_id(DWORD id)
{
	id_ = id;
	named_ = false;
	name_.clear();
}

//Adds resource_data_entry
void pe_base::resource_directory_entry::add_data_entry(const resource_data_entry& entry)
{
	release();
	ptr_.data_ = new resource_data_entry(entry);
	includes_data_ = true;
}

//Adds resource_directory
void pe_base::resource_directory_entry::add_resource_directory(const resource_directory& dir)
{
	release();
	ptr_.dir_ = new resource_directory(dir);
	includes_data_ = false;
}

//Default constructor
pe_base::resource_directory::resource_directory()
	:characteristics_(0),
	timestamp_(0),
	major_version_(0), minor_version_(0),
	number_of_named_entries_(0), number_of_id_entries_(0)
{}

//Constructor from data
pe_base::resource_directory::resource_directory(const IMAGE_RESOURCE_DIRECTORY& dir)
	:characteristics_(dir.Characteristics),
	timestamp_(dir.TimeDateStamp),
	major_version_(dir.MajorVersion), minor_version_(dir.MinorVersion),
	number_of_named_entries_(0), number_of_id_entries_(0) //Set to zero here, calculate on add
{}

//Returns characteristics of directory
DWORD pe_base::resource_directory::get_characteristics() const
{
	return characteristics_;
}

//Returns date and time stamp of directory
DWORD pe_base::resource_directory::get_timestamp() const
{
	return timestamp_;
}

//Returns major version of directory
WORD pe_base::resource_directory::get_major_version() const
{
	return major_version_;
}

//Returns minor version of directory
WORD pe_base::resource_directory::get_minor_version() const
{
	return minor_version_;
}

//Returns number of named entries
DWORD pe_base::resource_directory::get_number_of_named_entries() const
{
	return number_of_named_entries_;
}

//Returns number of ID entries
DWORD pe_base::resource_directory::get_number_of_id_entries() const
{
	return number_of_id_entries_;
}

//Returns resource_directory_entry array
const pe_base::resource_directory::entry_list& pe_base::resource_directory::get_entry_list() const
{
	return entries_;
}

//Returns resource_directory_entry array
pe_base::resource_directory::entry_list& pe_base::resource_directory::get_entry_list()
{
	return entries_;
}

//Adds resource_directory_entry
void pe_base::resource_directory::add_resource_directory_entry(const resource_directory_entry& entry)
{
	entries_.push_back(entry);
	if(entry.is_named())
		++number_of_named_entries_;
	else
		++number_of_id_entries_;
}

//Clears resource_directory_entry array
void pe_base::resource_directory::clear_resource_directory_entry_list()
{
	entries_.clear();
	number_of_named_entries_ = 0;
	number_of_id_entries_ = 0;
}

//Sets characteristics of directory
void pe_base::resource_directory::set_characteristics(DWORD characteristics)
{
	characteristics_ = characteristics;
}

//Sets date and time stamp of directory
void pe_base::resource_directory::set_timestamp(DWORD timestamp)
{
	timestamp_ = timestamp;
}

//Sets number of named entries
void pe_base::resource_directory::set_number_of_named_entries(DWORD number)
{
	number_of_named_entries_ = number;
}

//Sets number of ID entries
void pe_base::resource_directory::set_number_of_id_entries(DWORD number)
{
	number_of_id_entries_ = number;
}

//Sets major version of directory
void pe_base::resource_directory::set_major_version(WORD major_version)
{
	major_version_ = major_version;
}

//Sets minor version of directory
void pe_base::resource_directory::get_minor_version(WORD minor_version)
{
	minor_version_ = minor_version;
}

//Processes resource directory
const pe_base::resource_directory pe_base::process_resource_directory(DWORD res_rva, DWORD offset_to_directory, std::set<DWORD>& processed) const
{
	resource_directory ret;
	
	//Check for resource loops
	if(!processed.insert(offset_to_directory).second)
		throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

	if(!is_sum_safe(res_rva, offset_to_directory))
		throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

	//Get root IMAGE_RESOURCE_DIRECTORY
	IMAGE_RESOURCE_DIRECTORY directory = section_data_from_rva<IMAGE_RESOURCE_DIRECTORY>(res_rva + offset_to_directory, section_data_virtual, true);

	ret = resource_directory(directory);

	//Check DWORDs for possible overflows
	if(!is_sum_safe(directory.NumberOfIdEntries, directory.NumberOfNamedEntries)
		|| directory.NumberOfIdEntries + directory.NumberOfNamedEntries >= max_dword / sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) + sizeof(IMAGE_RESOURCE_DIRECTORY))
		throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

	if(!is_sum_safe(offset_to_directory, sizeof(IMAGE_RESOURCE_DIRECTORY) + (directory.NumberOfIdEntries + directory.NumberOfNamedEntries) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY))
		|| !is_sum_safe(res_rva, offset_to_directory + sizeof(IMAGE_RESOURCE_DIRECTORY) + (directory.NumberOfIdEntries + directory.NumberOfNamedEntries) * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)))
		throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

	for(unsigned long i = 0; i != static_cast<unsigned long>(directory.NumberOfIdEntries) + directory.NumberOfNamedEntries; ++i)
	{
		//Read directory entries one by one
		IMAGE_RESOURCE_DIRECTORY_ENTRY dir_entry = section_data_from_rva<IMAGE_RESOURCE_DIRECTORY_ENTRY>(
			res_rva + sizeof(IMAGE_RESOURCE_DIRECTORY) + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) + offset_to_directory, section_data_virtual, true);

		//Create directory entry structure
		resource_directory_entry entry;

		//If directory is named
		if(dir_entry.NameIsString)
		{
			if(!is_sum_safe(res_rva + sizeof(WORD) /* safe */, dir_entry.NameOffset))
				throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

			//get directory name length
			WORD directory_name_length = section_data_from_rva<WORD>(res_rva + dir_entry.NameOffset, section_data_virtual, true);

			//Check name length
			if(section_data_length_from_rva(res_rva + dir_entry.NameOffset + sizeof(WORD), res_rva + dir_entry.NameOffset + sizeof(WORD), section_data_virtual, true) < directory_name_length)
				throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

			//Set entry UNICODE name
			entry.set_name(std::wstring(
				reinterpret_cast<const wchar_t*>(section_data_from_rva(res_rva + dir_entry.NameOffset + sizeof(WORD), section_data_virtual, true)),
				directory_name_length));
		}
		else
		{
			//Else - set directory ID
			entry.set_id(dir_entry.Id);
		}

		//If directory entry has another resource directory
		if(dir_entry.DataIsDirectory)
		{
			entry.add_resource_directory(process_resource_directory(res_rva, dir_entry.OffsetToDirectory, processed));
		}
		else
		{
			//If directory entry has data
			IMAGE_RESOURCE_DATA_ENTRY data_entry = section_data_from_rva<IMAGE_RESOURCE_DATA_ENTRY>(
				res_rva + dir_entry.OffsetToData, section_data_virtual, true);

			//Check byte count that stated by data entry
			if(section_data_length_from_rva(data_entry.OffsetToData, data_entry.OffsetToData, section_data_virtual, true) < data_entry.Size)
				throw pe_exception("Incorrect resource directory", pe_exception::incorrect_resource_directory);

			//Add data entry to directory entry
			entry.add_data_entry(resource_data_entry(
				std::string(section_data_from_rva(data_entry.OffsetToData, section_data_virtual, true), data_entry.Size),
				data_entry.CodePage));
		}

		//Save directory entry
		ret.add_resource_directory_entry(entry);
	}

	//Return resource directory
	return ret;
}

//Helper function to calculate needed space for resource data
void pe_base::calculate_resource_data_space(const resource_directory& root, DWORD& needed_size_for_structures, DWORD& needed_size_for_strings, DWORD& needed_size_for_data)
{
	needed_size_for_structures += sizeof(IMAGE_RESOURCE_DIRECTORY);
	for(resource_directory::entry_list::const_iterator it = root.get_entry_list().begin(); it != root.get_entry_list().end(); ++it)
	{
		needed_size_for_structures += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY);

		if((*it).is_named())
			needed_size_for_strings += static_cast<DWORD>(((*it).get_name().length() + 1) * 2 /* unicode */ + sizeof(WORD) /* for string length */);

		if((*it).includes_data())
			needed_size_for_data += static_cast<DWORD>((*it).get_data_entry().get_data().length() + sizeof(IMAGE_RESOURCE_DATA_ENTRY) + sizeof(DWORD) /* overhead for alignment */);
		else
			calculate_resource_data_space((*it).get_resource_directory(), needed_size_for_structures, needed_size_for_strings, needed_size_for_data);
	}
}

//Helper function to rebuild resource directory
void pe_base::rebuild_resource_directory(section& resource_section, resource_directory& root, unsigned long& current_structures_pos, unsigned long& current_data_pos, unsigned long& current_strings_pos, unsigned long offset_from_section_start)
{
	//Create resource directory
	IMAGE_RESOURCE_DIRECTORY dir = {0};
	dir.Characteristics = root.get_characteristics();
	dir.MajorVersion = root.get_major_version();
	dir.MinorVersion = root.get_minor_version();
	dir.TimeDateStamp = root.get_timestamp();
	
	{
		resource_directory::entry_list& entries = root.get_entry_list();
		std::sort(entries.begin(), entries.end(), entry_sorter());
	}

	//Calculate number of named and ID entries
	for(resource_directory::entry_list::const_iterator it = root.get_entry_list().begin(); it != root.get_entry_list().end(); ++it)
	{
		if((*it).is_named())
			++dir.NumberOfNamedEntries;
		else
			++dir.NumberOfIdEntries;
	}
	
	std::string& raw_data = resource_section.get_raw_data();

	//Save resource directory
	memcpy(&raw_data[current_structures_pos], &dir, sizeof(dir));
	current_structures_pos += sizeof(dir);

	DWORD this_current_structures_pos = current_structures_pos;

	current_structures_pos += sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) * (dir.NumberOfNamedEntries + dir.NumberOfIdEntries);

	//Create all resource directory entries
	for(resource_directory::entry_list::iterator it = root.get_entry_list().begin(); it != root.get_entry_list().end(); ++it)
	{
		IMAGE_RESOURCE_DIRECTORY_ENTRY entry;
		if((*it).is_named())
		{
			entry.Name = 0x80000000 | (current_strings_pos - offset_from_section_start);
			WORD unicode_length = static_cast<WORD>((*it).get_name().length());
			memcpy(&raw_data[current_strings_pos], &unicode_length, sizeof(unicode_length));
			current_strings_pos += sizeof(unicode_length);

			memcpy(&raw_data[current_strings_pos], (*it).get_name().c_str(), (*it).get_name().length() * 2 + 2 /* unicode */);
			current_strings_pos += static_cast<unsigned long>((*it).get_name().length() * 2 + 2 /* unicode */);
		}
		else
		{
			entry.Name = (*it).get_id();
		}

		if((*it).includes_data())
		{
			current_data_pos = align_up(current_data_pos, sizeof(DWORD));
			IMAGE_RESOURCE_DATA_ENTRY data_entry = {0};
			data_entry.CodePage = (*it).get_data_entry().get_codepage();
			data_entry.Size = static_cast<DWORD>((*it).get_data_entry().get_data().length());
			data_entry.OffsetToData = rva_from_section_offset(resource_section, current_data_pos + sizeof(data_entry));
			
			entry.OffsetToData = current_data_pos - offset_from_section_start;

			memcpy(&raw_data[current_data_pos], &data_entry, sizeof(data_entry));
			current_data_pos += sizeof(data_entry);
			
			memcpy(&raw_data[current_data_pos], (*it).get_data_entry().get_data().data(), data_entry.Size);
			current_data_pos += data_entry.Size;

			memcpy(&raw_data[this_current_structures_pos], &entry, sizeof(entry));
			this_current_structures_pos += sizeof(entry);
		}
		else
		{
			entry.OffsetToData = 0x80000000 | (current_structures_pos - offset_from_section_start);

			memcpy(&raw_data[this_current_structures_pos], &entry, sizeof(entry));
			this_current_structures_pos += sizeof(entry);

			rebuild_resource_directory(resource_section, (*it).get_resource_directory(), current_structures_pos, current_data_pos, current_strings_pos, offset_from_section_start);
		}
	}
}

//Helper function to rebuild resource directory
bool pe_base::entry_sorter::operator()(const resource_directory_entry& entry1, const resource_directory_entry& entry2) const
{
	if(entry1.is_named() && entry2.is_named())
		return entry1.get_name() < entry2.get_name();
	else if(!entry1.is_named() && !entry2.is_named())
		return entry1.get_id() < entry2.get_id();
	else
		return entry1.is_named();
}

//Resources rebuilder
//resource_directory - root resource directory
//resources_section - section where resource directory will be placed (must be attached to PE image)
//offset_from_section_start - offset from resources_section raw data start
//resource_directory is non-constant, because it will be sorted
//save_to_pe_headers - if true, new resource directory information will be saved to PE image headers
//auto_strip_last_section - if true and resources are placed in the last section, it will be automatically stripped
//number_of_id_entries and number_of_named_entries for resource directories are recalculated and not used
const pe_base::image_directory pe_base::rebuild_resources(resource_directory& info, section& resources_section, DWORD offset_from_section_start, bool save_to_pe_header, bool auto_strip_last_section)
{
	//Check that resources_section is attached to this PE image
	if(!section_attached(resources_section))
		throw pe_exception("Resource section must be attached to PE file", pe_exception::section_is_not_attached);
	
	//Check resource directory correctness
	if(info.get_entry_list().empty())
		throw pe_exception("Empty resource directory", pe_exception::incorrect_resource_directory);

	DWORD needed_size_for_structures = sizeof(DWORD); //Calculate needed size for resource tables and data
	DWORD needed_size_for_strings = 0;
	DWORD needed_size_for_data = 0;
	//sizeof(DWORD) - for DWORD alignment
	calculate_resource_data_space(info, needed_size_for_structures, needed_size_for_strings, needed_size_for_data);

	DWORD needed_size = needed_size_for_structures + needed_size_for_strings + needed_size_for_data;
	DWORD aligned_offset_from_section_start = align_up(offset_from_section_start, sizeof(DWORD));

	//Check if exports_section is last one. If it's not, check if there's enough place for resource data
	if(&resources_section != &*(sections_.end() - 1) && 
		(resources_section.empty() || align_up(resources_section.get_size_of_raw_data(), get_file_alignment())
		< needed_size + aligned_offset_from_section_start))
		throw pe_exception("Insufficient space for resource directory", pe_exception::insufficient_space);

	std::string& raw_data = resources_section.get_raw_data();

	//This will be done only is resources_section is the last section of image or for section with unaligned raw length of data
	if(raw_data.length() < needed_size + needed_size + aligned_offset_from_section_start)
		raw_data.resize(needed_size + aligned_offset_from_section_start); //Expand section raw data

	unsigned long current_structures_pos = aligned_offset_from_section_start;
	unsigned long current_strings_pos = current_structures_pos + needed_size_for_structures;
	unsigned long current_data_pos = current_strings_pos + needed_size_for_strings;
	rebuild_resource_directory(resources_section, info, current_structures_pos, current_data_pos, current_strings_pos, aligned_offset_from_section_start);
	
	//Adjust section raw and virtual sizes
	recalculate_section_sizes(resources_section, auto_strip_last_section);

	image_directory ret(rva_from_section_offset(resources_section, aligned_offset_from_section_start), needed_size);

	//If auto-rewrite of PE headers is required
	if(save_to_pe_header)
	{
		set_directory_rva(IMAGE_DIRECTORY_ENTRY_RESOURCE, ret.get_rva());
		set_directory_size(IMAGE_DIRECTORY_ENTRY_RESOURCE, ret.get_size());
	}

	return ret;
}

//Returns resources from PE file
const pe_base::resource_directory pe_base::get_resources() const
{
	resource_directory ret;

	if(!has_resources())
		return ret;

	//Get resource directory RVA
	DWORD res_rva = get_directory_rva(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	
	//Store already processed directories to avoid resource loops
	std::set<DWORD> processed;
	
	//Process all directories (recursion)
	ret = process_resource_directory(res_rva, 0, processed);

	return ret;
}

//Finds resource_directory_entry by ID
pe_base::resource_directory::id_entry_finder::id_entry_finder(DWORD id)
	:id_(id)
{}

bool pe_base::resource_directory::id_entry_finder::operator()(const resource_directory_entry& entry) const
{
	return !entry.is_named() && entry.get_id() == id_;
}

//Finds resource_directory_entry by name
pe_base::resource_directory::name_entry_finder::name_entry_finder(const std::wstring& name)
	:name_(name)
{}

bool pe_base::resource_directory::name_entry_finder::operator()(const resource_directory_entry& entry) const
{
	return entry.is_named() && entry.get_name() == name_;
}

//Finds resource_directory_entry by name or ID (universal)
pe_base::resource_directory::entry_finder::entry_finder(const std::wstring& name)
	:name_(name), named_(true)
{}

pe_base::resource_directory::entry_finder::entry_finder(DWORD id)
	:id_(id), named_(false)
{}

bool pe_base::resource_directory::entry_finder::operator()(const resource_directory_entry& entry) const
{
	if(named_)
		return entry.is_named() && entry.get_name() == name_;
	else
		return !entry.is_named() && entry.get_id() == id_;
}

//Returns resource_directory_entry by ID. If not found - throws an exception
const pe_base::resource_directory_entry& pe_base::resource_directory::entry_by_id(DWORD id) const
{
	entry_list::const_iterator i = std::find_if(entries_.begin(), entries_.end(), id_entry_finder(id));
	if(i == entries_.end())
		throw pe_exception("Resource directory entry not found", pe_exception::resource_directory_entry_not_found);

	return *i;
}

//Returns resource_directory_entry by name. If not found - throws an exception
const pe_base::resource_directory_entry& pe_base::resource_directory::entry_by_name(const std::wstring& name) const
{
	entry_list::const_iterator i = std::find_if(entries_.begin(), entries_.end(), name_entry_finder(name));
	if(i == entries_.end())
		throw pe_exception("Resource directory entry not found", pe_exception::resource_directory_entry_not_found);

	return *i;
}


//EXCEPTION DIRECTORY (exists on PE+ only)
//Default constructor
pe_base::exception_entry::exception_entry()
	:begin_address_(0), end_address_(0), unwind_info_address_(0),
	unwind_info_version_(0),
	flags_(0),
	size_of_prolog_(0),
	count_of_codes_(0),
	frame_register_(0),
	frame_offset_(0)
{}

//Constructor from data
pe_base::exception_entry::exception_entry(const IMAGE_RUNTIME_FUNCTION_ENTRY& entry, const UNWIND_INFO& unwind_info)
	:begin_address_(entry.BeginAddress), end_address_(entry.EndAddress), unwind_info_address_(entry.UnwindInfoAddress),
	unwind_info_version_(unwind_info.Version),
	flags_(unwind_info.Flags),
	size_of_prolog_(unwind_info.SizeOfProlog),
	count_of_codes_(unwind_info.CountOfCodes),
	frame_register_(unwind_info.FrameRegister),
	frame_offset_(unwind_info.FrameOffset)
{}

//Returns starting address of function, affected by exception unwinding
DWORD pe_base::exception_entry::get_begin_address() const
{
	return begin_address_;
}

//Returns ending address of function, affected by exception unwinding
DWORD pe_base::exception_entry::get_end_address() const
{
	return end_address_;
}

//Returns unwind info address
DWORD pe_base::exception_entry::get_unwind_info_address() const
{
	return unwind_info_address_;
}

//Returns UNWIND_INFO structure version
BYTE pe_base::exception_entry::get_unwind_info_version() const
{
	return unwind_info_version_;
}

//Returns unwind info flags
BYTE pe_base::exception_entry::get_flags() const
{
	return flags_;
}

//The function has an exception handler that should be called
//when looking for functions that need to examine exceptions
bool pe_base::exception_entry::has_exception_handler() const
{
	return (flags_ & UNW_FLAG_EHANDLER) ? true : false;
}

//The function has a termination handler that should be called
//when unwinding an exception
bool pe_base::exception_entry::has_termination_handler() const
{
	return (flags_ & UNW_FLAG_UHANDLER) ? true : false;
}

//The unwind info structure is not the primary one for the procedure
bool pe_base::exception_entry::is_chaininfo() const
{
	return (flags_ & UNW_FLAG_CHAININFO) ? true : false;
}

//Returns size of function prolog
BYTE pe_base::exception_entry::get_size_of_prolog() const
{
	return size_of_prolog_;
}

//Returns number of unwind slots
BYTE pe_base::exception_entry::get_number_of_unwind_slots() const
{
	return count_of_codes_;
}

//If the function uses frame pointer
bool pe_base::exception_entry::uses_frame_pointer() const
{
	return frame_register_ != 0;
}

//Number of the nonvolatile register used as the frame pointer,
//using the same encoding for the operation info field of UNWIND_CODE nodes
BYTE pe_base::exception_entry::get_frame_pointer_register_number() const
{
	return frame_register_;
}

//The scaled offset from RSP that is applied to the FP reg when it is established.
//The actual FP reg is set to RSP + 16 * this number, allowing offsets from 0 to 240
BYTE pe_base::exception_entry::get_scaled_rsp_offset() const
{
	return frame_offset_;
}

//Returns exception directory data (exists on PE+ only)
//Unwind opcodes are not listed, because their format and list are subject to change
const pe_base::exception_entry_list pe_base::get_exception_directory_data() const
{
	exception_entry_list ret;

	//If image doesn't have exception directory, return empty list
	if(!has_exception_directory())
		return ret;

	//Check the length in bytes of the section containing exception directory
	if(section_data_length_from_rva(get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXCEPTION), get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXCEPTION), section_data_virtual, true) < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY))
		throw pe_exception("Incorrect exception directory", pe_exception::incorrect_exception_directory);

	unsigned long current_pos = get_directory_rva(IMAGE_DIRECTORY_ENTRY_EXCEPTION);

	//Check if structures are DWORD-aligned
	if(current_pos % sizeof(DWORD))
		throw pe_exception("Incorrect exception directory", pe_exception::incorrect_exception_directory);

	//First IMAGE_RUNTIME_FUNCTION_ENTRY table
	IMAGE_RUNTIME_FUNCTION_ENTRY exception_table = section_data_from_rva<IMAGE_RUNTIME_FUNCTION_ENTRY>(current_pos, section_data_virtual, true);

	//todo: virtual addresses BeginAddress and EndAddress are not checked to be inside image
	while(exception_table.BeginAddress)
	{
		//Check addresses
		if(exception_table.BeginAddress > exception_table.EndAddress)
			throw pe_exception("Incorrect exception directory", pe_exception::incorrect_exception_directory);

		//Get unwind information
		UNWIND_INFO info = section_data_from_rva<UNWIND_INFO>(exception_table.UnwindInfoAddress, section_data_virtual, true);

		//Create exception entry and save it
		ret.push_back(exception_entry(exception_table, info));

		//Go to next exception entry
		current_pos += sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
		exception_table = section_data_from_rva<IMAGE_RUNTIME_FUNCTION_ENTRY>(current_pos, section_data_virtual, true);
	}

	return ret;
}


//DEBUG
//Default constructor
pe_base::debug_info::debug_info()
	:characteristics_(0),
	time_stamp_(0),
	major_version_(0), minor_version_(0),
	type_(0),
	size_of_data_(0),
	address_of_raw_data_(0),
	pointer_to_raw_data_(0),
	advanced_info_type_(advanced_info_none)
{}

//Constructor from data
pe_base::debug_info::debug_info(const IMAGE_DEBUG_DIRECTORY& debug)
	:characteristics_(debug.Characteristics),
	time_stamp_(debug.TimeDateStamp),
	major_version_(debug.MajorVersion), minor_version_(debug.MinorVersion),
	type_(debug.Type),
	size_of_data_(debug.SizeOfData),
	address_of_raw_data_(debug.AddressOfRawData),
	pointer_to_raw_data_(debug.PointerToRawData),
	advanced_info_type_(advanced_info_none)
{}

//Returns debug characteristics
DWORD pe_base::debug_info::get_characteristics() const
{
	return characteristics_;
}

//Returns debug datetimestamp
DWORD pe_base::debug_info::get_time_stamp() const
{
	return time_stamp_;
}

//Returns major version
DWORD pe_base::debug_info::get_major_version() const
{
	return major_version_;
}

//Returns minor version
DWORD pe_base::debug_info::get_minor_version() const
{
	return minor_version_;
}

//Returns type of debug info (unchecked)
DWORD pe_base::debug_info::get_type_raw() const
{
	return type_;
}

//Returns type of debug info from debug_info_type enumeration
pe_base::debug_info::debug_info_type pe_base::debug_info::get_type() const
{
	//Determine debug type
	switch(type_)
	{
	case IMAGE_DEBUG_TYPE_COFF:
		return debug_type_coff;

	case IMAGE_DEBUG_TYPE_CODEVIEW:
		return debug_type_codeview;

	case IMAGE_DEBUG_TYPE_FPO:
		return debug_type_fpo;

	case IMAGE_DEBUG_TYPE_MISC:
		return debug_type_misc;

	case IMAGE_DEBUG_TYPE_EXCEPTION:
		return debug_type_exception;

	case IMAGE_DEBUG_TYPE_FIXUP:
		return debug_type_fixup;

	case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
		return debug_type_omap_to_src;

	case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
		return debug_type_omap_from_src;

	case IMAGE_DEBUG_TYPE_BORLAND:
		return debug_type_borland;

	case IMAGE_DEBUG_TYPE_CLSID:
		return debug_type_clsid;

	case IMAGE_DEBUG_TYPE_RESERVED10:
		return debug_type_reserved10;
	}

	return debug_type_unknown;
}

//Returns size of debug data (internal, .pdb or other file doesn't count)
DWORD pe_base::debug_info::get_size_of_data() const
{
	return size_of_data_;
}

//Returns RVA of debug info when mapped to memory or zero, if info is not mapped
DWORD pe_base::debug_info::get_rva_of_raw_data() const
{
	return address_of_raw_data_;
}

//Returns raw file pointer to raw data
DWORD pe_base::debug_info::get_pointer_to_raw_data() const
{
	return pointer_to_raw_data_;
}

//Copy constructor
pe_base::debug_info::debug_info(const debug_info& info)
	:characteristics_(info.characteristics_),
	time_stamp_(info.time_stamp_),
	major_version_(info.major_version_), minor_version_(info.minor_version_),
	type_(info.type_),
	size_of_data_(info.size_of_data_),
	address_of_raw_data_(info.address_of_raw_data_),
	pointer_to_raw_data_(info.pointer_to_raw_data_),
	advanced_info_type_(info.advanced_info_type_)
{
	copy_advanced_info(info);
}

//Copy assignment operator
pe_base::debug_info& pe_base::debug_info::operator=(const debug_info& info)
{
	copy_advanced_info(info);

	characteristics_ = info.characteristics_;
	time_stamp_ = info.time_stamp_;
	major_version_ = info.major_version_;
	minor_version_ = info.minor_version_;
	type_ = info.type_;
	size_of_data_ = info.size_of_data_;
	address_of_raw_data_ = info.address_of_raw_data_;
	pointer_to_raw_data_ = info.pointer_to_raw_data_;
	advanced_info_type_ = info.advanced_info_type_;

	return *this;
}

//Default constructor
pe_base::debug_info::advanced_info::advanced_info()
	:adv_pdb_7_0_info(0) //Zero pointer to advanced data
{}

//Returns true if advanced debug info is present
bool pe_base::debug_info::advanced_info::is_present() const
{
	return adv_pdb_7_0_info != 0;
}

//Helper for advanced debug information copying
void pe_base::debug_info::copy_advanced_info(const debug_info& info)
{
	free_present_advanced_info();

	switch(info.advanced_info_type_)
	{
	case advanced_info_pdb_7_0:
		advanced_debug_info_.adv_pdb_7_0_info = new pdb_7_0_info(*info.advanced_debug_info_.adv_pdb_7_0_info);
		break;
	case advanced_info_pdb_2_0:
		advanced_debug_info_.adv_pdb_2_0_info = new pdb_2_0_info(*info.advanced_debug_info_.adv_pdb_2_0_info);
		break;
	case advanced_info_misc:
		advanced_debug_info_.adv_misc_info = new misc_debug_info(*info.advanced_debug_info_.adv_misc_info);
		break;
	case advanced_info_coff:
		advanced_debug_info_.adv_coff_info = new coff_debug_info(*info.advanced_debug_info_.adv_coff_info);
		break;
	}

	advanced_info_type_ = info.advanced_info_type_;
}

//Helper for clearing any present advanced debug information
void pe_base::debug_info::free_present_advanced_info()
{
	switch(advanced_info_type_)
	{
	case advanced_info_pdb_7_0:
		delete advanced_debug_info_.adv_pdb_7_0_info;
		break;
	case advanced_info_pdb_2_0:
		delete advanced_debug_info_.adv_pdb_2_0_info;
		break;
	case advanced_info_misc:
		delete advanced_debug_info_.adv_misc_info;
		break;
	case advanced_info_coff:
		delete advanced_debug_info_.adv_coff_info;
		break;
	}

	advanced_debug_info_.adv_pdb_7_0_info = 0;
	advanced_info_type_ = advanced_info_none;
}

//Destructor
pe_base::debug_info::~debug_info()
{
	free_present_advanced_info();
}

//Sets advanced debug information
void pe_base::debug_info::set_advanced_debug_info(const pdb_7_0_info& info)
{
	free_present_advanced_info();
	advanced_debug_info_.adv_pdb_7_0_info = new pdb_7_0_info(info);
	advanced_info_type_ = advanced_info_pdb_7_0;
}

void pe_base::debug_info::set_advanced_debug_info(const pdb_2_0_info& info)
{
	free_present_advanced_info();
	advanced_debug_info_.adv_pdb_2_0_info = new pdb_2_0_info(info);
	advanced_info_type_ = advanced_info_pdb_2_0;
}

void pe_base::debug_info::set_advanced_debug_info(const misc_debug_info& info)
{
	free_present_advanced_info();
	advanced_debug_info_.adv_misc_info = new misc_debug_info(info);
	advanced_info_type_ = advanced_info_misc;
}

void pe_base::debug_info::set_advanced_debug_info(const coff_debug_info& info)
{
	free_present_advanced_info();
	advanced_debug_info_.adv_coff_info = new coff_debug_info(info);
	advanced_info_type_ = advanced_info_coff;
}

//Returns advanced debug information type
pe_base::debug_info::advanced_info_type pe_base::debug_info::get_advanced_info_type() const
{
	return advanced_info_type_;
}

//Returns advanced debug information or throws an exception,
//if requested information type is not contained by structure
template<>
const pe_base::pdb_7_0_info pe_base::debug_info::get_advanced_debug_info<pe_base::pdb_7_0_info>() const
{
	if(advanced_info_type_ != advanced_info_pdb_7_0)
		throw pe_exception("Debug info structure does not contain PDB 7.0 data", pe_exception::advanced_debug_information_request_error);

	return *advanced_debug_info_.adv_pdb_7_0_info;
}

template<>
const pe_base::pdb_2_0_info pe_base::debug_info::get_advanced_debug_info<pe_base::pdb_2_0_info>() const
{
	if(advanced_info_type_ != advanced_info_pdb_2_0)
		throw pe_exception("Debug info structure does not contain PDB 2.0 data", pe_exception::advanced_debug_information_request_error);

	return *advanced_debug_info_.adv_pdb_2_0_info;
}

template<>
const pe_base::misc_debug_info pe_base::debug_info::get_advanced_debug_info<pe_base::misc_debug_info>() const
{
	if(advanced_info_type_ != advanced_info_misc)
		throw pe_exception("Debug info structure does not contain MISC data", pe_exception::advanced_debug_information_request_error);

	return *advanced_debug_info_.adv_misc_info;
}

template<>
const pe_base::coff_debug_info pe_base::debug_info::get_advanced_debug_info<pe_base::coff_debug_info>() const
{
	if(advanced_info_type_ != advanced_info_coff)
		throw pe_exception("Debug info structure does not contain COFF data", pe_exception::advanced_debug_information_request_error);

	return *advanced_debug_info_.adv_coff_info;
}

//Sets advanced debug information type, if no advanced info structure available
void pe_base::debug_info::set_advanced_info_type(advanced_info_type type)
{
	free_present_advanced_info();
	if(advanced_info_type_ >= advanced_info_codeview_4_0) //Don't set info type for those types, which have advanced info structures
		advanced_info_type_ = type;
}

//Default constructor
pe_base::pdb_7_0_info::pdb_7_0_info()
	:age_(0)
{
	memset(&guid_, 0, sizeof(guid_));
}

//Constructor from data
pe_base::pdb_7_0_info::pdb_7_0_info(const CV_INFO_PDB70* info)
	:age_(info->Age), guid_(info->Signature),
	pdb_file_name_(reinterpret_cast<const char*>(info->PdbFileName)) //Must be checked before for null-termination
{}

//Returns debug PDB 7.0 structure GUID
const GUID pe_base::pdb_7_0_info::get_guid() const
{
	return guid_;
}

//Returns age of build
DWORD pe_base::pdb_7_0_info::get_age() const
{
	return age_;
}

//Returns PDB file name / path
const std::string& pe_base::pdb_7_0_info::get_pdb_file_name() const
{
	return pdb_file_name_;
}

//Default constructor
pe_base::pdb_2_0_info::pdb_2_0_info()
	:age_(0), signature_(0)
{}

//Constructor from data
pe_base::pdb_2_0_info::pdb_2_0_info(const CV_INFO_PDB20* info)
	:age_(info->Age), signature_(info->Signature),
	pdb_file_name_(reinterpret_cast<const char*>(info->PdbFileName)) //Must be checked before for null-termination
{}

//Returns debug PDB 2.0 structure signature
DWORD pe_base::pdb_2_0_info::get_signature() const
{
	return signature_;
}

//Returns age of build
DWORD pe_base::pdb_2_0_info::get_age() const
{
	return age_;
}

//Returns PDB file name / path
const std::string& pe_base::pdb_2_0_info::get_pdb_file_name() const
{
	return pdb_file_name_;
}

//Default constructor
pe_base::misc_debug_info::misc_debug_info()
	:data_type_(0), unicode_(false)
{}

//Constructor from data
pe_base::misc_debug_info::misc_debug_info(const IMAGE_DEBUG_MISC* info)
	:data_type_(info->DataType), unicode_(info->Unicode ? true : false)
{
	//IMAGE_DEBUG_MISC::Data must be checked before!
	if(info->Unicode)
	{
		debug_data_unicode_ = std::wstring(reinterpret_cast<const wchar_t*>(info->Data), (info->Length - sizeof(IMAGE_DEBUG_MISC) + 1 /* BYTE[1] in the end of structure */) / 2);
		strip_nullbytes(debug_data_unicode_); //Strip nullbytes in the end of string
	}
	else
	{
		debug_data_ansi_ = std::string(reinterpret_cast<const char*>(info->Data), info->Length - sizeof(IMAGE_DEBUG_MISC) + 1 /* BYTE[1] in the end of structure */);
		strip_nullbytes(debug_data_ansi_); //Strip nullbytes in the end of string
	}
}

//Returns debug data type
DWORD pe_base::misc_debug_info::get_data_type() const
{
	return data_type_;
}

//Returns true if data type is exe name
bool pe_base::misc_debug_info::is_exe_name() const
{
	return data_type_ == IMAGE_DEBUG_MISC_EXENAME;
}

//Returns true if debug data is UNICODE
bool pe_base::misc_debug_info::is_unicode() const
{
	return unicode_;
}

//Returns debug data (ANSI)
const std::string& pe_base::misc_debug_info::get_data_ansi() const
{
	return debug_data_ansi_;
}

//Returns debug data (UNICODE)
const std::wstring& pe_base::misc_debug_info::get_data_unicode() const
{
	return debug_data_unicode_;
}

//Default constructor
pe_base::coff_debug_info::coff_debug_info()
	:number_of_symbols_(0),
	lva_to_first_symbol_(0),
	number_of_line_numbers_(0),
	lva_to_first_line_number_(0),
	rva_to_first_byte_of_code_(0),
	rva_to_last_byte_of_code_(0),
	rva_to_first_byte_of_data_(0),
	rva_to_last_byte_of_data_(0)
{}

//Constructor from data
pe_base::coff_debug_info::coff_debug_info(const IMAGE_COFF_SYMBOLS_HEADER* info)
	:number_of_symbols_(info->NumberOfSymbols),
	lva_to_first_symbol_(info->LvaToFirstSymbol),
	number_of_line_numbers_(info->NumberOfLinenumbers),
	lva_to_first_line_number_(info->LvaToFirstLinenumber),
	rva_to_first_byte_of_code_(info->RvaToFirstByteOfCode),
	rva_to_last_byte_of_code_(info->RvaToLastByteOfCode),
	rva_to_first_byte_of_data_(info->RvaToFirstByteOfData),
	rva_to_last_byte_of_data_(info->RvaToLastByteOfData)
{}

//Returns number of symbols
DWORD pe_base::coff_debug_info::get_number_of_symbols() const
{
	return number_of_symbols_;
}

//Returns virtual address of the first symbol
DWORD pe_base::coff_debug_info::get_lva_to_first_symbol() const
{
	return lva_to_first_symbol_;
}

//Returns number of line-number entries
DWORD pe_base::coff_debug_info::get_number_of_line_numbers() const
{
	return number_of_line_numbers_;
}

//Returns virtual address of the first line-number entry
DWORD pe_base::coff_debug_info::get_lva_to_first_line_number() const
{
	return lva_to_first_line_number_;
}

//Returns relative virtual address of the first byte of code
DWORD pe_base::coff_debug_info::get_rva_to_first_byte_of_code() const
{
	return rva_to_first_byte_of_code_;
}

//Returns relative virtual address of the last byte of code
DWORD pe_base::coff_debug_info::get_rva_to_last_byte_of_code() const
{
	return rva_to_last_byte_of_code_;
}

//Returns relative virtual address of the first byte of data
DWORD pe_base::coff_debug_info::get_rva_to_first_byte_of_data() const
{
	return rva_to_first_byte_of_data_;
}

//Returns relative virtual address of the last byte of data
DWORD pe_base::coff_debug_info::get_rva_to_last_byte_of_data() const
{
	return rva_to_last_byte_of_data_;
}

//Returns COFF symbols list
const pe_base::coff_debug_info::coff_symbols_list& pe_base::coff_debug_info::get_symbols() const
{
	return symbols_;
}

//Adds COFF symbol
void pe_base::coff_debug_info::add_symbol(const coff_symbol& sym)
{
	symbols_.push_back(sym);
}

//Default constructor
pe_base::coff_debug_info::coff_symbol::coff_symbol()
	:storage_class_(0),
	index_(0),
	section_number_(0), rva_(0),
	type_(0),
	is_filename_(false)
{}

//Returns storage class
DWORD pe_base::coff_debug_info::coff_symbol::get_storage_class() const
{
	return storage_class_;
}

//Returns symbol index
DWORD pe_base::coff_debug_info::coff_symbol::get_index() const
{
	return index_;
}

//Returns section number
DWORD pe_base::coff_debug_info::coff_symbol::get_section_number() const
{
	return section_number_;
}

//Returns RVA
DWORD pe_base::coff_debug_info::coff_symbol::get_rva() const
{
	return rva_;
}

//Returns true if structure contains file name
bool pe_base::coff_debug_info::coff_symbol::is_file() const
{
	return is_filename_;
}

//Returns text data (symbol or file name)
const std::string& pe_base::coff_debug_info::coff_symbol::get_symbol() const
{
	return name_;
}

//Sets storage class
void pe_base::coff_debug_info::coff_symbol::set_storage_class(DWORD storage_class)
{
	storage_class_ = storage_class;
}

//Sets symbol index
void pe_base::coff_debug_info::coff_symbol::set_index(DWORD index)
{
	index_ = index;
}

//Sets section number
void pe_base::coff_debug_info::coff_symbol::set_section_number(DWORD section_number)
{
	section_number_ = section_number;
}

//Sets RVA
void pe_base::coff_debug_info::coff_symbol::set_rva(DWORD rva)
{
	rva_ = rva;
}

//Sets file name
void pe_base::coff_debug_info::coff_symbol::set_file_name(const std::string& file_name)
{
	name_ = file_name;
	is_filename_ = true;
}

//Sets symbol name
void pe_base::coff_debug_info::coff_symbol::set_symbol_name(const std::string& symbol_name)
{
	name_ = symbol_name;
	is_filename_ = false;
}

//Returns type
WORD pe_base::coff_debug_info::coff_symbol::get_type() const
{
	return type_;
}

//Sets type
void pe_base::coff_debug_info::coff_symbol::set_type(WORD type)
{
	type_ = type;
}

//Returns debug information list
const pe_base::debug_info_list pe_base::get_debug_information() const
{
	debug_info_list ret;

	//If there's no debug directory, return empty list
	if(!has_debug())
		return ret;

	//Check the length in bytes of the section containing debug directory
	if(section_data_length_from_rva(get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG), get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG), section_data_virtual, true) < sizeof(IMAGE_DEBUG_DIRECTORY))
		throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

	unsigned long current_pos = get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG);

	//First IMAGE_DEBUG_DIRECTORY table
	IMAGE_DEBUG_DIRECTORY directory = section_data_from_rva<IMAGE_DEBUG_DIRECTORY>(current_pos, section_data_virtual, true);

	if(!is_sum_safe(get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG), get_directory_size(IMAGE_DIRECTORY_ENTRY_DEBUG)))
		throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

	//Iterate over all IMAGE_DEBUG_DIRECTORY directories
	while(directory.PointerToRawData
		&& current_pos < get_directory_rva(IMAGE_DIRECTORY_ENTRY_DEBUG) + get_directory_size(IMAGE_DIRECTORY_ENTRY_DEBUG))
	{
		//Create debug information structure
		debug_info info(directory);

		//Find raw debug data
		debug_data_list::const_iterator it = debug_data_.find(directory.PointerToRawData);
		if(it != debug_data_.end()) //If it exists, we'll do some detailed debug info research
		{
			const std::string& debug_data = (*it).second;
			switch(directory.Type)
			{
			case IMAGE_DEBUG_TYPE_COFF:
				{
					//Check data length
					if(debug_data.length() < sizeof(IMAGE_COFF_SYMBOLS_HEADER))
						throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

					//Get coff header structure pointer
					const IMAGE_COFF_SYMBOLS_HEADER* coff = reinterpret_cast<const IMAGE_COFF_SYMBOLS_HEADER*>(debug_data.data());

					//Check possible overflows
					if(coff->NumberOfSymbols >= max_dword / sizeof(IMAGE_SYMBOL)
						|| !is_sum_safe(coff->NumberOfSymbols * sizeof(IMAGE_SYMBOL), coff->LvaToFirstSymbol))
						throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

					//Check data length again
					if(debug_data.length() < coff->NumberOfSymbols * sizeof(IMAGE_SYMBOL) + coff->LvaToFirstSymbol)
						throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

					//Create COFF debug info structure
					coff_debug_info coff_info(coff);

					//Enumerate debug symbols data
					for(DWORD i = 0; i < coff->NumberOfSymbols; ++i)
					{
						//Safe sum (checked above)
						const IMAGE_SYMBOL* sym = reinterpret_cast<const IMAGE_SYMBOL*>(debug_data.data() + i * sizeof(IMAGE_SYMBOL) + coff->LvaToFirstSymbol);

						coff_debug_info::coff_symbol symbol;
						symbol.set_index(i); //Save symbol index
						symbol.set_storage_class(sym->StorageClass); //Save storage class
						symbol.set_type(sym->Type); //Save storage class

						//Check data length again
						if(!is_sum_safe(i, sym->NumberOfAuxSymbols)
							|| (i + sym->NumberOfAuxSymbols) > coff->NumberOfSymbols
							|| debug_data.length() < (i + 1) * sizeof(IMAGE_SYMBOL) + coff->LvaToFirstSymbol + sym->NumberOfAuxSymbols * sizeof(IMAGE_SYMBOL))
							throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

						//If symbol is filename
						if(sym->StorageClass == IMAGE_SYM_CLASS_FILE)
						{
							//Save file name, it is situated just after this IMAGE_SYMBOL structure
							std::string file_name(reinterpret_cast<const char*>(debug_data.data() + (i + 1) * sizeof(IMAGE_SYMBOL)), sym->NumberOfAuxSymbols * sizeof(IMAGE_SYMBOL));
							strip_nullbytes(file_name);
							symbol.set_file_name(file_name);

							//Save symbol info
							coff_info.add_symbol(symbol);

							//Move to next symbol
							i += sym->NumberOfAuxSymbols;
							continue;
						}

						//Dump some other symbols
						if(((sym->StorageClass == IMAGE_SYM_CLASS_STATIC)
							&& (sym->NumberOfAuxSymbols == 0)
							&& (sym->SectionNumber == 1))
							||
							((sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL)
							&& ISFCN(sym->Type)
							&& (sym->SectionNumber > 0))
							)
						{
							//Save RVA and section number
							symbol.set_section_number(sym->SectionNumber);
							symbol.set_rva(sym->Value);

							//If symbol has short name
							if(sym->N.Name.Short)
							{
								//Copy and save symbol name
								char name_buff[9];
								memcpy(name_buff, sym->N.ShortName, 8);
								name_buff[8] = '\0';
								symbol.set_symbol_name(name_buff);
							}
							else
							{
								//Symbol has long name

								//Check possible overflows
								if(!is_sum_safe(coff->LvaToFirstSymbol + coff->NumberOfSymbols * sizeof(IMAGE_SYMBOL), sym->N.Name.Long))
									throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

								//Here we have an offset to the string table
								DWORD symbol_offset = coff->LvaToFirstSymbol + coff->NumberOfSymbols * sizeof(IMAGE_SYMBOL) + sym->N.Name.Long;

								//Check data length
								if(debug_data.length() < symbol_offset)
									throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

								//Check symbol name for null-termination
								if(!is_null_terminated(debug_data.data() + symbol_offset, debug_data.length() - symbol_offset))
									throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

								//Save symbol name
								symbol.set_symbol_name(debug_data.data() + symbol_offset);
							}

							//Save symbol info
							coff_info.add_symbol(symbol);

							//Move to next symbol
							i += sym->NumberOfAuxSymbols;
							continue;
						}
					}

					info.set_advanced_debug_info(coff_info);
				}
				break;

			case IMAGE_DEBUG_TYPE_CODEVIEW:
				{
					//Check data length
					if(debug_data.length() < sizeof(POMFSignature))
						throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

					//Get POMFSignature structure pointer from the very beginning of debug data
					const OMFSignature* sig = reinterpret_cast<const OMFSignature*>(debug_data.data());
					if(!memcmp(sig->Signature, "RSDS", 4))
					{
						//Signature is "RSDS" - PDB 7.0

						//Check data length
						if(debug_data.length() < sizeof(CV_INFO_PDB70))
							throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

						const CV_INFO_PDB70* pdb_data = reinterpret_cast<const CV_INFO_PDB70*>(debug_data.data());

						//Check PDB file name null-termination
						if(!is_null_terminated(pdb_data->PdbFileName, debug_data.length() - (sizeof(CV_INFO_PDB70) - 1 /* BYTE of filename in structure */)))
							throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

						info.set_advanced_debug_info(pdb_7_0_info(pdb_data));
					}
					else if(!memcmp(sig->Signature, "NB10", 4))
					{
						//Signature is "NB10" - PDB 2.0

						//Check data length
						if(debug_data.length() < sizeof(CV_INFO_PDB20))
							throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

						const CV_INFO_PDB20* pdb_data = reinterpret_cast<const CV_INFO_PDB20*>(debug_data.data());

						//Check PDB file name null-termination
						if(!is_null_terminated(pdb_data->PdbFileName, debug_data.length() - (sizeof(CV_INFO_PDB20) - 1 /* BYTE of filename in structure */)))
							throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

						info.set_advanced_debug_info(pdb_2_0_info(pdb_data));
					}
					else if(!memcmp(sig->Signature, "NB09", 4))
					{
						//CodeView 4.0, no structures available
						info.set_advanced_info_type(debug_info::advanced_info_codeview_4_0);
					}
					else if(!memcmp(sig->Signature, "NB11", 4))
					{
						//CodeView 5.0, no structures available
						info.set_advanced_info_type(debug_info::advanced_info_codeview_5_0);
					}
					else if(!memcmp(sig->Signature, "NB05", 4))
					{
						//Other CodeView, no structures available
						info.set_advanced_info_type(debug_info::advanced_info_codeview);
					}
				}

				break;

			case IMAGE_DEBUG_TYPE_MISC:
				{
					//Check data length
					if(debug_data.length() < sizeof(IMAGE_DEBUG_MISC))
						throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

					//Get misc structure pointer
					const IMAGE_DEBUG_MISC* misc_data = reinterpret_cast<const IMAGE_DEBUG_MISC*>(debug_data.data());

					//Check misc data length
					if(debug_data.length() < misc_data->Length /* Total length of record */)
						throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

					//Save advanced information
					info.set_advanced_debug_info(misc_debug_info(misc_data));
				}
				break;
			}
		}

		//Save debug information structure
		ret.push_back(info);

		//Check possible overflow
		if(!is_sum_safe(current_pos, sizeof(IMAGE_DEBUG_DIRECTORY)))
			throw pe_exception("Incorrect debug directory", pe_exception::incorrect_debug_directory);

		//Go to next debug entry
		current_pos += sizeof(IMAGE_DEBUG_DIRECTORY);
		directory = section_data_from_rva<IMAGE_DEBUG_DIRECTORY>(current_pos, section_data_virtual, true);
	}

	return ret;
}


//.NET
pe_base::basic_dotnet_info::basic_dotnet_info()
{
	memset(&header_, 0, sizeof(header_));
}

//Constructor from data
pe_base::basic_dotnet_info::basic_dotnet_info(const IMAGE_COR20_HEADER& header)
	:header_(header)
{}

//Returns major runtime version
WORD pe_base::basic_dotnet_info::get_major_runtime_version() const
{
	return header_.MajorRuntimeVersion;
}

//Returns minor runtime version
WORD pe_base::basic_dotnet_info::get_minor_runtime_version() const
{
	return header_.MinorRuntimeVersion;
}

//Returns RVA of metadata (symbol table and startup information)
DWORD pe_base::basic_dotnet_info::get_rva_of_metadata() const
{
	return header_.MetaData.VirtualAddress;
}

//Returns size of metadata (symbol table and startup information)
DWORD pe_base::basic_dotnet_info::get_size_of_metadata() const
{
	return header_.MetaData.Size;
}

//Returns flags
DWORD pe_base::basic_dotnet_info::get_flags() const
{
	return header_.Flags;
}

//Returns true if entry point is native
bool pe_base::basic_dotnet_info::is_native_entry_point() const
{
#ifdef _MSC_VER
#if _MSC_VER < 1600
	//Not defined for VS 9
#define COMIMAGE_FLAGS_NATIVE_ENTRYPOINT 16
#endif
#endif
	return (header_.Flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) ? true : false;
}

//Returns true if 32 bit required
bool pe_base::basic_dotnet_info::is_32bit_required() const
{
	return (header_.Flags & COMIMAGE_FLAGS_32BITREQUIRED) ? true : false;
}

//Returns true if image is IL library
bool pe_base::basic_dotnet_info::is_il_library() const
{
	return (header_.Flags & COMIMAGE_FLAGS_IL_LIBRARY) ? true : false;
}

//Returns true if image uses IL only
bool pe_base::basic_dotnet_info::is_il_only() const
{
	return (header_.Flags & COMIMAGE_FLAGS_ILONLY) ? true : false;
}

//Returns entry point RVA (if entry point is native)
//Returns entry point managed token (if entry point is managed)
DWORD pe_base::basic_dotnet_info::get_entry_point_rva_or_token() const
{
	return header_.EntryPointToken;
}

//Returns RVA of managed resources
DWORD pe_base::basic_dotnet_info::get_rva_of_resources() const
{
	return header_.Resources.VirtualAddress;
}

//Returns size of managed resources
DWORD pe_base::basic_dotnet_info::get_size_of_resources() const
{
	return header_.Resources.Size;
}

//Returns RVA of strong name signature
DWORD pe_base::basic_dotnet_info::get_rva_of_strong_name_signature() const
{
	return header_.StrongNameSignature.VirtualAddress;
}

//Returns size of strong name signature
DWORD pe_base::basic_dotnet_info::get_size_of_strong_name_signature() const
{
	return header_.StrongNameSignature.Size;
}

//Returns RVA of code manager table
DWORD pe_base::basic_dotnet_info::get_rva_of_code_manager_table() const
{
	return header_.CodeManagerTable.VirtualAddress;
}

//Returns size of code manager table
DWORD pe_base::basic_dotnet_info::get_size_of_code_manager_table() const
{
	return header_.CodeManagerTable.Size;
}

//Returns RVA of VTable fixups
DWORD pe_base::basic_dotnet_info::get_rva_of_vtable_fixups() const
{
	return header_.VTableFixups.VirtualAddress;
}

//Returns size of VTable fixups
DWORD pe_base::basic_dotnet_info::get_size_of_vtable_fixups() const
{
	return header_.VTableFixups.Size;
}

//Returns RVA of export address table jumps
DWORD pe_base::basic_dotnet_info::get_rva_of_export_address_table_jumps() const
{
	return header_.ExportAddressTableJumps.VirtualAddress;
}

//Returns size of export address table jumps
DWORD pe_base::basic_dotnet_info::get_size_of_export_address_table_jumps() const
{
	return header_.ExportAddressTableJumps.Size;
}

//Returns RVA of managed native header
//(precompiled header info, usually set to zero, for internal use)
DWORD pe_base::basic_dotnet_info::get_rva_of_managed_native_header() const
{
	return header_.ManagedNativeHeader.VirtualAddress;
}

//Returns size of managed native header
//(precompiled header info, usually set to zero, for internal use)
DWORD pe_base::basic_dotnet_info::get_size_of_managed_native_header() const
{
	return header_.ManagedNativeHeader.Size;
}

//Returns basic .NET information
//If image is not native, throws an exception
const pe_base::basic_dotnet_info pe_base::get_basic_dotnet_info() const
{
	//If there's no debug directory, return empty list
	if(!has_debug())
		throw pe_exception("Image does not have managed code", pe_exception::image_does_not_have_managed_code);

	//Return basic .NET information
	return basic_dotnet_info(section_data_from_rva<IMAGE_COR20_HEADER>(get_directory_rva(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR), section_data_virtual, true));
}


//ENTROPY
//Calculates entropy for PE image section
double pe_base::calculate_entropy(const section& s)
{
	if(s.get_raw_data().empty()) //Don't count entropy for empty sections
		throw pe_exception("Section is empty", pe_exception::section_is_empty);

	return calculate_entropy(s.get_raw_data().data(), s.get_raw_data().length());
}

//Calculates entropy from bytes count
double pe_base::calculate_entropy(const DWORD byte_count[256], std::streamoff total_length)
{
	double entropy = 0.; //Entropy result value
	//Calculate entropy
	for(DWORD i = 0; i < 256; ++i)
	{
		double temp = static_cast<double>(byte_count[i]) / total_length;
		if(temp > 0.)
			entropy += abs(temp * (log(temp) * log_2));
	}

	return entropy;
}

//Calculates entropy for istream (from current position of stream)
double pe_base::calculate_entropy(std::istream& file)
{
	DWORD byte_count[256] = {0}; //Byte count for each of 255 bytes

	if(file.bad())
		throw pe_exception("Stream is bad", pe_exception::stream_is_bad);
	
	std::streamoff pos = file.tellg();

	std::streamoff length = get_file_size(file);
	length -= file.tellg();

	if(!length) //Don't calculate entropy for empty buffers
		throw pe_exception("Data length is zero", pe_exception::data_is_empty);
	
	//Count bytes
	for(std::streamoff i = 0; i != length; ++i)
		++byte_count[static_cast<unsigned char>(file.get())];

	file.seekg(pos);

	return calculate_entropy(byte_count, length);
}

//Calculates entropy for data block
double pe_base::calculate_entropy(const char* data, size_t length)
{
	DWORD byte_count[256] = {0}; //Byte count for each of 255 bytes

	if(!length) //Don't calculate entropy for empty buffers
		throw pe_exception("Data length is zero", pe_exception::data_is_empty);

	//Count bytes
	for(size_t i = 0; i != length; ++i)
		++byte_count[static_cast<unsigned char>(data[i])];
	
	return calculate_entropy(byte_count, length);
}

//Calculates entropy for this PE file (only section data)
double pe_base::calculate_entropy() const
{
	DWORD byte_count[256] = {0}; //Byte count for each of 255 bytes

	size_t total_data_length = 0;

	//Count bytes for each section
	for(section_list::const_iterator it = sections_.begin(); it != sections_.end(); ++it)
	{
		const std::string& data = (*it).get_raw_data();
		size_t length = data.length();
		total_data_length += length;
		for(size_t i = 0; i != length; ++i)
			++byte_count[static_cast<unsigned char>(data[i])];
	}

	return calculate_entropy(byte_count, total_data_length);
}

pe_base::section_ptr_finder::section_ptr_finder(const section& s)
	:s_(s)
{}

bool pe_base::section_ptr_finder::operator()(const section& s) const
{
	return &s == &s_;
}

//Default constructor
pe_base::image_directory::image_directory()
	:rva_(0), size_(0)
{}

//Constructor from data
pe_base::image_directory::image_directory(DWORD rva, DWORD size)
	:rva_(rva), size_(size)
{}

//Returns RVA
DWORD pe_base::image_directory::get_rva() const
{
	return rva_;
}

//Returns size
DWORD pe_base::image_directory::get_size() const
{
	return size_;
}

//Sets RVA
void pe_base::image_directory::set_rva(DWORD rva)
{
	rva_ = rva;
}

//Sets size
void pe_base::image_directory::set_size(DWORD size)
{
	size_ = size;
}

//Realigns file (changes file alignment)
void pe_base::realign_file(unsigned long new_file_alignment)
{
	//Checks alignment for correctness
	set_file_alignment(new_file_alignment);
	realign_all_sections();
}

//Helper function to recalculate RAW and virtual section sizes and strip it, if necessary
void pe_base::recalculate_section_sizes(section& s, bool auto_strip)
{
	prepare_section(s); //Recalculate section raw addresses

	//Strip RAW size of section, if it is the last one
	//For all others it must be file-aligned and calculated by prepare_section() call
	if(auto_strip && !(sections_.empty() || &s == &*(sections_.end() - 1)))
	{
		//Strip ending raw data nullbytes to optimize size
		std::string& raw_data = s.get_raw_data();
		if(!raw_data.empty())
		{
			std::string::size_type i = raw_data.length();
			for(; i != 1; --i)
			{
				if(raw_data[i - 1] != 0)
					break;
			}
			
			raw_data.resize(i);
		}

		s.set_size_of_raw_data(static_cast<DWORD>(raw_data.length()));
	}

	//Can occur only for last section
	if(align_up(s.get_virtual_size(), get_section_alignment()) < align_up(s.get_size_of_raw_data(), get_file_alignment()))
		set_section_virtual_size(s, align_up(s.get_size_of_raw_data(), get_section_alignment())); //Recalculate section virtual size
}

//Returns data from the beginning of image
//Size = SizeOfHeaders
const std::string& pe_base::get_full_headers_data() const
{
	return full_headers_data_;
}
