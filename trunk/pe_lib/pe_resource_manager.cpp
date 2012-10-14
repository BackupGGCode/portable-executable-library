#include <algorithm>
#include <sstream>
#include <iomanip>
#include <math.h>
#include "pe_resource_manager.h"

#define U16TEXT(t) reinterpret_cast<const unicode16_t*>( t )

namespace pe_bliss
{
using namespace pe_win;

//Root version info block key value
const u16string pe_resource_viewer::version_info_key(U16TEXT("V\0S\0_\0V\0E\0R\0S\0I\0O\0N\0_\0I\0N\0F\0O\0\0"));
//Default process language, UNICODE
const std::wstring version_info_viewer::default_language_translation(L"041904b0");

#define StringFileInfo U16TEXT("S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0")
#define SizeofStringFileInfo sizeof("S\0t\0r\0i\0n\0g\0F\0i\0l\0e\0I\0n\0f\0o\0\0")
#define VarFileInfo U16TEXT("V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0")
#define Translation U16TEXT("T\0r\0a\0n\0s\0l\0a\0t\0i\0o\0n\0\0")

#define VarFileInfoAligned U16TEXT("V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0\0")
#define TranslationAligned U16TEXT("T\0r\0a\0n\0s\0l\0a\0t\0i\0o\0n\0\0\0\0")
#define SizeofVarFileInfoAligned sizeof("V\0a\0r\0F\0i\0l\0e\0I\0n\0f\0o\0\0\0\0")
#define SizeofTranslationAligned sizeof("T\0r\0a\0n\0s\0l\0a\0t\0i\0o\0n\0\0\0\0")

//Constructor from root resource_directory
pe_resource_viewer::pe_resource_viewer(const pe_base::resource_directory& root_directory)
	:root_dir_(root_directory)
{}

//Finder helpers
bool pe_resource_viewer::has_name::operator()(const pe_base::resource_directory_entry& entry) const
{
	return entry.is_named();
}

bool pe_resource_viewer::has_id::operator()(const pe_base::resource_directory_entry& entry) const
{
	return !entry.is_named();
}

//Lists resource types existing in PE file (non-named only)
const pe_resource_viewer::resource_type_list pe_resource_viewer::list_resource_types() const
{
	resource_type_list ret;

	//Get root directory entries list
	const pe_base::resource_directory::entry_list& entries = root_dir_.get_entry_list();
	for(pe_base::resource_directory::entry_list::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		//List all non-named items
		if(!(*it).is_named())
			ret.push_back((*it).get_id());
	}

	return ret;
}

//Returns true if resource type exists
bool pe_resource_viewer::resource_exists(resource_type type) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_.get_entry_list();
	return std::find_if(entries.begin(), entries.end(), pe_base::resource_directory::id_entry_finder(type)) != entries.end();
}

//Returns true if resource name exists
bool pe_resource_viewer::resource_exists(const std::wstring& root_name) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_.get_entry_list();
	return std::find_if(entries.begin(), entries.end(), pe_base::resource_directory::name_entry_finder(root_name)) != entries.end();
}

//Helper function to get name list from entry list
const pe_resource_viewer::resource_name_list pe_resource_viewer::get_name_list(const pe_base::resource_directory::entry_list& entries)
{
	resource_name_list ret;

	for(pe_base::resource_directory::entry_list::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		//List all named items
		if((*it).is_named())
			ret.push_back((*it).get_name());
	}

	return ret;
}

//Helper function to get ID list from entry list
const pe_resource_viewer::resource_id_list pe_resource_viewer::get_id_list(const pe_base::resource_directory::entry_list& entries)
{
	resource_id_list ret;

	for(pe_base::resource_directory::entry_list::const_iterator it = entries.begin(); it != entries.end(); ++it)
	{
		//List all non-named items
		if(!(*it).is_named())
			ret.push_back((*it).get_id());
	}

	return ret;
}

//Lists resource names existing in PE file by resource type
const pe_resource_viewer::resource_name_list pe_resource_viewer::list_resource_names(resource_type type) const
{
	return get_name_list(root_dir_.entry_by_id(type).get_resource_directory().get_entry_list());
}

//Lists resource names existing in PE file by resource name
const pe_resource_viewer::resource_name_list pe_resource_viewer::list_resource_names(const std::wstring& root_name) const
{
	return get_name_list(root_dir_.entry_by_name(root_name).get_resource_directory().get_entry_list());
}

//Lists resource IDs existing in PE file by resource type
const pe_resource_viewer::resource_id_list pe_resource_viewer::list_resource_ids(resource_type type) const
{
	return get_id_list(root_dir_.entry_by_id(type).get_resource_directory().get_entry_list());
}

//Lists resource IDs existing in PE file by resource name
const pe_resource_viewer::resource_id_list pe_resource_viewer::list_resource_ids(const std::wstring& root_name) const
{
	return get_id_list(root_dir_.entry_by_name(root_name).get_resource_directory().get_entry_list());
}

//Returns resource count by type
unsigned long pe_resource_viewer::get_resource_count(resource_type type) const
{
	return static_cast<unsigned long>(
		root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.get_entry_list()
		.size());
}

//Returns language count of resource by resource type and name
unsigned long pe_resource_viewer::get_language_count(resource_type type, const std::wstring& name) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return static_cast<unsigned long>(std::count_if(entries.begin(), entries.end(), has_id()));
}

//Returns language count of resource by resource names
unsigned long pe_resource_viewer::get_language_count(const std::wstring& root_name, const std::wstring& name) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return static_cast<unsigned long>(std::count_if(entries.begin(), entries.end(), has_id()));
}

//Returns language count of resource by resource type and ID
unsigned long pe_resource_viewer::get_language_count(resource_type type, uint32_t id) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return static_cast<unsigned long>(std::count_if(entries.begin(), entries.end(), has_id()));
}

//Returns language count of resource by resource name and ID
unsigned long pe_resource_viewer::get_language_count(const std::wstring& root_name, uint32_t id) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return static_cast<unsigned long>(std::count_if(entries.begin(), entries.end(), has_id()));
}

//Lists resource languages by resource type and name
const pe_resource_viewer::resource_language_list pe_resource_viewer::list_resource_languages(resource_type type, const std::wstring& name) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return get_id_list(entries);
}

//Lists resource languages by resource names
const pe_resource_viewer::resource_language_list pe_resource_viewer::list_resource_languages(const std::wstring& root_name, const std::wstring& name) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return get_id_list(entries);
}

//Lists resource languages by resource type and ID
const pe_resource_viewer::resource_language_list pe_resource_viewer::list_resource_languages(resource_type type, uint32_t id) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return get_id_list(entries);
}

//Lists resource languages by resource name and ID
const pe_resource_viewer::resource_language_list pe_resource_viewer::list_resource_languages(const std::wstring& root_name, uint32_t id) const
{
	const pe_base::resource_directory::entry_list& entries =
		root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.get_entry_list();

	return get_id_list(entries);
}

//Returns raw resource data by type, name and language
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_name(uint32_t language, resource_type type, const std::wstring& name) const
{
	return resource_data_info(root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.entry_by_id(language)
		.get_data_entry()); //Data directory
}

//Returns raw resource data by root name, name and language
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_name(uint32_t language, const std::wstring& root_name, const std::wstring& name) const
{
	return resource_data_info(root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.entry_by_id(language)
		.get_data_entry()); //Data directory
}

//Returns raw resource data by type, ID and language
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_id(uint32_t language, resource_type type, uint32_t id) const
{
	return resource_data_info(root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.entry_by_id(language)
		.get_data_entry()); //Data directory
}

//Returns raw resource data by root name, ID and language
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_id(uint32_t language, const std::wstring& root_name, uint32_t id) const
{
	return resource_data_info(root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.entry_by_id(language)
		.get_data_entry()); //Data directory
}

//Returns raw resource data by type, name and index in language directory (instead of language)
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_name(resource_type type, const std::wstring& name, uint32_t index) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.get_entry_list();

	if(entries.size() <= index)
		throw pe_exception("Resource data entry not found", pe_exception::resource_data_entry_not_found);

	return resource_data_info(entries.at(index).get_data_entry()); //Data directory
}

//Returns raw resource data by root name, name and index in language directory (instead of language)
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_name(const std::wstring& root_name, const std::wstring& name, uint32_t index) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_name(name)
		.get_resource_directory() //Language directory
		.get_entry_list();

	if(entries.size() <= index)
		throw pe_exception("Resource data entry not found", pe_exception::resource_data_entry_not_found);

	return resource_data_info(entries.at(index).get_data_entry()); //Data directory
}

//Returns raw resource data by type, ID and index in language directory (instead of language)
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_id(resource_type type, uint32_t id, uint32_t index) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_ //Type directory
		.entry_by_id(type)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.get_entry_list();

	if(entries.size() <= index)
		throw pe_exception("Resource data entry not found", pe_exception::resource_data_entry_not_found);

	return resource_data_info(entries.at(index).get_data_entry()); //Data directory
}

//Returns raw resource data by root name, ID and index in language directory (instead of language)
const pe_resource_viewer::resource_data_info pe_resource_viewer::get_resource_data_by_id(const std::wstring& root_name, uint32_t id, uint32_t index) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_ //Type directory
		.entry_by_name(root_name)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(id)
		.get_resource_directory() //Language directory
		.get_entry_list();

	if(entries.size() <= index)
		throw pe_exception("Resource data entry not found", pe_exception::resource_data_entry_not_found);

	return resource_data_info(entries.at(index).get_data_entry()); //Data directory
}

//Helper function of creating bitmap header
const std::string pe_resource_viewer::create_bitmap(const std::string& resource_data) const
{
	//Create bitmap file header
	bitmapfileheader header = {0};
	header.bfType = 0x4d42; //Signature "BM"
	header.bfOffBits = sizeof(bitmapfileheader) + sizeof(bitmapinfoheader); //Offset to bitmap bits
	header.bfSize = static_cast<uint32_t>(sizeof(bitmapfileheader) + resource_data.length()); //Size of bitmap

	//Check size of resource data
	if(resource_data.length() < sizeof(bitmapinfoheader))
		throw pe_exception("Incorrect resource bitmap", pe_exception::resource_incorrect_bitmap);

	{
		//Get bitmap info header
		const bitmapinfoheader* info = reinterpret_cast<const bitmapinfoheader*>(resource_data.data());

		//If color table is present, skip it
		if(info->biClrUsed != 0)
			header.bfOffBits += 4 * info->biClrUsed; //Add this size to offset to bitmap bits
		else if(info->biBitCount <= 8)
			header.bfOffBits += 4 * static_cast<uint32_t>(pow(2.f, info->biBitCount)); //Add this size to offset to bitmap bits
	}

	//Return final bitmap data
	return std::string(reinterpret_cast<const char*>(&header), sizeof(bitmapfileheader)) + resource_data;
}

//Returns bitmap data by name and index in language directory (instead of language) (minimum checks of format correctness)
const std::string pe_resource_viewer::get_bitmap_by_name(const std::wstring& name, uint32_t index) const
{
	return create_bitmap(get_resource_data_by_name(resource_bitmap, name, index).get_data());
};

//Returns bitmap data by name and language (minimum checks of format correctness)
const std::string pe_resource_viewer::get_bitmap_by_name(uint32_t language, const std::wstring& name) const
{
	return create_bitmap(get_resource_data_by_name(language, resource_bitmap, name).get_data());
}

//Returns bitmap data by ID and language (minimum checks of format correctness)
const std::string pe_resource_viewer::get_bitmap_by_id_lang(uint32_t language, uint32_t id) const
{
	return create_bitmap(get_resource_data_by_id(language, resource_bitmap, id).get_data());
};

//Returns bitmap data by ID and index in language directory (instead of language) (minimum checks of format correctness)
const std::string pe_resource_viewer::get_bitmap_by_id(uint32_t id, uint32_t index) const
{
	return create_bitmap(get_resource_data_by_id(resource_bitmap, id, index).get_data());
}

//Helper function of creating icon headers from ICON_GROUP resource data
//Returns icon count
uint16_t pe_resource_viewer::format_icon_headers(std::string& ico_data, const std::string& resource_data) const
{
	//Check resource data size
	if(resource_data.length() < sizeof(ico_header))
		throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

	//Get icon header
	const ico_header* info = reinterpret_cast<const ico_header*>(resource_data.data());

	//Check resource data size
	if(resource_data.length() < sizeof(ico_header) + info->Count * sizeof(icon_group))
		throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

	//Reserve memory to speed up a little
	ico_data.reserve(sizeof(ico_header) + info->Count * sizeof(icondirentry));
	ico_data.append(reinterpret_cast<const char*>(info), sizeof(ico_header));

	//Iterate over all listed icons
	uint32_t offset = sizeof(ico_header) + sizeof(icondirentry) * info->Count;
	for(uint16_t i = 0; i != info->Count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(resource_data.data() + sizeof(ico_header) + i * sizeof(icon_group));

		//Fill icon data
		icondirentry direntry;
		direntry.BitCount = group->BitCount;
		direntry.ColorCount = group->ColorCount;
		direntry.Height = group->Height;
		direntry.Planes = group->Planes;
		direntry.Reserved = group->Reserved;
		direntry.SizeInBytes = group->SizeInBytes;
		direntry.Width = group->Width;
		direntry.ImageOffset = offset;

		//Add icon header to returned value
		ico_data.append(reinterpret_cast<const char*>(&direntry), sizeof(icondirentry));

		offset += group->SizeInBytes;
	}

	//Return icon count
	return info->Count;
}

//Returns icon data by name and index in language directory (instead of language) (minimum checks of format correctness)
const std::string pe_resource_viewer::get_icon_by_name(const std::wstring& name, uint32_t index) const
{
	std::string ret;

	//Get resource by name and index
	const std::string data = get_resource_data_by_name(resource_icon_group, name, index).get_data();

	//Create icon headers
	uint16_t icon_count = format_icon_headers(ret, data);

	//Append icon data
	for(uint16_t i = 0; i != icon_count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(data.data() + sizeof(ico_header) + i * sizeof(icon_group));
		ret += get_resource_data_by_id(resource_icon, group->Number, index).get_data();
	}

	return ret;
}

//Returns icon data by name and language (minimum checks of format correctness)
const std::string pe_resource_viewer::get_icon_by_name(uint32_t language, const std::wstring& name) const
{
	std::string ret;

	//Get resource by name and language
	const std::string data = get_resource_data_by_name(language, resource_icon_group, name).get_data();

	//Create icon headers
	uint16_t icon_count = format_icon_headers(ret, data);

	//Append icon data
	for(uint16_t i = 0; i != icon_count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(data.data() + sizeof(ico_header) + i * sizeof(icon_group));
		ret += get_resource_data_by_id(language, resource_icon, group->Number).get_data();
	}

	return ret;
}

//Returns icon data by ID and language (minimum checks of format correctness)
const std::string pe_resource_viewer::get_icon_by_id_lang(uint32_t language, uint32_t id) const
{
	std::string ret;

	//Get resource by language and id
	const std::string data = get_resource_data_by_id(language, resource_icon_group, id).get_data();

	//Create icon headers
	uint16_t icon_count = format_icon_headers(ret, data);

	//Append icon data
	for(uint16_t i = 0; i != icon_count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(data.data() + sizeof(ico_header) + i * sizeof(icon_group));
		ret += get_resource_data_by_id(language, resource_icon, group->Number).get_data();
	}

	return ret;
}

//Returns icon data by ID and index in language directory (instead of language) (minimum checks of format correctness)
const std::string pe_resource_viewer::get_icon_by_id(uint32_t id, uint32_t index) const
{
	std::string ret;

	//Get resource by id and index
	const std::string data = get_resource_data_by_id(resource_icon_group, id, index).get_data();

	//Create icon headers
	uint16_t icon_count = format_icon_headers(ret, data);

	//Append icon data
	for(uint16_t i = 0; i != icon_count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(data.data() + sizeof(ico_header) + i * sizeof(icon_group));
		ret += get_resource_data_by_id(resource_icon, group->Number, index).get_data();
	}

	return ret;
}

//Helper function of creating cursor headers
//Returns cursor count
uint16_t pe_resource_viewer::format_cursor_headers(std::string& cur_data, const std::string& resource_data, uint32_t language, uint32_t index) const
{
	//Check resource data length
	if(resource_data.length() < sizeof(cursor_header))
		throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

	const cursor_header* info = reinterpret_cast<const cursor_header*>(resource_data.data());

	//Check resource data length
	if(resource_data.length() < sizeof(cursor_header) + sizeof(cursor_group) * info->Count)
		throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

	//Reserve needed space to speed up a little
	cur_data.reserve(sizeof(cursor_header) + info->Count * sizeof(cursordirentry));
	//Add icon header
	cur_data.append(reinterpret_cast<const char*>(info), sizeof(cursor_header));

	//Iterate over all cursors listed in cursor group
	uint32_t offset = sizeof(cursor_header) + sizeof(cursordirentry) * info->Count;
	for(uint16_t i = 0; i != info->Count; ++i)
	{
		const cursor_group* group = reinterpret_cast<const cursor_group*>(resource_data.data() + sizeof(cursor_header) + i * sizeof(cursor_group));

		//Fill cursor info
		cursordirentry direntry;
		direntry.ColorCount = 0; //OK
		direntry.Width = static_cast<uint8_t>(group->Width);
		direntry.Height = static_cast<uint8_t>(group->Height)  / 2;
		direntry.Reserved = 0;

		//Now read hotspot data from cursor data directory
		const std::string cursor = index == 0xFFFFFFFF
			? get_resource_data_by_id(language, resource_cursor, group->Number).get_data()
			: get_resource_data_by_id(resource_cursor, group->Number, index).get_data();
		if(cursor.length() < 2 * sizeof(uint16_t))
			throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

		//Here it is - two words in the very beginning of cursor data
		direntry.HotspotX = *reinterpret_cast<const uint16_t*>(cursor.data());
		direntry.HotspotY = *reinterpret_cast<const uint16_t*>(cursor.data() + sizeof(uint16_t));

		//Fill the rest data
		direntry.SizeInBytes = group->SizeInBytes - 2 * sizeof(uint16_t);
		direntry.ImageOffset = offset;

		//Add cursor header
		cur_data.append(reinterpret_cast<const char*>(&direntry), sizeof(cursordirentry));

		offset += group->SizeInBytes;
	}

	//Return cursor count
	return info->Count;
}

//Returns cursor data by name and language (minimum checks of format correctness)
const std::string pe_resource_viewer::get_cursor_by_name(uint32_t language, const std::wstring& name) const
{
	std::string ret;

	//Get resource by name and language
	const std::string resource_data = get_resource_data_by_name(language, resource_cursor_group, name).get_data();

	//Create cursor headers
	uint16_t cursor_count = format_cursor_headers(ret, resource_data, language);

	//Add cursor data
	for(uint16_t i = 0; i != cursor_count; ++i)
	{
		const cursor_group* group = reinterpret_cast<const cursor_group*>(resource_data.data() + sizeof(cursor_header) + i * sizeof(cursor_group));
		ret += get_resource_data_by_id(resource_cursor, group->Number, language).get_data().substr(2 * sizeof(uint16_t));
	}

	return ret;
}

//Returns cursor data by name and index in language directory (instead of language) (minimum checks of format correctness)
const std::string pe_resource_viewer::get_cursor_by_name(const std::wstring& name, uint32_t index) const
{
	std::string ret;

	//Get resource by name and index
	const std::string resource_data = get_resource_data_by_name(resource_cursor_group, name, index).get_data();

	//Create cursor headers
	uint16_t cursor_count = format_cursor_headers(ret, resource_data, 0, index);

	//Add cursor data
	for(uint16_t i = 0; i != cursor_count; ++i)
	{
		const cursor_group* group = reinterpret_cast<const cursor_group*>(resource_data.data() + sizeof(cursor_header) + i * sizeof(cursor_group));
		ret += get_resource_data_by_id(resource_cursor, group->Number, index).get_data().substr(2 * sizeof(uint16_t));
	}

	return ret;
}

//Returns cursor data by ID and language (minimum checks of format correctness)
const std::string pe_resource_viewer::get_cursor_by_id_lang(uint32_t language, uint32_t id) const
{
	std::string ret;

	//Get resource by ID and language
	const std::string resource_data = get_resource_data_by_id(language, resource_cursor_group, id).get_data();

	//Create cursor headers
	uint16_t cursor_count = format_cursor_headers(ret, resource_data, language);

	//Add cursor data
	for(uint16_t i = 0; i != cursor_count; ++i)
	{
		const cursor_group* group = reinterpret_cast<const cursor_group*>(resource_data.data() + sizeof(cursor_header) + i * sizeof(cursor_group));
		ret += get_resource_data_by_id(resource_cursor, group->Number, language).get_data().substr(2 * sizeof(uint16_t));
	}

	return ret;
}

//Returns cursor data by ID and index in language directory (instead of language) (minimum checks of format correctness)
const std::string pe_resource_viewer::get_cursor_by_id(uint32_t id, uint32_t index) const
{
	std::string ret;

	//Get resource by ID and index
	const std::string resource_data = get_resource_data_by_id(resource_cursor_group, id, index).get_data();

	//Create cursor headers
	uint16_t cursor_count = format_cursor_headers(ret, resource_data, 0, index);

	//Add cursor data
	for(uint16_t i = 0; i != cursor_count; ++i)
	{
		const cursor_group* group = reinterpret_cast<const cursor_group*>(resource_data.data() + sizeof(cursor_header) + i * sizeof(cursor_group));
		ret += get_resource_data_by_id(resource_cursor, group->Number, index).get_data().substr(2 * sizeof(uint16_t));
	}

	return ret;
}

//Returns string table data by ID and index in language directory (instead of language)
const pe_resource_viewer::string_list pe_resource_viewer::get_string_table_by_id(uint32_t id, uint32_t index) const
{
	return parse_string_list(id, get_resource_data_by_id(resource_string, id, index).get_data());
}

//Returns string table data by ID and language
const pe_resource_viewer::string_list pe_resource_viewer::get_string_table_by_id_lang(uint32_t language, uint32_t id) const
{
	return parse_string_list(id, get_resource_data_by_id(language, resource_string, id).get_data());
}

//Helper function of parsing string list table
const pe_resource_viewer::string_list pe_resource_viewer::parse_string_list(uint32_t id, const std::string& resource_data) const
{
	string_list ret;

	//16 is maximum count of strings in a string table
	static const unsigned long max_string_list_entries = 16;
	unsigned long passed_bytes = 0;
	for(unsigned long i = 0; i != max_string_list_entries; ++i)
	{
		//Check resource data length
		if(resource_data.length() < sizeof(uint16_t) + passed_bytes)
			throw pe_exception("Incorrect resource string table", pe_exception::resource_incorrect_string_table);

		//Get string length - the first WORD
		uint16_t string_length = *reinterpret_cast<const uint16_t*>(resource_data.data() + passed_bytes);
		passed_bytes += sizeof(uint16_t); //WORD containing string length

		//Check resource data length again
		if(resource_data.length() < string_length + passed_bytes)
			throw pe_exception("Incorrect resource string table", pe_exception::resource_incorrect_string_table);

		if(string_length)
		{
			//Create and save string (UNICODE)
#ifdef PE_BLISS_WINDOWS
			ret.insert(
				std::make_pair(static_cast<uint16_t>(((id - 1) << 4) + i), //ID of string is calculated in such way
				std::wstring(reinterpret_cast<const wchar_t*>(resource_data.data() + passed_bytes), string_length)));
#else
			ret.insert(
				std::make_pair(static_cast<uint16_t>(((id - 1) << 4) + i), //ID of string is calculated in such way
				pe_base::from_ucs2(u16string(reinterpret_cast<const unicode16_t*>(resource_data.data() + passed_bytes), string_length))));
#endif
		}

		//Go to next string
		passed_bytes += string_length * 2;
	}

	return ret;
}

//Returns string from string table by ID and language
const std::wstring pe_resource_viewer::get_string_by_id_lang(uint32_t language, uint16_t id) const
{
	//List strings by string table id and language
	const string_list strings(get_string_table_by_id(language, (id >> 4) + 1));
	string_list::const_iterator it = strings.find(id); //Find string by id
	if(it == strings.end())
		throw pe_exception("Resource string not found", pe_exception::resource_string_not_found);

	return (*it).second;
}

//Returns string from string table by ID and index in language directory (instead of language)
const std::wstring pe_resource_viewer::get_string_by_id(uint16_t id, uint32_t index) const
{
	//List strings by string table id and index
	const string_list strings(get_string_table_by_id((id >> 4) + 1, index));
	string_list::const_iterator it = strings.find(id); //Find string by id
	if(it == strings.end())
		throw pe_exception("Resource string not found", pe_exception::resource_string_not_found);

	return (*it).second;
}

//Default constructor
pe_resource_viewer::message_table_item::message_table_item()
	:unicode_(false)
{}

//Constructor from ANSI string
pe_resource_viewer::message_table_item::message_table_item(const std::string& str)
	:unicode_(false), ansi_str_(str)
{
	pe_base::strip_nullbytes(ansi_str_);
}

//Constructor from UNICODE string
pe_resource_viewer::message_table_item::message_table_item(const std::wstring& str)
	:unicode_(true), unicode_str_(str)
{
	pe_base::strip_nullbytes(unicode_str_);
}

//Returns true if contained string is unicode
bool pe_resource_viewer::message_table_item::is_unicode() const
{
	return unicode_;
}

//Returns ANSI string
const std::string& pe_resource_viewer::message_table_item::get_ansi_string() const
{
	return ansi_str_;
}

//Returns UNICODE string
const std::wstring& pe_resource_viewer::message_table_item::get_unicode_string() const
{
	return unicode_str_;
}

//Sets ANSI string (clears UNICODE one)
void pe_resource_viewer::message_table_item::set_string(const std::string& str)
{
	ansi_str_ = str;
	pe_base::strip_nullbytes(ansi_str_);
	unicode_str_.clear();
	unicode_ = false;
}

//Sets UNICODE string (clears ANSI one)
void pe_resource_viewer::message_table_item::set_string(const std::wstring& str)
{
	unicode_str_ = str;
	pe_base::strip_nullbytes(unicode_str_);
	ansi_str_.clear();
	unicode_ = true;
}

//Helper function of parsing message list table
const pe_resource_viewer::message_list pe_resource_viewer::parse_message_list(const std::string& resource_data) const
{
	message_list ret;

	//Check resource data length
	if(resource_data.length() < sizeof(message_resource_data))
		throw pe_exception("Incorrect resource message table", pe_exception::resource_incorrect_message_table);

	const message_resource_data* message_data = reinterpret_cast<const message_resource_data*>(resource_data.data());

	//Check resource data length more carefully and some possible overflows
	if(message_data->NumberOfBlocks >= pe_base::max_dword / sizeof(message_resource_block)
		|| !pe_base::is_sum_safe(message_data->NumberOfBlocks * sizeof(message_resource_block), sizeof(message_resource_data))
		|| resource_data.length() < message_data->NumberOfBlocks * sizeof(message_resource_block) + sizeof(message_resource_data))
		throw pe_exception("Incorrect resource message table", pe_exception::resource_incorrect_message_table);

	//Iterate over all message resource blocks
	for(unsigned long i = 0; i != message_data->NumberOfBlocks; ++i)
	{
		//Get block
		const message_resource_block* block =
			reinterpret_cast<const message_resource_block*>(resource_data.data() + sizeof(message_resource_data) - sizeof(message_resource_block) + sizeof(message_resource_block) * i);

		//Check resource data length and IDs
		if(resource_data.length() < block->OffsetToEntries || block->LowId > block->HighId)
			throw pe_exception("Incorrect resource message table", pe_exception::resource_incorrect_message_table);

		unsigned long current_pos = 0;
		static const unsigned long size_of_entry_headers = 4;
		//List all message resource entries in block
		for(uint32_t curr_id = block->LowId; curr_id <= block->HighId; curr_id++)
		{
			//Check resource data length and some possible overflows
			if(!pe_base::is_sum_safe(block->OffsetToEntries, current_pos)
				|| !pe_base::is_sum_safe(block->OffsetToEntries + current_pos, size_of_entry_headers)
				|| resource_data.length() < block->OffsetToEntries + current_pos + size_of_entry_headers)
				throw pe_exception("Incorrect resource message table", pe_exception::resource_incorrect_message_table);

			//Get entry
			const message_resource_entry* entry = reinterpret_cast<const message_resource_entry*>(resource_data.data() + block->OffsetToEntries + current_pos);

			//Check resource data length and entry length and some possible overflows
			if(entry->Length < size_of_entry_headers
				|| !pe_base::is_sum_safe(block->OffsetToEntries + current_pos, entry->Length)
				|| resource_data.length() < block->OffsetToEntries + current_pos + entry->Length
				|| entry->Length < size_of_entry_headers)
				throw pe_exception("Incorrect resource message table", pe_exception::resource_incorrect_message_table);

			if(entry->Flags & message_resource_unicode)
			{
				//If string is UNICODE
				//Check its length
				if(entry->Length % 2)
					throw pe_exception("Incorrect resource message table", pe_exception::resource_incorrect_message_table);

				//Add ID and string to message table
#ifdef PE_BLISS_WINDOWS
				ret.insert(std::make_pair(curr_id, message_table_item(
					std::wstring(reinterpret_cast<const wchar_t*>(resource_data.data() + block->OffsetToEntries + current_pos + size_of_entry_headers),
					(entry->Length - size_of_entry_headers) / 2)
					)));
#else
				ret.insert(std::make_pair(curr_id, message_table_item(
					pe_base::from_ucs2(u16string(reinterpret_cast<const unicode16_t*>(resource_data.data() + block->OffsetToEntries + current_pos + size_of_entry_headers),
					(entry->Length - size_of_entry_headers) / 2))
					)));
#endif
			}
			else
			{
				//If string is ANSI
				//Add ID and string to message table
				ret.insert(std::make_pair(curr_id, message_table_item(
					std::string(resource_data.data() + block->OffsetToEntries + current_pos + size_of_entry_headers,
					entry->Length - size_of_entry_headers)
					)));
			}

			//Go to next entry
			current_pos += entry->Length;
		}
	}

	return ret;
}

//Returns message table data by ID and index in language directory (instead of language)
const pe_resource_viewer::message_list pe_resource_viewer::get_message_table_by_id(uint32_t id, uint32_t index) const
{
	return parse_message_list(get_resource_data_by_id(resource_message_table, id, index).get_data());
}

//Returns message table data by ID and language
const pe_resource_viewer::message_list pe_resource_viewer::get_message_table_by_id_lang(uint32_t language, uint32_t id) const
{
	return parse_message_list(get_resource_data_by_id(language, resource_message_table, id).get_data());
}

//Returns aligned version block value position
uint32_t pe_resource_viewer::get_version_block_value_pos(uint32_t base_pos, const unicode16_t* key)
{
	uint32_t string_length = static_cast<uint32_t>(u16string(key).length());
	uint32_t ret = pe_base::align_up(static_cast<uint32_t>(sizeof(uint16_t) * 3 /* headers before Key data */
		+ base_pos
		+ (string_length + 1 /* nullbyte */) * 2),
		sizeof(uint32_t));

	//Check possible overflows
	if(ret < base_pos || ret < sizeof(uint16_t) * 3 || ret < (string_length + 1) * 2)
		throw_incorrect_version_info();

	return ret;
}

//Returns aligned version block first child position
uint32_t pe_resource_viewer::get_version_block_first_child_pos(uint32_t base_pos, uint32_t value_length, const unicode16_t* key)
{
	uint32_t string_length = static_cast<uint32_t>(u16string(key).length());
	uint32_t ret =  pe_base::align_up(static_cast<uint32_t>(sizeof(uint16_t) * 3 /* headers before Key data */
		+ base_pos
		+ (string_length + 1 /* nullbyte */) * 2),
		sizeof(uint32_t))
		+ pe_base::align_up(value_length, sizeof(uint32_t));

	//Check possible overflows
	if(ret < base_pos || ret < value_length || ret < sizeof(uint16_t) * 3 || ret < (string_length + 1) * 2)
		throw_incorrect_version_info();

	return ret;
}

//Throws an exception (id = resource_incorrect_version_info)
void pe_resource_viewer::throw_incorrect_version_info()
{
	throw pe_exception("Incorrect resource version info", pe_exception::resource_incorrect_version_info);
}

//Returns full version information:
//file_version_info: versions and file info
//lang_string_values_map: map of version info strings with encodings
//translation_values_map: map of translations
const pe_resource_viewer::file_version_info pe_resource_viewer::get_version_info(lang_string_values_map& string_values, translation_values_map& translations, const std::string& resource_data) const
{
	//Fixed file version info
	file_version_info ret;

	//Check resource data length
	if(resource_data.length() < sizeof(version_info_block))
		throw_incorrect_version_info();

	//Root version info block
	const version_info_block* root_block = reinterpret_cast<const version_info_block*>(resource_data.data());

	//Check root block key for null-termination and its name
	if(!pe_base::is_null_terminated(root_block->Key, resource_data.length() - sizeof(uint16_t) * 3 /* headers before Key data */)
		|| version_info_key != reinterpret_cast<const unicode16_t*>(root_block->Key))
		throw_incorrect_version_info();

	//If file has fixed version info
	if(root_block->ValueLength)
	{
		//Get root block value position
		uint32_t value_pos = get_version_block_value_pos(0, reinterpret_cast<const unicode16_t*>(root_block->Key));
		//Check value length
		if(resource_data.length() < value_pos + sizeof(vs_fixedfileinfo))
			throw_incorrect_version_info();

		//Get VS_FIXEDFILEINFO structure pointer
		const vs_fixedfileinfo* file_info = reinterpret_cast<const vs_fixedfileinfo*>(resource_data.data() + value_pos);
		//Check its signature and some other fields
		if(file_info->dwSignature != vs_ffi_signature || file_info->dwStrucVersion != vs_ffi_strucversion) //Don't check if file_info->dwFileFlagsMask == VS_FFI_FILEFLAGSMASK
			throw_incorrect_version_info();

		//Save fixed version info
		ret = file_version_info(*file_info);
	}

	//Iterate over child elements of VS_VERSIONINFO (StringFileInfo or VarFileInfo)
	for(uint32_t child_pos = get_version_block_first_child_pos(0, root_block->ValueLength, reinterpret_cast<const unicode16_t*>(root_block->Key));
		child_pos < root_block->Length;)
	{
		//Check block position
		if(!pe_base::is_sum_safe(child_pos, sizeof(version_info_block))
			|| resource_data.length() < child_pos + sizeof(version_info_block))
			throw_incorrect_version_info();

		//Get VERSION_INFO_BLOCK structure pointer
		const version_info_block* block = reinterpret_cast<const version_info_block*>(resource_data.data() + child_pos);

		//Check its length
		if(block->Length == 0)
			throw_incorrect_version_info();

		//Check block key for null-termination
		if(!pe_base::is_null_terminated(block->Key, resource_data.length() - child_pos - sizeof(uint16_t) * 3 /* headers before Key data */))
			throw_incorrect_version_info();

		u16string info_type(reinterpret_cast<const unicode16_t*>(block->Key));
		//If we encountered StringFileInfo...
		if(info_type == StringFileInfo)
		{
			//Enumerate all string tables
			for(uint32_t string_table_pos = get_version_block_first_child_pos(child_pos, block->ValueLength, reinterpret_cast<const unicode16_t*>(block->Key));
				string_table_pos - child_pos < block->Length;)
			{
				//Check string table block position
				if(resource_data.length() < string_table_pos + sizeof(version_info_block))
					throw_incorrect_version_info();

				//Get VERSION_INFO_BLOCK structure pointer for string table
				const version_info_block* string_table = reinterpret_cast<const version_info_block*>(resource_data.data() + string_table_pos);

				//Check its length
				if(string_table->Length == 0)
					throw_incorrect_version_info();

				//Check string table key for null-termination
				if(!pe_base::is_null_terminated(string_table->Key, resource_data.length() - string_table_pos - sizeof(uint16_t) * 3 /* headers before Key data */))	
					throw_incorrect_version_info();

				string_values_map new_values;

				//Enumerate all strings in the string table
				for(uint32_t string_pos = get_version_block_first_child_pos(string_table_pos, string_table->ValueLength, reinterpret_cast<const unicode16_t*>(string_table->Key));
					string_pos - string_table_pos < string_table->Length;)
				{
					//Check string block position
					if(resource_data.length() < string_pos + sizeof(version_info_block))
						throw_incorrect_version_info();

					//Get VERSION_INFO_BLOCK structure pointer for string block
					const version_info_block* string_block = reinterpret_cast<const version_info_block*>(resource_data.data() + string_pos);

					//Check its length
					if(string_block->Length == 0)
						throw_incorrect_version_info();

					//Check string block key for null-termination
					if(!pe_base::is_null_terminated(string_block->Key, resource_data.length() - string_pos - sizeof(uint16_t) * 3 /* headers before Key data */))
						throw_incorrect_version_info();

					u16string data;
					//If string block has value
					if(string_block->ValueLength != 0)
					{
						//Get value position
						uint32_t value_pos = get_version_block_value_pos(string_pos, reinterpret_cast<const unicode16_t*>(string_block->Key));
						//Check it
						if(resource_data.length() < value_pos + string_block->ValueLength)
							throw pe_exception("Incorrect resource version info", pe_exception::resource_incorrect_version_info);

						//Get UNICODE string value
						data = u16string(reinterpret_cast<const unicode16_t*>(resource_data.data() + value_pos), string_block->ValueLength);
						pe_base::strip_nullbytes(data);
					}

					//Save name-value pair
#ifdef PE_BLISS_WINDOWS
					new_values.insert(std::make_pair(reinterpret_cast<const unicode16_t*>(string_block->Key), data));
#else
					new_values.insert(std::make_pair(pe_base::from_ucs2(reinterpret_cast<const unicode16_t*>(string_block->Key)),
						pe_base::from_ucs2(data)));
#endif

					//Navigate to next string block
					string_pos += pe_base::align_up(string_block->Length, sizeof(uint32_t));
				}

#ifdef PE_BLISS_WINDOWS
				string_values.insert(std::make_pair(reinterpret_cast<const unicode16_t*>(string_table->Key), new_values));
#else
				string_values.insert(std::make_pair(pe_base::from_ucs2(reinterpret_cast<const unicode16_t*>(string_table->Key)), new_values));
#endif

				//Navigate to next string table block
				string_table_pos += pe_base::align_up(string_table->Length, sizeof(uint32_t));
			}
		}
		else if(info_type == VarFileInfo) //If we encountered VarFileInfo
		{
			for(uint32_t var_table_pos = get_version_block_first_child_pos(child_pos, block->ValueLength, reinterpret_cast<const unicode16_t*>(block->Key));
				var_table_pos - child_pos < block->Length;)
			{
				//Check var block position
				if(resource_data.length() < var_table_pos + sizeof(version_info_block))
					throw_incorrect_version_info();

				//Get VERSION_INFO_BLOCK structure pointer for var block
				const version_info_block* var_table = reinterpret_cast<const version_info_block*>(resource_data.data() + var_table_pos);

				//Check its length
				if(var_table->Length == 0)
					throw_incorrect_version_info();

				//Check its key for null-termination
				if(!pe_base::is_null_terminated(var_table->Key, resource_data.length() - var_table_pos - sizeof(uint16_t) * 3 /* headers before Key data */))
					throw_incorrect_version_info();

				//If block is "Translation" (actually, there's no other types possible in VarFileInfo) and it has value
				if(u16string(reinterpret_cast<const unicode16_t*>(var_table->Key)) == Translation && var_table->ValueLength)
				{
					//Get its value position
					uint32_t value_pos = get_version_block_value_pos(var_table_pos, reinterpret_cast<const unicode16_t*>(var_table->Key));
					//Cherck value length
					if(resource_data.length() < value_pos + var_table->ValueLength)
						throw_incorrect_version_info();

					//Get list of translations: pairs of LANGUAGE_ID - CODEPAGE_ID
					for(unsigned long i = 0; i < var_table->ValueLength; i += sizeof(uint16_t) * 2)
					{
						//Pair of WORDs
						uint16_t lang_id = *reinterpret_cast<const uint16_t*>(resource_data.data() + value_pos + i);
						uint16_t codepage_id = *reinterpret_cast<const uint16_t*>(resource_data.data() + value_pos + sizeof(uint16_t) + i);
						//Save translation
						translations.insert(std::make_pair(lang_id, codepage_id));
					}
				}

				//Navigate to next var block
				var_table_pos += pe_base::align_up(var_table->Length, sizeof(uint32_t));
			}
		}
		else
		{
			throw_incorrect_version_info();
		}

		//Navigate to next element in root block
		child_pos += pe_base::align_up(block->Length, sizeof(uint32_t));
	}

	return ret;
}

//Returns full version information:
//file_version info: versions and file info
//lang_string_values_map: map of version info strings with encodings
//translation_values_map: map of translations
const pe_resource_viewer::file_version_info pe_resource_viewer::get_version_info_by_lang(lang_string_values_map& string_values, translation_values_map& translations, uint32_t language) const
{
	const std::string& resource_data = root_dir_ //Type directory
		.entry_by_id(resource_version)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(1)
		.get_resource_directory() //Language directory
		.entry_by_id(language)
		.get_data_entry() //Data directory
		.get_data();

	return get_version_info(string_values, translations, resource_data);
}

//Returns full version information:
//file_version_info: versions and file info
//lang_string_values_map: map of version info strings with encodings
//translation_values_map: map of translations
const pe_resource_viewer::file_version_info pe_resource_viewer::get_version_info(lang_string_values_map& string_values, translation_values_map& translations, uint32_t index) const
{
	const pe_base::resource_directory::entry_list& entries = root_dir_ //Type directory
		.entry_by_id(resource_version)
		.get_resource_directory() //Name/ID directory
		.entry_by_id(1)
		.get_resource_directory() //Language directory
		.get_entry_list();

	if(entries.size() <= index)
		throw pe_exception("Resource data entry not found", pe_exception::resource_data_entry_not_found);

	return get_version_info(string_values, translations, entries.at(index).get_data_entry().get_data()); //Data directory
}

//Default constructor
pe_resource_viewer::file_version_info::file_version_info()
	:file_version_ms_(0), file_version_ls_(0),
	product_version_ms_(0), product_version_ls_(0),
	file_flags_(0),
	file_os_(0),
	file_type_(0), file_subtype_(0),
	file_date_ms_(0), file_date_ls_(0)
{}

//Constructor from Windows fixed version info structure
pe_resource_viewer::file_version_info::file_version_info(const vs_fixedfileinfo& info)
	:file_version_ms_(info.dwFileVersionMS), file_version_ls_(info.dwFileVersionLS),
	product_version_ms_(info.dwProductVersionMS), product_version_ls_(info.dwProductVersionLS),
	file_flags_(info.dwFileFlags),
	file_os_(info.dwFileOS),
	file_type_(info.dwFileType), file_subtype_(info.dwFileSubtype),
	file_date_ms_(info.dwFileDateMS), file_date_ls_(info.dwFileDateLS)
{}

//Returns true if file is debug-built
bool pe_resource_viewer::file_version_info::is_debug() const
{
	return file_flags_ & vs_ff_debug ? true : false;
}

//Returns true if file is release-built
bool pe_resource_viewer::file_version_info::is_prerelease() const
{
	return file_flags_ & vs_ff_prerelease ? true : false;
}

//Returns true if file is patched
bool pe_resource_viewer::file_version_info::is_patched() const
{
	return file_flags_ & vs_ff_patched ? true : false;
}

//Returns true if private build
bool pe_resource_viewer::file_version_info::is_private_build() const
{
	return file_flags_ & vs_ff_privatebuild ? true : false;
}

//Returns true if special build
bool pe_resource_viewer::file_version_info::is_special_build() const
{
	return file_flags_ & vs_ff_specialbuild ? true : false;
}

//Returns true if info inferred
bool pe_resource_viewer::file_version_info::is_info_inferred() const
{
	return file_flags_ & vs_ff_infoinferred ? true : false;
}

//Retuens file flags (raw DWORD)
uint32_t pe_resource_viewer::file_version_info::get_file_flags() const
{
	return file_flags_;
}

//Returns file version most significant DWORD
uint32_t pe_resource_viewer::file_version_info::get_file_version_ms() const
{
	return file_version_ms_;
}

//Returns file version least significant DWORD
uint32_t pe_resource_viewer::file_version_info::get_file_version_ls() const
{
	return file_version_ls_;
}

//Returns product version most significant DWORD
uint32_t pe_resource_viewer::file_version_info::get_product_version_ms() const
{
	return product_version_ms_;
}

//Returns product version least significant DWORD
uint32_t pe_resource_viewer::file_version_info::get_product_version_ls() const
{
	return product_version_ls_;
}

//Returns file OS type (raw DWORD)
uint32_t pe_resource_viewer::file_version_info::get_file_os_raw() const
{
	return file_os_;
}

//Returns file OS type
pe_resource_viewer::file_version_info::file_os_type pe_resource_viewer::file_version_info::get_file_os() const
{
	//Determine file operation system type
	switch(file_os_)
	{
	case vos_dos:
		return file_os_dos;

	case vos_os216:
		return file_os_os216;

	case vos_os232:
		return file_os_os232;

	case vos_nt:
		return file_os_nt;

	case vos_wince:
		return file_os_wince;

	case vos__windows16:
		return file_os_win16;

	case vos__pm16:
		return file_os_pm16;

	case vos__pm32:
		return file_os_pm32;

	case vos__windows32:
		return file_os_win32;

	case vos_dos_windows16:
		return file_os_dos_win16;

	case vos_dos_windows32:
		return file_os_dos_win32;

	case vos_os216_pm16:
		return file_os_os216_pm16;

	case vos_os232_pm32:
		return file_os_os232_pm32;

	case vos_nt_windows32:
		return file_os_nt_win32;
	}

	return file_os_unknown;
}

//Returns file type (raw DWORD)
uint32_t pe_resource_viewer::file_version_info::get_file_type_raw() const
{
	return file_type_;
}

//Returns file type
pe_resource_viewer::file_version_info::file_type pe_resource_viewer::file_version_info::get_file_type() const
{
	//Determine file type
	switch(file_type_)
	{
	case vft_app:
		return file_type_application;

	case vft_dll:
		return file_type_dll;

	case vft_drv:
		return file_type_driver;

	case vft_font:
		return file_type_font;

	case vft_vxd:
		return file_type_vxd;

	case vft_static_lib:
		return file_type_static_lib;
	}

	return file_type_unknown;
}

//Returns file subtype (usually non-zero for drivers and fonts)
uint32_t pe_resource_viewer::file_version_info::get_file_subtype() const
{
	return file_subtype_;
}

//Returns file date most significant DWORD
uint32_t pe_resource_viewer::file_version_info::get_file_date_ms() const
{
	return file_date_ms_;
}

//Returns file date least significant DWORD
uint32_t pe_resource_viewer::file_version_info::get_file_date_ls() const
{
	return file_date_ls_;
}

//Helper to set file flag
void pe_resource_viewer::file_version_info::set_file_flag(uint32_t flag)
{
	file_flags_ |= flag;
}

//Helper to clear file flag
void pe_resource_viewer::file_version_info::clear_file_flag(uint32_t flag)
{
	file_flags_ &= ~flag;
}

//Helper to set or clear file flag
void pe_resource_viewer::file_version_info::set_file_flag(uint32_t flag, bool set_flag)
{
	set_flag ? set_file_flag(flag) : clear_file_flag(flag);
}

//Sets if file is debug-built
void pe_resource_viewer::file_version_info::set_debug(bool debug)
{
	set_file_flag(vs_ff_debug, debug);
}

//Sets if file is prerelease
void pe_resource_viewer::file_version_info::set_prerelease(bool prerelease)
{
	set_file_flag(vs_ff_prerelease, prerelease);
}

//Sets if file is patched
void pe_resource_viewer::file_version_info::set_patched(bool patched)
{
	set_file_flag(vs_ff_patched, patched);
}

//Sets if private build
void pe_resource_viewer::file_version_info::set_private_build(bool private_build)
{
	set_file_flag(vs_ff_privatebuild, private_build);
}

//Sets if special build
void pe_resource_viewer::file_version_info::set_special_build(bool special_build)
{
	set_file_flag(vs_ff_specialbuild, special_build);
}

//Sets if info inferred
void pe_resource_viewer::file_version_info::set_info_inferred(bool info_inferred)
{
	set_file_flag(vs_ff_infoinferred, info_inferred);
}

//Sets flags (raw DWORD)
void pe_resource_viewer::file_version_info::set_file_flags(uint32_t file_flags)
{
	file_flags_ = file_flags;
}

//Sets file version most significant DWORD
void pe_resource_viewer::file_version_info::set_file_version_ms(uint32_t file_version_ms)
{
	file_version_ms_ = file_version_ms;
}

//Sets file version least significant DWORD
void pe_resource_viewer::file_version_info::set_file_version_ls(uint32_t file_version_ls)
{
	file_version_ls_ = file_version_ls;
}

//Sets product version most significant DWORD
void pe_resource_viewer::file_version_info::set_product_version_ms(uint32_t product_version_ms)
{
	product_version_ms_ = product_version_ms;
}

//Sets product version least significant DWORD
void pe_resource_viewer::file_version_info::set_product_version_ls(uint32_t product_version_ls)
{
	product_version_ls_ = product_version_ls;
}

//Sets file OS type (raw DWORD)
void pe_resource_viewer::file_version_info::set_file_os_raw(uint32_t file_os)
{
	file_os_ = file_os;
}

//Sets file OS type
void pe_resource_viewer::file_version_info::set_file_os(file_os_type file_os)
{
	//Determine file operation system type
	switch(file_os)
	{
	case file_os_dos:
		file_os_ = vos_dos;
		return;

	case file_os_os216:
		file_os_ = vos_os216;
		return;

	case file_os_os232:
		file_os_ = vos_os232;
		return;

	case file_os_nt:
		file_os_ = vos_nt;
		return;

	case file_os_wince:
		file_os_ = vos_wince;
		return;

	case file_os_win16:
		file_os_ = vos__windows16;
		return;
		
	case file_os_pm16:
		file_os_ = vos__pm16;
		return;

	case file_os_pm32:
		file_os_ = vos__pm32;
		return;

	case file_os_win32:
		file_os_ = vos__windows32;
		return;

	case file_os_dos_win16:
		file_os_ = vos_dos_windows16;
		return;

	case file_os_dos_win32:
		file_os_ = vos_dos_windows32;
		return;

	case file_os_os216_pm16:
		file_os_ = vos_os216_pm16;
		return;

	case file_os_os232_pm32:
		file_os_ = vos_os232_pm32;
		return;

	case file_os_nt_win32:
		file_os_ = vos_nt_windows32;
		return;

	default:
		return;
	}
}

//Sets file type (raw DWORD)
void pe_resource_viewer::file_version_info::set_file_type_raw(uint32_t file_type)
{
	file_type_ = file_type;
}

//Sets file type
void pe_resource_viewer::file_version_info::set_file_type(file_type file_type)
{
	//Determine file type
	switch(file_type)
	{
	case file_type_application:
		file_type_ = vft_app;
		return;
		
	case file_type_dll:
		file_type_ = vft_dll;
		return;

	case file_type_driver:
		file_type_ = vft_drv;
		return;

	case file_type_font:
		file_type_ = vft_font;
		return;

	case file_type_vxd:
		file_type_ = vft_vxd;
		return;

	case file_type_static_lib:
		file_type_ = vft_static_lib;
		return;

	default:
		return;
	}
}

//Sets file subtype (usually non-zero for drivers and fonts)
void pe_resource_viewer::file_version_info::set_file_subtype(uint32_t file_subtype)
{
	file_subtype_ = file_subtype;
}

//Sets file date most significant DWORD
void pe_resource_viewer::file_version_info::set_file_date_ms(uint32_t file_date_ms)
{
	file_date_ms_ = file_date_ms;
}

//Sets file date least significant DWORD
void pe_resource_viewer::file_version_info::set_file_date_ls(uint32_t file_date_ls)
{
	file_date_ls_ = file_date_ls;
}

//Constructor from root resource directory
pe_resource_manager::pe_resource_manager(pe_base::resource_directory& root_directory)
	:pe_resource_viewer(root_directory), root_dir_edit_(root_directory)
{}

//Removes all resources of given type or root name
//If there's more than one directory entry of a given type, only the
//first one will be deleted (that's an unusual situation)
//Returns true if resource was deleted
bool pe_resource_manager::remove_resource_type(resource_type type)
{
	//Search for resource type
	pe_base::resource_directory::entry_list& entries = root_dir_edit_.get_entry_list();
	pe_base::resource_directory::entry_list::iterator it = std::find_if(entries.begin(), entries.end(), pe_base::resource_directory::id_entry_finder(type));
	if(it != entries.end())
	{
		//Remove it, if found
		entries.erase(it);
		return true;
	}

	return false;
}

bool pe_resource_manager::remove_resource(const std::wstring& root_name)
{
	//Search for resource type
	pe_base::resource_directory::entry_list& entries = root_dir_edit_.get_entry_list();
	pe_base::resource_directory::entry_list::iterator it = std::find_if(entries.begin(), entries.end(), pe_base::resource_directory::name_entry_finder(root_name));
	if(it != entries.end())
	{
		//Remove it, if found
		entries.erase(it);
		return true;
	}

	return false;
}

//Helper to remove resource
bool pe_resource_manager::remove_resource(const pe_base::resource_directory::entry_finder& root_finder, const pe_base::resource_directory::entry_finder& finder)
{
	//Search for resource type
	pe_base::resource_directory::entry_list& entries_type = root_dir_edit_.get_entry_list();
	pe_base::resource_directory::entry_list::iterator it_type = std::find_if(entries_type.begin(), entries_type.end(), root_finder);
	if(it_type != entries_type.end())
	{
		//Search for resource name/ID with "finder"
		pe_base::resource_directory::entry_list& entries_name = (*it_type).get_resource_directory().get_entry_list();
		pe_base::resource_directory::entry_list::iterator it_name = std::find_if(entries_name.begin(), entries_name.end(), finder);
		if(it_name != entries_name.end())
		{
			//Erase resource, if found
			entries_name.erase(it_name);
			if(entries_name.empty())
				entries_type.erase(it_type);

			return true;
		}
	}

	return false;
}

	//Removes all resource languages by resource type/root name and name
//Deletes only one entry of given type and name
//Returns true if resource was deleted
bool pe_resource_manager::remove_resource(resource_type type, const std::wstring& name)
{
	return remove_resource(pe_base::resource_directory::entry_finder(type), pe_base::resource_directory::entry_finder(name));
}

bool pe_resource_manager::remove_resource(const std::wstring& root_name, const std::wstring& name)
{
	return remove_resource(pe_base::resource_directory::entry_finder(root_name), pe_base::resource_directory::entry_finder(name));
}

//Removes all resource languages by resource type/root name and ID
//Deletes only one entry of given type and ID
//Returns true if resource was deleted
bool pe_resource_manager::remove_resource(resource_type type, uint32_t id)
{
	return remove_resource(pe_base::resource_directory::entry_finder(type), pe_base::resource_directory::entry_finder(id));
}

bool pe_resource_manager::remove_resource(const std::wstring& root_name, uint32_t id)
{
	return remove_resource(pe_base::resource_directory::entry_finder(root_name), pe_base::resource_directory::entry_finder(id));
}

//Helper to remove resource
bool pe_resource_manager::remove_resource(const pe_base::resource_directory::entry_finder& root_finder, const pe_base::resource_directory::entry_finder& finder, uint32_t language)
{
	//Search for resource type
	pe_base::resource_directory::entry_list& entries_type = root_dir_edit_.get_entry_list();
	pe_base::resource_directory::entry_list::iterator it_type = std::find_if(entries_type.begin(), entries_type.end(), root_finder);
	if(it_type != entries_type.end())
	{
		//Search for resource name/ID with "finder"
		pe_base::resource_directory::entry_list& entries_name = (*it_type).get_resource_directory().get_entry_list();
		pe_base::resource_directory::entry_list::iterator it_name = std::find_if(entries_name.begin(), entries_name.end(), finder);
		if(it_name != entries_name.end())
		{
			//Search for resource language
			pe_base::resource_directory::entry_list& entries_lang = (*it_name).get_resource_directory().get_entry_list();
			pe_base::resource_directory::entry_list::iterator it_lang = std::find_if(entries_lang.begin(), entries_lang.end(), pe_base::resource_directory::id_entry_finder(language));
			if(it_lang != entries_lang.end())
			{
				//Erase resource, if found
				entries_lang.erase(it_lang);
				if(entries_lang.empty())
				{
					entries_name.erase(it_name);
					if(entries_name.empty())
						entries_type.erase(it_type);
				}

				return true;
			}
		}
	}

	return false;
}

//Removes resource language by resource type/root name and name
//Deletes only one entry of given type, name and language
//Returns true if resource was deleted
bool pe_resource_manager::remove_resource(resource_type type, const std::wstring& name, uint32_t language)
{
	return remove_resource(pe_base::resource_directory::entry_finder(type), pe_base::resource_directory::entry_finder(name), language);
}

bool pe_resource_manager::remove_resource(const std::wstring& root_name, const std::wstring& name, uint32_t language)
{
	return remove_resource(pe_base::resource_directory::entry_finder(root_name), pe_base::resource_directory::entry_finder(name), language);
}

//Removes recource language by resource type/root name and ID
//Deletes only one entry of given type, ID and language
//Returns true if resource was deleted
bool pe_resource_manager::remove_resource(resource_type type, uint32_t id, uint32_t language)
{
	return remove_resource(pe_base::resource_directory::entry_finder(type), pe_base::resource_directory::entry_finder(id), language);
}

bool pe_resource_manager::remove_resource(const std::wstring& root_name, uint32_t id, uint32_t language)
{
	return remove_resource(pe_base::resource_directory::entry_finder(root_name), pe_base::resource_directory::entry_finder(id), language);
}

//Helper to add/replace resource
void pe_resource_manager::add_resource(const std::string& data, resource_type type, pe_base::resource_directory_entry& new_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_type_entry;
	new_type_entry.set_id(type);

	add_resource(data, new_type_entry, pe_base::resource_directory::entry_finder(type), new_entry, finder, language, codepage, timestamp);
}

//Helper to add/replace resource
void pe_resource_manager::add_resource(const std::string& data, const std::wstring& root_name, pe_base::resource_directory_entry& new_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_type_entry;
	new_type_entry.set_name(root_name);
	
	add_resource(data, new_type_entry, pe_base::resource_directory::entry_finder(root_name), new_entry, finder, language, codepage, timestamp);
}

//Helper to add/replace resource
void pe_resource_manager::add_resource(const std::string& data, pe_base::resource_directory_entry& new_root_entry, const pe_base::resource_directory::entry_finder& root_finder, pe_base::resource_directory_entry& new_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	//Search for resource type
	pe_base::resource_directory::entry_list* entries = &root_dir_edit_.get_entry_list();
	pe_base::resource_directory::entry_list::iterator it = std::find_if(entries->begin(), entries->end(), root_finder);
	if(it == entries->end())
	{
		//Add resource type directory, if it was not found
		pe_base::resource_directory dir;
		dir.set_timestamp(timestamp);
		new_root_entry.add_resource_directory(dir);
		entries->push_back(new_root_entry);
		it = entries->end() - 1;
	}

	//Search for resource name/ID directory with "finder"
	entries = &(*it).get_resource_directory().get_entry_list();
	it = std::find_if(entries->begin(), entries->end(), finder);
	if(it == entries->end())
	{
		//Add resource name/ID directory, if it was not found
		pe_base::resource_directory dir;
		dir.set_timestamp(timestamp);
		new_entry.add_resource_directory(dir);
		entries->push_back(new_entry);
		it = entries->end() - 1;
	}

	//Search for data resource entry by language
	entries = &(*it).get_resource_directory().get_entry_list();
	it = std::find_if(entries->begin(), entries->end(), pe_base::resource_directory::id_entry_finder(language));
	if(it != entries->end())
		entries->erase(it); //Erase it, if found

	//Add new data entry
	pe_base::resource_directory_entry new_dir_data_entry;
	pe_base::resource_data_entry data_dir(data, codepage);
	new_dir_data_entry.add_data_entry(data_dir);
	new_dir_data_entry.set_id(language);
	entries->push_back(new_dir_data_entry);
}

//Adds resource. If resource already exists, replaces it
void pe_resource_manager::add_resource(const std::string& data, resource_type type, const std::wstring& name, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_entry;
	new_entry.set_name(name);

	add_resource(data, type, new_entry, pe_base::resource_directory::entry_finder(name), language, codepage, timestamp);
}

//Adds resource. If resource already exists, replaces it
void pe_resource_manager::add_resource(const std::string& data, const std::wstring& root_name, const std::wstring& name, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_entry;
	new_entry.set_name(name);

	add_resource(data, root_name, new_entry, pe_base::resource_directory::entry_finder(name), language, codepage, timestamp);
}

//Adds resource. If resource already exists, replaces it
void pe_resource_manager::add_resource(const std::string& data, resource_type type, uint32_t id, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_entry;
	new_entry.set_id(id);

	add_resource(data, type, new_entry, pe_base::resource_directory::entry_finder(id), language, codepage, timestamp);
}

//Adds resource. If resource already exists, replaces it
void pe_resource_manager::add_resource(const std::string& data, const std::wstring& root_name, uint32_t id, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_entry;
	new_entry.set_id(id);

	add_resource(data, root_name, new_entry, pe_base::resource_directory::entry_finder(id), language, codepage, timestamp);
}

//Adds bitmap from bitmap file data. If bitmap already exists, replaces it
//timestamp will be used for directories that will be added
void pe_resource_manager::add_bitmap(const std::string& bitmap_file, uint32_t id, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	//Check bitmap data a little
	if(bitmap_file.length() < sizeof(bitmapfileheader))
		throw pe_exception("Incorrect resource bitmap", pe_exception::resource_incorrect_bitmap);

	pe_base::resource_directory_entry new_entry;
	new_entry.set_id(id);

	//Add bitmap
	add_resource(bitmap_file.substr(sizeof(bitmapfileheader)), resource_bitmap, new_entry, pe_base::resource_directory::entry_finder(id), language, codepage, timestamp);
}

//Adds bitmap from bitmap file data. If bitmap already exists, replaces it
//timestamp will be used for directories that will be added
void pe_resource_manager::add_bitmap(const std::string& bitmap_file, const std::wstring& name, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	//Check bitmap data a little
	if(bitmap_file.length() < sizeof(bitmapfileheader))
		throw pe_exception("Incorrect resource bitmap", pe_exception::resource_incorrect_bitmap);

	pe_base::resource_directory_entry new_entry;
	new_entry.set_name(name);

	//Add bitmap
	add_resource(bitmap_file.substr(sizeof(bitmapfileheader)), resource_bitmap, new_entry, pe_base::resource_directory::entry_finder(name), language, codepage, timestamp);
}

//Add icon helper
void pe_resource_manager::add_icon(const std::string& icon_file, const resource_data_info* group_icon_info /* or zero */, pe_base::resource_directory_entry& new_icon_group_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp)
{
	//Check icon for correctness
	if(icon_file.length() < sizeof(ico_header))
		throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

	const ico_header* icon_header = reinterpret_cast<const ico_header*>(&icon_file[0]);

	unsigned long size_of_headers = sizeof(ico_header) + icon_header->Count * sizeof(icondirentry);
	if(icon_file.length() < size_of_headers || icon_header->Count == 0)
		throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

	//Enumerate all icons in file
	for(uint16_t i = 0; i != icon_header->Count; ++i)
	{
		//Check icon entries
		const icondirentry* icon_entry = reinterpret_cast<const icondirentry*>(&icon_file[sizeof(ico_header) + i * sizeof(icondirentry)]);
		if(icon_entry->SizeInBytes == 0
			|| icon_entry->ImageOffset < size_of_headers
			|| !pe_base::is_sum_safe(icon_entry->ImageOffset, icon_entry->SizeInBytes)
			|| icon_entry->ImageOffset + icon_entry->SizeInBytes > icon_file.length())
			throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);
	}

	std::string icon_group_data;
	ico_header* info = 0;

	if(group_icon_info)
	{
		//If icon group already exists
		{
			icon_group_data = group_icon_info->get_data();
			codepage = group_icon_info->get_codepage(); //Don't change codepage of icon group entry
		}

		//Check resource data size
		if(icon_group_data.length() < sizeof(ico_header))
			throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

		//Get icon header
		info = reinterpret_cast<ico_header*>(&icon_group_data[0]);

		//Check resource data size
		if(icon_group_data.length() < sizeof(ico_header) + info->Count * sizeof(icon_group))
			throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

		icon_group_data.resize(sizeof(ico_header) + (info->Count + icon_header->Count) * sizeof(icon_group));
		info = reinterpret_cast<ico_header*>(&icon_group_data[0]); //In case if memory was reallocated
	}
	else //Entry not found - icon group doesn't exist
	{
		icon_group_data.resize(sizeof(ico_header) + icon_header->Count * sizeof(icon_group));
		memcpy(&icon_group_data[0], icon_header, sizeof(ico_header));
	}

	//Search for available icon IDs
	std::vector<uint16_t> icon_id_list(get_icon_or_cursor_free_id_list(resource_icon, mode, icon_header->Count));

	//Enumerate all icons in file
	for(uint16_t i = 0; i != icon_header->Count; ++i)
	{
		const icondirentry* icon_entry = reinterpret_cast<const icondirentry*>(&icon_file[sizeof(ico_header) + i * sizeof(icondirentry)]);
		icon_group group = {0};

		//Fill icon resource header
		group.BitCount = icon_entry->BitCount;
		group.ColorCount = icon_entry->ColorCount;
		group.Height = icon_entry->Height;
		group.Planes = icon_entry->Planes;
		group.Reserved = icon_entry->Reserved;
		group.SizeInBytes = icon_entry->SizeInBytes;
		group.Width = icon_entry->Width;
		group.Number = icon_id_list.at(i);

		memcpy(&icon_group_data[sizeof(ico_header) + ((info ? info->Count : 0) + i) * sizeof(icon_group)], &group, sizeof(group));

		//Add icon to resources
		pe_base::resource_directory_entry new_entry;
		new_entry.set_id(group.Number);
		add_resource(icon_file.substr(icon_entry->ImageOffset, icon_entry->SizeInBytes), resource_icon, new_entry, pe_base::resource_directory::entry_finder(group.Number), language, codepage, timestamp);
	}

	if(info)
		info->Count += icon_header->Count; //Increase icon count, if we're adding icon to existing group

	{
		//Add or replace icon group data entry
		add_resource(icon_group_data, resource_icon_group, new_icon_group_entry, finder, language, codepage, timestamp);
	}
}

//Returns free icon or cursor ID list depending on icon_place_mode
const std::vector<uint16_t> pe_resource_manager::get_icon_or_cursor_free_id_list(resource_type type, icon_place_mode mode, uint32_t count)
{
	//Search for available icon/cursor IDs
	std::vector<uint16_t> icon_cursor_id_list;

	try
	{
		//If any icon exists
		//List icon IDs
		std::vector<uint32_t> id_list(list_resource_ids(type));
		std::sort(id_list.begin(), id_list.end());

		//If we are placing icon on free spaces
		//I.e., icon IDs 1, 3, 4, 7, 8 already exist
		//We'll place five icons on IDs 2, 5, 6, 9, 10
		if(mode != icon_place_after_max_icon_id)
		{
			if(!id_list.empty())
			{
				//Determine and list free icon IDs
				for(std::vector<uint32_t>::const_iterator it = id_list.begin(); it != id_list.end(); ++it)
				{
					if(it == id_list.begin())
					{
						if(*it > 1)
						{
							for(uint16_t i = 1; i != *it; ++i)
							{
								icon_cursor_id_list.push_back(i);
								if(icon_cursor_id_list.size() == count)
									break;
							}
						}
					}
					else if(*(it - 1) - *it > 1)
					{
						for(uint16_t i = static_cast<uint16_t>(*(it - 1) + 1); i != static_cast<uint16_t>(*it); ++i)
						{
							icon_cursor_id_list.push_back(i);
							if(icon_cursor_id_list.size() == count)
								break;
						}
					}

					if(icon_cursor_id_list.size() == count)
						break;
				}
			}
		}

		uint32_t max_id = id_list.empty() ? 0 : *std::max_element(id_list.begin(), id_list.end());
		for(uint32_t i = static_cast<uint32_t>(icon_cursor_id_list.size()); i != count; ++i)
			icon_cursor_id_list.push_back(static_cast<uint16_t>(++max_id));
	}
	catch(const pe_exception&) //Entry not found
	{
		for(uint16_t i = 1; i != count + 1; ++i)
			icon_cursor_id_list.push_back(i);
	}

	return icon_cursor_id_list;
}

//Add cursor helper
void pe_resource_manager::add_cursor(const std::string& cursor_file, const resource_data_info* group_cursor_info /* or zero */, pe_base::resource_directory_entry& new_cursor_group_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp)
{
	//Check cursor for correctness
	if(cursor_file.length() < sizeof(cursor_header))
		throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

	const cursor_header* cur_header = reinterpret_cast<const cursor_header*>(&cursor_file[0]);

	unsigned long size_of_headers = sizeof(cursor_header) + cur_header->Count * sizeof(cursordirentry);
	if(cursor_file.length() < size_of_headers || cur_header->Count == 0)
		throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

	//Enumerate all cursors in file
	for(uint16_t i = 0; i != cur_header->Count; ++i)
	{
		//Check cursor entries
		const cursordirentry* cursor_entry = reinterpret_cast<const cursordirentry*>(&cursor_file[sizeof(cursor_header) + i * sizeof(cursordirentry)]);
		if(cursor_entry->SizeInBytes == 0
			|| cursor_entry->ImageOffset < size_of_headers
			|| !pe_base::is_sum_safe(cursor_entry->ImageOffset, cursor_entry->SizeInBytes)
			|| cursor_entry->ImageOffset + cursor_entry->SizeInBytes > cursor_file.length())
			throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);
	}

	std::string cursor_group_data;
	cursor_header* info = 0;

	if(group_cursor_info)
	{
		//If cursor group already exists
		{
			cursor_group_data = group_cursor_info->get_data();
			codepage = group_cursor_info->get_codepage(); //Don't change codepage of cursor group entry
		}

		//Check resource data size
		if(cursor_group_data.length() < sizeof(cursor_header))
			throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

		//Get cursor header
		info = reinterpret_cast<cursor_header*>(&cursor_group_data[0]);

		//Check resource data size
		if(cursor_group_data.length() < sizeof(cursor_header) + info->Count * sizeof(cursor_group))
			throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

		cursor_group_data.resize(sizeof(cursor_header) + (info->Count + cur_header->Count) * sizeof(cursor_group));
		info = reinterpret_cast<cursor_header*>(&cursor_group_data[0]); //In case if memory was reallocated
	}
	else //Entry not found - cursor group doesn't exist
	{
		cursor_group_data.resize(sizeof(cursor_header) + cur_header->Count * sizeof(cursor_group));
		memcpy(&cursor_group_data[0], cur_header, sizeof(cursor_header));
	}

	//Search for available cursor IDs
	std::vector<uint16_t> cursor_id_list(get_icon_or_cursor_free_id_list(resource_cursor, mode, cur_header->Count));

	//Enumerate all cursors in file
	for(uint16_t i = 0; i != cur_header->Count; ++i)
	{
		const cursordirentry* cursor_entry = reinterpret_cast<const cursordirentry*>(&cursor_file[sizeof(cursor_header) + i * sizeof(cursordirentry)]);
		cursor_group group = {0};

		//Fill cursor resource header
		group.Height = cursor_entry->Height;
		group.SizeInBytes = cursor_entry->SizeInBytes;
		group.Width = cursor_entry->Width;
		group.Number = cursor_id_list.at(i);

		memcpy(&cursor_group_data[sizeof(cursor_header) + ((info ? info->Count : 0) + i) * sizeof(cursor_group)], &group, sizeof(group));

		//Add cursor to resources
		pe_base::resource_directory_entry new_entry;
		new_entry.set_id(group.Number);

		//Fill resource data (two WORDs for hotspot of cursor, and cursor bitmap data)
		std::string cur_data;
		cur_data.resize(sizeof(uint16_t) * 2);
		memcpy(&cur_data[0], &cursor_entry->HotspotX, sizeof(uint16_t));
		memcpy(&cur_data[sizeof(uint16_t)], &cursor_entry->HotspotY, sizeof(uint16_t));
		cur_data.append(cursor_file.substr(cursor_entry->ImageOffset, cursor_entry->SizeInBytes));

		add_resource(cur_data, resource_cursor, new_entry, pe_base::resource_directory::entry_finder(group.Number), language, codepage, timestamp);
	}

	if(info)
		info->Count += cur_header->Count; //Increase cursor count, if we're adding cursor to existing group

	{
		//Add or replace cursor group data entry
		add_resource(cursor_group_data, resource_cursor_group, new_cursor_group_entry, finder, language, codepage, timestamp);
	}
}

//Adds icon(s) from icon file data
//timestamp will be used for directories that will be added
//If icon group with name "icon_group_name" or ID "icon_group_id" already exists, it will be appended with new icon(s)
//(Codepage of icon group and icons will not be changed in this case)
//icon_place_mode determines, how new icon(s) will be placed
void pe_resource_manager::add_icon(const std::string& icon_file, const std::wstring& icon_group_name, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_icon_group_entry;
	new_icon_group_entry.set_name(icon_group_name);
	std::auto_ptr<resource_data_info> data_info;

	try
	{
		data_info.reset(new resource_data_info(get_resource_data_by_name(language, resource_icon_group, icon_group_name)));
	}
	catch(const pe_exception&) //Entry not found
	{
	}

	add_icon(icon_file, data_info.get(), new_icon_group_entry, pe_base::resource_directory::entry_finder(icon_group_name), language, mode, codepage, timestamp);
}

void pe_resource_manager::add_icon(const std::string& icon_file, uint32_t icon_group_id, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_icon_group_entry;
	new_icon_group_entry.set_id(icon_group_id);
	std::auto_ptr<resource_data_info> data_info;

	try
	{
		data_info.reset(new resource_data_info(get_resource_data_by_id(language, resource_icon_group, icon_group_id)));
	}
	catch(const pe_exception&) //Entry not found
	{
	}

	add_icon(icon_file, data_info.get(), new_icon_group_entry, pe_base::resource_directory::entry_finder(icon_group_id), language, mode, codepage, timestamp);
}

//Adds cursor(s) from cursor file data
//timestamp will be used for directories that will be added
//If cursor group with name "cursor_group_name" or ID "cursor_group_id" already exists, it will be appended with new cursor(s)
//(Codepage of cursor group and cursors will not be changed in this case)
//icon_place_mode determines, how new cursor(s) will be placed
void pe_resource_manager::add_cursor(const std::string& cursor_file, const std::wstring& cursor_group_name, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_cursor_group_entry;
	new_cursor_group_entry.set_name(cursor_group_name);
	std::auto_ptr<resource_data_info> data_info;

	try
	{
		data_info.reset(new resource_data_info(get_resource_data_by_name(language, resource_cursor_group, cursor_group_name)));
	}
	catch(const pe_exception&) //Entry not found
	{
	}

	add_cursor(cursor_file, data_info.get(), new_cursor_group_entry, pe_base::resource_directory::entry_finder(cursor_group_name), language, mode, codepage, timestamp);
}

void pe_resource_manager::add_cursor(const std::string& cursor_file, uint32_t cursor_group_id, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp)
{
	pe_base::resource_directory_entry new_cursor_group_entry;
	new_cursor_group_entry.set_id(cursor_group_id);
	std::auto_ptr<resource_data_info> data_info;

	try
	{
		data_info.reset(new resource_data_info(get_resource_data_by_id(language, resource_cursor_group, cursor_group_id)));
	}
	catch(const pe_exception&) //Entry not found
	{
	}

	add_cursor(cursor_file, data_info.get(), new_cursor_group_entry, pe_base::resource_directory::entry_finder(cursor_group_id), language, mode, codepage, timestamp);
}

//Remove icon group helper
void pe_resource_manager::remove_icons_from_icon_group(const std::string& icon_group_data, uint32_t language)
{
	//Check resource data size
	if(icon_group_data.length() < sizeof(ico_header))
		throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

	//Get icon header
	const ico_header* info = reinterpret_cast<const ico_header*>(icon_group_data.data());

	uint16_t icon_count = info->Count;

	//Check resource data size
	if(icon_group_data.length() < sizeof(ico_header) + icon_count * sizeof(icon_group))
		throw pe_exception("Incorrect resource icon", pe_exception::resource_incorrect_icon);

	//Remove icon data
	for(uint16_t i = 0; i != icon_count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(icon_group_data.data() + sizeof(ico_header) + i * sizeof(icon_group));
		remove_resource(resource_icon, group->Number, language);
	}
}

//Remove cursor group helper
void pe_resource_manager::remove_cursors_from_cursor_group(const std::string& cursor_group_data, uint32_t language)
{
	//Check resource data size
	if(cursor_group_data.length() < sizeof(cursor_header))
		throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

	//Get icon header
	const cursor_header* info = reinterpret_cast<const cursor_header*>(cursor_group_data.data());

	uint16_t cursor_count = info->Count;

	//Check resource data size
	if(cursor_group_data.length() < sizeof(cursor_header) + cursor_count * sizeof(cursor_group))
		throw pe_exception("Incorrect resource cursor", pe_exception::resource_incorrect_cursor);

	//Remove icon data
	for(uint16_t i = 0; i != cursor_count; ++i)
	{
		const icon_group* group = reinterpret_cast<const icon_group*>(cursor_group_data.data() + sizeof(cursor_header) + i * sizeof(cursor_group));
		remove_resource(resource_cursor, group->Number, language);
	}
}

//Removes cursor group and all its cursors by name/ID and language
void pe_resource_manager::remove_cursor_group(const std::wstring& cursor_group_name, uint32_t language)
{
	//Get resource by name and language
	const std::string data = get_resource_data_by_name(language, resource_cursor_group, cursor_group_name).get_data();
	remove_cursors_from_cursor_group(data, language);
	remove_resource(resource_cursor_group, cursor_group_name, language);
}

//Removes cursor group and all its cursors by name/ID and language
void pe_resource_manager::remove_cursor_group(uint32_t cursor_group_id, uint32_t language)
{
	//Get resource by name and language
	const std::string data = get_resource_data_by_id(language, resource_cursor_group, cursor_group_id).get_data();
	remove_cursors_from_cursor_group(data, language);
	remove_resource(resource_cursor_group, cursor_group_id, language);
}

//Removes icon group and all its icons by name/ID and language
void pe_resource_manager::remove_icon_group(const std::wstring& icon_group_name, uint32_t language)
{
	//Get resource by name and language
	const std::string data = get_resource_data_by_name(language, resource_icon_group, icon_group_name).get_data();
	remove_icons_from_icon_group(data, language);
	remove_resource(resource_icon_group, icon_group_name, language);
}

//Removes icon group and all its icons by name/ID and language
void pe_resource_manager::remove_icon_group(uint32_t icon_group_id, uint32_t language)
{
	//Get resource by name and language
	const std::string data = get_resource_data_by_id(language, resource_icon_group, icon_group_id).get_data();
	remove_icons_from_icon_group(data, language);
	remove_resource(resource_icon_group, icon_group_id, language);
}

//Removes bitmap by name/ID and language
void pe_resource_manager::remove_bitmap(const std::wstring& name, uint32_t language)
{
	remove_resource(resource_bitmap, name, language);
}

//Removes bitmap by name/ID and language
void pe_resource_manager::remove_bitmap(uint32_t id, uint32_t language)
{
	remove_resource(resource_bitmap, id, language);
}

//Default constructor
pe_resource_viewer::resource_data_info::resource_data_info(const std::string& data, uint32_t codepage)
	:data_(data), codepage_(codepage)
{}

//Constructor from data
pe_resource_viewer::resource_data_info::resource_data_info(const pe_base::resource_data_entry& data)
	:data_(data.get_data()), codepage_(data.get_codepage())
{}

//Returns resource data
const std::string& pe_resource_viewer::resource_data_info::get_data() const
{
	return data_;
}

//Returns resource codepage
uint32_t pe_resource_viewer::resource_data_info::get_codepage() const
{
	return codepage_;
}

//Sets/replaces full version information:
//file_version_info: versions and file info
//lang_string_values_map: map of version info strings with encodings
//translation_values_map: map of translations
void pe_resource_manager::set_version_info(const file_version_info& file_info, const lang_string_values_map& string_values, const translation_values_map& translations, uint32_t language, uint32_t codepage, uint32_t timestamp)
{
	std::string version_data;

	//Calculate total size of version resource data
	uint32_t total_version_info_length =
		static_cast<uint32_t>(sizeof(version_info_block) - sizeof(uint16_t) + sizeof(uint16_t) /* pading */
		+ (version_info_key.length() + 1) * 2
		+ sizeof(vs_fixedfileinfo));

	//If we have any strings values
	if(!string_values.empty())
	{
		total_version_info_length += sizeof(version_info_block) - sizeof(uint16_t); //StringFileInfo block
		total_version_info_length += SizeofStringFileInfo; //Name of block (key)

		//Add required size for version strings
		for(lang_string_values_map::const_iterator table_it = string_values.begin(); table_it != string_values.end(); ++table_it)
		{
			total_version_info_length += pe_base::align_up(static_cast<uint32_t>(sizeof(uint16_t) * 3 + ((*table_it).first.length() + 1) * 2), sizeof(uint32_t)); //Name of child block and block size (key of string table block)

			const string_values_map& values = (*table_it).second;
			for(string_values_map::const_iterator it = values.begin(); it != values.end(); ++it)
			{
				total_version_info_length += pe_base::align_up(static_cast<uint32_t>(sizeof(uint16_t) * 3 + ((*it).first.length() + 1) * 2), sizeof(uint32_t));
				total_version_info_length += pe_base::align_up(static_cast<uint32_t>(((*it).second.length() + 1) * 2), sizeof(uint32_t));
			}
		}
	}

	//If we have translations
	if(!translations.empty())
	{
		total_version_info_length += (sizeof(version_info_block) - sizeof(uint16_t)) * 2; //VarFileInfo and Translation blocks
		total_version_info_length += SizeofVarFileInfoAligned; //DWORD-aligned VarFileInfo block name
		total_version_info_length += SizeofTranslationAligned; //DWORD-aligned Translation block name
		total_version_info_length += static_cast<uint32_t>(translations.size() * sizeof(uint16_t) * 2);
	}

	//Resize version data buffer
	version_data.resize(total_version_info_length);

	//Create root version block
	version_info_block root_block = {0};
	root_block.ValueLength = sizeof(vs_fixedfileinfo);
	root_block.Length = static_cast<uint16_t>(total_version_info_length);

	//Fill fixed file info
	vs_fixedfileinfo fixed_info = {0};
	fixed_info.dwFileDateLS = file_info.get_file_date_ls();
	fixed_info.dwFileDateMS = file_info.get_file_date_ms();
	fixed_info.dwFileFlags = file_info.get_file_flags();
	fixed_info.dwFileFlagsMask = vs_ffi_fileflagsmask;
	fixed_info.dwFileOS = file_info.get_file_os_raw();
	fixed_info.dwFileSubtype = file_info.get_file_subtype();
	fixed_info.dwFileType = file_info.get_file_type_raw();
	fixed_info.dwFileVersionLS = file_info.get_product_version_ls();
	fixed_info.dwFileVersionMS = file_info.get_file_version_ms();
	fixed_info.dwSignature = vs_ffi_signature;
	fixed_info.dwStrucVersion = vs_ffi_strucversion;
	fixed_info.dwProductVersionLS = file_info.get_product_version_ls();
	fixed_info.dwProductVersionMS = file_info.get_product_version_ms();

	//Write root block and fixed file info to buffer
	uint32_t data_ptr = 0;
	memcpy(&version_data[data_ptr], &root_block, sizeof(version_info_block) - sizeof(uint16_t));
	data_ptr += sizeof(version_info_block) - sizeof(uint16_t);
	memcpy(&version_data[data_ptr], version_info_key.c_str(), (version_info_key.length() + 1) * sizeof(uint16_t));
	data_ptr += static_cast<uint32_t>((version_info_key.length() + 1) * sizeof(uint16_t));
	memset(&version_data[data_ptr], 0, sizeof(uint16_t));
	data_ptr += sizeof(uint16_t);
	memcpy(&version_data[data_ptr], &fixed_info, sizeof(fixed_info));
	data_ptr += sizeof(fixed_info);

	//Write string values, if any
	if(!string_values.empty())
	{
		//Create string file info root block
		version_info_block string_file_info_block = {0};
		string_file_info_block.Type = 1; //Block type is string
		memcpy(&version_data[data_ptr], &string_file_info_block, sizeof(version_info_block) - sizeof(uint16_t));
		//We will calculate its length later
		version_info_block* string_file_info_block_ptr = reinterpret_cast<version_info_block*>(&version_data[data_ptr]);
		data_ptr += sizeof(version_info_block) - sizeof(uint16_t);

		uint32_t old_ptr1 = data_ptr; //Used to calculate string file info block length later
		memcpy(&version_data[data_ptr], StringFileInfo, SizeofStringFileInfo); //Write block name
		data_ptr += SizeofStringFileInfo;

		//Create string table root block (child of string file info)
		version_info_block string_table_block = {0};
		string_table_block.Type = 1; //Block type is string

		for(lang_string_values_map::const_iterator table_it = string_values.begin(); table_it != string_values.end(); ++table_it)
		{
			const string_values_map& values = (*table_it).second;

			memcpy(&version_data[data_ptr], &string_table_block, sizeof(version_info_block) - sizeof(uint16_t));
			//We will calculate its length later
			version_info_block* string_table_block_ptr = reinterpret_cast<version_info_block*>(&version_data[data_ptr]);
			data_ptr += sizeof(version_info_block) - sizeof(uint16_t);

			uint32_t old_ptr2 = data_ptr; //Used to calculate string table block length later
			uint32_t lang_key_length = static_cast<uint32_t>(((*table_it).first.length() + 1) * sizeof(uint16_t));

#ifdef PE_BLISS_WINDOWS
			memcpy(&version_data[data_ptr], (*table_it).first.c_str(), lang_key_length); //Write block key
#else
			{
				u16string str(pe_base::to_ucs2((*table_it).first));
				memcpy(&version_data[data_ptr], str.c_str(), lang_key_length); //Write block key
			}
#endif

			data_ptr += lang_key_length;
			//Align key if necessary
			if((sizeof(uint16_t) * 3 + lang_key_length) % sizeof(uint32_t))
			{
				memset(&version_data[data_ptr], 0, sizeof(uint16_t));
				data_ptr += sizeof(uint16_t);
			}

			//Create string block (child of string table block)
			version_info_block string_block = {0};
			string_block.Type = 1; //Block type is string
			for(string_values_map::const_iterator it = values.begin(); it != values.end(); ++it)
			{
				//Calculate value length and key length of string block
				string_block.ValueLength = static_cast<uint16_t>((*it).second.length() + 1);
				uint32_t key_length = static_cast<uint32_t>(((*it).first.length() + 1) * sizeof(uint16_t));
				//Calculate length of block
				string_block.Length = static_cast<uint16_t>(pe_base::align_up(sizeof(uint16_t) * 3 + key_length, sizeof(uint32_t)) + string_block.ValueLength * sizeof(uint16_t));

				//Write string block
				memcpy(&version_data[data_ptr], &string_block, sizeof(version_info_block) - sizeof(uint16_t));
				data_ptr += sizeof(version_info_block) - sizeof(uint16_t);

#ifdef PE_BLISS_WINDOWS
				memcpy(&version_data[data_ptr], (*it).first.c_str(), key_length); //Write block key
#else
				{
					u16string str(pe_base::to_ucs2((*it).first));
					memcpy(&version_data[data_ptr], str.c_str(), key_length); //Write block key
				}
#endif

				data_ptr += key_length;
				//Align key if necessary
				if((sizeof(uint16_t) * 3 + key_length) % sizeof(uint32_t))
				{
					memset(&version_data[data_ptr], 0, sizeof(uint16_t));
					data_ptr += sizeof(uint16_t);
				}

				//Write block data (value)
#ifdef PE_BLISS_WINDOWS
				memcpy(&version_data[data_ptr], (*it).second.c_str(), string_block.ValueLength * sizeof(uint16_t));
#else
				{
					u16string str(pe_base::to_ucs2((*it).second));
					memcpy(&version_data[data_ptr], str.c_str(), string_block.ValueLength * sizeof(uint16_t));
				}
#endif

				data_ptr += string_block.ValueLength * 2;
				//Align data if necessary
				if((string_block.ValueLength * 2) % sizeof(uint32_t))
				{
					memset(&version_data[data_ptr], 0, sizeof(uint16_t));
					data_ptr += sizeof(uint16_t);
				}
			}

			//Calculate string table and string file info blocks lengths
			string_table_block_ptr->Length = static_cast<uint16_t>(data_ptr - old_ptr2 + sizeof(uint16_t) * 3);
		}

		string_file_info_block_ptr->Length = static_cast<uint16_t>(data_ptr - old_ptr1 + sizeof(uint16_t) * 3);
	}

	//If we have transactions
	if(!translations.empty())
	{
		//Create root var file info block
		version_info_block var_file_info_block = {0};
		var_file_info_block.Type = 1; //Type of block is string
		//Write block header
		memcpy(&version_data[data_ptr], &var_file_info_block, sizeof(version_info_block) - sizeof(uint16_t));
		//We will calculate its length later
		version_info_block* var_file_info_block_ptr = reinterpret_cast<version_info_block*>(&version_data[data_ptr]);
		data_ptr += sizeof(version_info_block) - sizeof(uint16_t);

		uint32_t old_ptr1 = data_ptr; //Used to calculate var file info block length later
		memcpy(&version_data[data_ptr], VarFileInfoAligned, SizeofVarFileInfoAligned); //Write block key (aligned)
		data_ptr += SizeofVarFileInfoAligned;

		//Create root translation block (child of var file info block)
		version_info_block translation_block = {0};
		//Write block header
		memcpy(&version_data[data_ptr], &translation_block, sizeof(version_info_block) - sizeof(uint16_t));
		//We will calculate its length later
		version_info_block* translation_block_ptr = reinterpret_cast<version_info_block*>(&version_data[data_ptr]);
		data_ptr += sizeof(version_info_block) - sizeof(uint16_t);

		uint32_t old_ptr2 = data_ptr; //Used to calculate var file info block length later
		memcpy(&version_data[data_ptr], TranslationAligned, SizeofTranslationAligned); //Write block key (aligned)
		data_ptr += SizeofTranslationAligned;

		//Calculate translation block value length
		translation_block_ptr->ValueLength = static_cast<uint16_t>(sizeof(uint16_t) * 2 * translations.size());

		//Write translation values to block
		for(translation_values_map::const_iterator it = translations.begin(); it != translations.end(); ++it)
		{
			uint16_t lang_id = (*it).first; //Language ID
			uint16_t codepage_id = (*it).second; //Codepage ID
			memcpy(&version_data[data_ptr], &lang_id, sizeof(lang_id));
			data_ptr += sizeof(lang_id);
			memcpy(&version_data[data_ptr], &codepage_id, sizeof(codepage_id));
			data_ptr += sizeof(codepage_id);
		}

		//Calculate Translation and VarFileInfo blocks lengths
		translation_block_ptr->Length = static_cast<uint16_t>(data_ptr - old_ptr2 + sizeof(uint16_t) * 3);
		var_file_info_block_ptr->Length = static_cast<uint16_t>(data_ptr - old_ptr1 + sizeof(uint16_t) * 3);
	}

	//Add/replace version info resource
	add_resource(version_data, resource_version, 1, language, codepage, timestamp);
}


//Default constructor
//strings - version info strings with charsets
//translations - version info translations map
version_info_viewer::version_info_viewer(const pe_resource_viewer::lang_string_values_map& strings,
	const pe_resource_viewer::translation_values_map& translations)
	:strings_(strings), translations_(translations)
{}

//Below functions have parameter translation
//If it's empty, the default language translation will be taken
//If there's no default language translation, the first one will be taken

//Returns company name
const std::wstring version_info_viewer::get_company_name(const std::wstring& translation) const
{
	return get_property(L"CompanyName", translation);
}

//Returns file description
const std::wstring version_info_viewer::get_file_description(const std::wstring& translation) const
{
	return get_property(L"FileDescription", translation);
}

//Returns file version
const std::wstring version_info_viewer::get_file_version(const std::wstring& translation) const
{
	return get_property(L"FileVersion", translation);
}

//Returns internal file name
const std::wstring version_info_viewer::get_internal_name(const std::wstring& translation) const
{
	return get_property(L"InternalName", translation);
}

//Returns legal copyright
const std::wstring version_info_viewer::get_legal_copyright(const std::wstring& translation) const
{
	return get_property(L"LegalCopyright", translation);
}

//Returns original file name
const std::wstring version_info_viewer::get_original_filename(const std::wstring& translation) const
{
	return get_property(L"OriginalFilename", translation);
}

//Returns product name
const std::wstring version_info_viewer::get_product_name(const std::wstring& translation) const
{
	return get_property(L"ProductName", translation);
}

//Returns product version
const std::wstring version_info_viewer::get_product_version(const std::wstring& translation) const
{
	return get_property(L"ProductVersion", translation);
}

//Returns list of translations in string representation
const version_info_viewer::translation_list version_info_viewer::get_translation_list() const
{
	translation_list ret;

	//Enumerate all translations
	for(pe_resource_viewer::translation_values_map::const_iterator it = translations_.begin(); it != translations_.end(); ++it)
	{
		//Create string representation of translation value
		std::wstringstream ss;
		ss << std::hex
			<< std::setw(4) << std::setfill(L'0') << (*it).first
			<< std::setw(4) << std::setfill(L'0') <<  (*it).second;

		//Save it
		ret.push_back(ss.str());
	}

	return ret;
}

//Returns version info property value
//property_name - required property name
//If throw_if_absent = true, will throw exception if property does not exist
//If throw_if_absent = false, will return empty string if property does not exist
const std::wstring version_info_viewer::get_property(const std::wstring& property_name, const std::wstring& translation, bool throw_if_absent) const
{
	std::wstring ret;

	//If there're no strings
	if(strings_.empty())
	{
		if(throw_if_absent)
			throw pe_exception("Version info string does not exist", pe_exception::version_info_string_does_not_exist);

		return ret;
	}

	pe_resource_viewer::lang_string_values_map::const_iterator it = strings_.begin();

	if(translation.empty())
	{
		//If no translation was specified
		it = strings_.find(default_language_translation); //Find default translation table
		if(it == strings_.end()) //If there's no default translation table, take the first one
			it = strings_.begin();
	}
	else
	{
		it = strings_.find(translation); //Find specified translation table
		if(it == strings_.end())
		{
			if(throw_if_absent)
				throw pe_exception("Version info string does not exist", pe_exception::version_info_string_does_not_exist);

			return ret;
		}
	}
	
	//Find value of the required property
	pe_resource_viewer::string_values_map::const_iterator str_it = (*it).second.find(property_name);

	if(str_it == (*it).second.end())
	{
		if(throw_if_absent)
			throw pe_exception("Version info string does not exist", pe_exception::version_info_string_does_not_exist);

		return ret;
	}

	ret = (*str_it).second;

	return ret;
}

//Default constructor
//strings - version info strings with charsets
//translations - version info translations map
version_info_editor::version_info_editor(pe_resource_viewer::lang_string_values_map& strings,
	pe_resource_viewer::translation_values_map& translations)
	:version_info_viewer(strings, translations),
	strings_edit_(strings),
	translations_edit_(translations)
{}

//Below functions have parameter translation
//If it's empty, the default language translation will be taken
//If there's no default language translation, the first one will be taken

//Sets company name
void version_info_editor::set_company_name(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"CompanyName", value, translation);
}

//Sets file description
void version_info_editor::set_file_description(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"FileDescription", value, translation);
}

//Sets file version
void version_info_editor::set_file_version(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"FileVersion", value, translation);
}

//Sets internal file name
void version_info_editor::set_internal_name(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"InternalName", value, translation);
}

//Sets legal copyright
void version_info_editor::set_legal_copyright(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"LegalCopyright", value, translation);
}

//Sets original file name
void version_info_editor::set_original_filename(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"OriginalFilename", value, translation);
}

//Sets product name
void version_info_editor::set_product_name(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"ProductName", value, translation);
}

//Sets product version
void version_info_editor::set_product_version(const std::wstring& value, const std::wstring& translation)
{
	set_property(L"ProductVersion", value, translation);
}

//Sets version info property value
//property_name - property name
//value - property value
//If translation does not exist, it will be added
//If property does not exist, it will be added
void version_info_editor::set_property(const std::wstring& property_name, const std::wstring& value, const std::wstring& translation)
{
	pe_resource_viewer::lang_string_values_map::iterator it = strings_edit_.begin();

	if(translation.empty())
	{
		//If no translation was specified
		it = strings_edit_.find(default_language_translation); //Find default translation table
		if(it == strings_edit_.end()) //If there's no default translation table, take the first one
		{
			it = strings_edit_.begin();
			if(it == strings_edit_.end()) //If there's no any translation table, add default one
			{
				it = strings_edit_.insert(std::make_pair(default_language_translation, pe_resource_viewer::string_values_map())).first;
				//Also add it to translations list
				add_translation(default_language_translation);
			}
		}
	}
	else
	{
		it = strings_edit_.find(translation); //Find specified translation table
		if(it == strings_edit_.end()) //If there's no translation, add it
		{
			it = strings_edit_.insert(std::make_pair(translation, pe_resource_viewer::string_values_map())).first;
			//Also add it to translations list
			add_translation(translation);
		}
	}

	//Change value of the required property
	((*it).second)[property_name] = value;
}

//Adds translation to translation list
void version_info_editor::add_translation(const std::wstring& translation)
{
	std::pair<uint16_t, uint16_t> translation_ids(translation_from_string(translation));
	add_translation(translation_ids.first, translation_ids.second);
}

void version_info_editor::add_translation(uint16_t language_id, uint16_t codepage_id)
{
	std::pair<pe_resource_viewer::translation_values_map::const_iterator, pe_resource_viewer::translation_values_map::const_iterator>
		range(translations_edit_.equal_range(language_id));

	//If translation already exists
	for(pe_resource_viewer::translation_values_map::const_iterator it = range.first; it != range.second; ++it)
	{
		if((*it).second == codepage_id)
			return;
	}

	translations_edit_.insert(std::make_pair(language_id, codepage_id));
}

//Removes translation from translations and strings lists
void version_info_editor::remove_translation(const std::wstring& translation)
{
	std::pair<uint16_t, uint16_t> translation_ids(translation_from_string(translation));
	remove_translation(translation_ids.first, translation_ids.second);
}

void version_info_editor::remove_translation(uint16_t language_id, uint16_t codepage_id)
{
	{
		//Erase string table (if exists)
		std::wstringstream ss;
		ss << std::hex
			<< std::setw(4) << std::setfill(L'0') << language_id
			<< std::setw(4) << std::setfill(L'0') << codepage_id;
		
		strings_edit_.erase(ss.str());
	}

	//Find and erase translation from translations table
	std::pair<pe_resource_viewer::translation_values_map::iterator, pe_resource_viewer::translation_values_map::iterator>
		it_pair = translations_edit_.equal_range(language_id);

	for(pe_resource_viewer::translation_values_map::iterator it = it_pair.first; it != it_pair.second; ++it)
	{
		if((*it).second == codepage_id)
		{
			translations_edit_.erase(it);
			break;
		}
	}
}

//Converts translation HEX-string to pair of language ID and codepage ID
const version_info_viewer::translation_pair version_info_viewer::translation_from_string(const std::wstring& translation)
{
	uint32_t translation_id = 0;

	{
		//Convert string to DWORD
		std::wstringstream ss;
		ss << std::hex << translation;
		ss >> translation_id;
	}

	return std::make_pair(static_cast<uint16_t>(translation_id >> 16), static_cast<uint16_t>(translation_id & 0xFFFF));
}
}
