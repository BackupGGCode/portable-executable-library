#pragma once
#include <map>
#include <sstream>
#include <string>
#include <string.h>
#include <memory>
#include "pe_base.h"
#include "pe_structures.h"

namespace pe_bliss
{
//PE resource manager allows to read resources from PE files
class pe_resource_viewer
{
public:
	//ID; string
	typedef std::map<uint16_t, std::wstring> string_list;

	//Structure representing message table string
	struct message_table_item
	{
	public:
		//Default constructor
		message_table_item();
		//Constructors from ANSI and UNICODE strings
		explicit message_table_item(const std::string& str);
		explicit message_table_item(const std::wstring& str);

		//Returns true if string is UNICODE
		bool is_unicode() const;
		//Returns ANSI string
		const std::string& get_ansi_string() const;
		//Returns UNICODE string
		const std::wstring& get_unicode_string() const;

	public:
		//SEets ANSI or UNICODE string
		void set_string(const std::string& str);
		void set_string(const std::wstring& str);

	private:
		bool unicode_;
		std::string ansi_str_;
		std::wstring unicode_str_;
	};

	//ID; message_table_item
	typedef std::map<uint32_t, message_table_item> message_list;

public:
	//Resource type enumeration
	enum resource_type
	{
		resource_cursor = 1,
		resource_bitmap = 2,
		resource_icon = 3,
		resource_menu = 4,
		resource_dialog = 5,
		resource_string = 6,
		resource_fontdir = 7,
		resource_font = 8,
		resource_accelerator = 9,
		resource_rcdata = 10,
		resource_message_table = 11,
		resource_cursor_group = 12,
		resource_icon_group = 14,
		resource_version = 16,
		resource_dlginclude = 17,
		resource_plugplay = 19,
		resource_vxd = 20,
		resource_anicursor = 21,
		resource_aniicon = 22,
		resource_html = 23,
		resource_manifest = 24
	};

	//Structure representing resource data
	struct resource_data_info
	{
	public:
		//Constructor from data
		resource_data_info(const std::string& data, uint32_t codepage);
		//Constructor from data
		explicit resource_data_info(const pe_base::resource_data_entry& data);

		//Returns resource data
		const std::string& get_data() const;
		//Returns resource codepage
		uint32_t get_codepage() const;

	private:
		std::string data_;
		uint32_t codepage_;
	};

public:
	//Some useful typedefs
	typedef std::vector<uint32_t> resource_type_list;
	typedef std::vector<uint32_t> resource_id_list;
	typedef std::vector<std::wstring> resource_name_list;
	typedef std::vector<uint32_t> resource_language_list;
	
	//Typedef for version info functions: Name - Value
	typedef std::map<std::wstring, std::wstring> string_values_map;
	//Typedef for version info functions: Language string - String Values Map
	//Language String consists of LangID and CharsetID
	//E.g. 041904b0 for Russian UNICODE, 040004b0 for Process Default Language UNICODE
	typedef std::map<std::wstring, string_values_map> lang_string_values_map;

	//Typedef for version info functions: Language - Character Set
	typedef std::multimap<uint16_t, uint16_t> translation_values_map;

public:
	//Constructor from root resource_directory from PE file
	explicit pe_resource_viewer(const pe_base::resource_directory& root_directory);

	//Lists resource types existing in PE file (non-named only)
	const resource_type_list list_resource_types() const;
	//Returns true if resource type exists
	bool resource_exists(resource_type type) const;
	//Returns true if resource name exists
	bool resource_exists(const std::wstring& root_name) const;

	//Lists resource names existing in PE file by resource type
	const resource_name_list list_resource_names(resource_type type) const;
	//Lists resource names existing in PE file by resource name
	const resource_name_list list_resource_names(const std::wstring& root_name) const;
	//Lists resource IDs existing in PE file by resource type
	const resource_id_list list_resource_ids(resource_type type) const;
	//Lists resource IDs existing in PE file by resource name
	const resource_id_list list_resource_ids(const std::wstring& root_name) const;
	//Returns resource count by type
	unsigned long get_resource_count(resource_type type) const;
	//Returns resource count by name
	unsigned long get_resource_count(const std::wstring& root_name) const;

	//Returns language count of resource by resource type and name
	unsigned long get_language_count(resource_type type, const std::wstring& name) const;
	//Returns language count of resource by resource names
	unsigned long get_language_count(const std::wstring& root_name, const std::wstring& name) const;
	//Returns language count of resource by resource type and ID
	unsigned long get_language_count(resource_type type, uint32_t id) const;
	//Returns language count of resource by resource name and ID
	unsigned long get_language_count(const std::wstring& root_name, uint32_t id) const;
	//Lists resource languages by resource type and name
	const resource_language_list list_resource_languages(resource_type type, const std::wstring& name) const;
	//Lists resource languages by resource names
	const resource_language_list list_resource_languages(const std::wstring& root_name, const std::wstring& name) const;
	//Lists resource languages by resource type and ID
	const resource_language_list list_resource_languages(resource_type type, uint32_t id) const;
	//Lists resource languages by resource name and ID
	const resource_language_list list_resource_languages(const std::wstring& root_name, uint32_t id) const;

	//Returns raw resource data by type, name and language
	const resource_data_info get_resource_data_by_name(uint32_t language, resource_type type, const std::wstring& name) const;
	//Returns raw resource data by root name, name and language
	const resource_data_info get_resource_data_by_name(uint32_t language, const std::wstring& root_name, const std::wstring& name) const;
	//Returns raw resource data by type, ID and language
	const resource_data_info get_resource_data_by_id(uint32_t language, resource_type type, uint32_t id) const;
	//Returns raw resource data by root name, ID and language
	const resource_data_info get_resource_data_by_id(uint32_t language, const std::wstring& root_name, uint32_t id) const;
	//Returns raw resource data by type, name and index in language directory (instead of language)
	const resource_data_info get_resource_data_by_name(resource_type type, const std::wstring& name, uint32_t index = 0) const;
	//Returns raw resource data by root name, name and index in language directory (instead of language)
	const resource_data_info get_resource_data_by_name(const std::wstring& root_name, const std::wstring& name, uint32_t index = 0) const;
	//Returns raw resource data by type, ID and index in language directory (instead of language)
	const resource_data_info get_resource_data_by_id(resource_type type, uint32_t id, uint32_t index = 0) const;
	//Returns raw resource data by root name, ID and index in language directory (instead of language)
	const resource_data_info get_resource_data_by_id(const std::wstring& root_name, uint32_t id, uint32_t index = 0) const;

	//Returns bitmap data by name and language (minimum checks of format correctness)
	const std::string get_bitmap_by_name(uint32_t language, const std::wstring& name) const;
	//Returns bitmap data by name and index in language directory (instead of language) (minimum checks of format correctness)
	const std::string get_bitmap_by_name(const std::wstring& name, uint32_t index = 0) const;
	//Returns bitmap data by ID and language (minimum checks of format correctness)
	const std::string get_bitmap_by_id_lang(uint32_t language, uint32_t id) const;
	//Returns bitmap data by ID and index in language directory (instead of language) (minimum checks of format correctness)
	const std::string get_bitmap_by_id(uint32_t id, uint32_t index = 0) const;

	//Returns icon data by name and language (minimum checks of format correctness)
	const std::string get_icon_by_name(uint32_t language, const std::wstring& icon_group_name) const;
	//Returns icon data by name and index in language directory (instead of language) (minimum checks of format correctness)
	const std::string get_icon_by_name(const std::wstring& icon_group_name, uint32_t index = 0) const;
	//Returns icon data by ID and language (minimum checks of format correctness)
	const std::string get_icon_by_id_lang(uint32_t language, uint32_t icon_group_id) const;
	//Returns icon data by ID and index in language directory (instead of language) (minimum checks of format correctness)
	const std::string get_icon_by_id(uint32_t icon_group_id, uint32_t index = 0) const;

	//Returns cursor data by name and language (minimum checks of format correctness)
	const std::string get_cursor_by_name(uint32_t language, const std::wstring& cursor_group_name) const;
	//Returns cursor data by name and index in language directory (instead of language) (minimum checks of format correctness)
	const std::string get_cursor_by_name(const std::wstring& cursor_group_name, uint32_t index = 0) const;
	//Returns cursor data by ID and language (minimum checks of format correctness)
	const std::string get_cursor_by_id_lang(uint32_t language, uint32_t cursor_group_id) const;
	//Returns cursor data by ID and index in language directory (instead of language) (minimum checks of format correctness)
	const std::string get_cursor_by_id(uint32_t cursor_group_id, uint32_t index = 0) const;

	//Returns string table data by ID and language
	const string_list get_string_table_by_id_lang(uint32_t language, uint32_t id) const;
	//Returns string table data by ID and index in language directory (instead of language)
	const string_list get_string_table_by_id(uint32_t id, uint32_t index = 0) const;
	//Returns string from string table by ID and language
	const std::wstring get_string_by_id_lang(uint32_t language, uint16_t id) const;
	//Returns string from string table by ID and index in language directory (instead of language)
	const std::wstring get_string_by_id(uint16_t id, uint32_t index = 0) const;

	//Returns message table data by ID and language
	const message_list get_message_table_by_id_lang(uint32_t language, uint32_t id) const;
	//Returns message table data by ID and index in language directory (instead of language)
	const message_list get_message_table_by_id(uint32_t id, uint32_t index = 0) const;


public: //VERSION INFO
	//Structure representing fixed file version info
	struct file_version_info
	{
	public:
		//Enumeration of file operating system types
		enum file_os_type
		{
			file_os_unknown,
			file_os_dos,
			file_os_os216,
			file_os_os232,
			file_os_nt,
			file_os_wince,
			file_os_win16,
			file_os_pm16,
			file_os_pm32,
			file_os_win32,
			file_os_dos_win16,
			file_os_dos_win32,
			file_os_os216_pm16,
			file_os_os232_pm32,
			file_os_nt_win32
		};

		//Enumeration of file types
		enum file_type
		{
			file_type_unknown,
			file_type_application,
			file_type_dll,
			file_type_driver,
			file_type_font,
			file_type_vxd,
			file_type_static_lib
		};

	public:
		//Default constructor
		file_version_info();
		//Constructor from Windows fixed version info structure
		explicit file_version_info(const pe_win::vs_fixedfileinfo& info);

	public: //Getters
		//Returns true if file is debug-built
		bool is_debug() const;
		//Returns true if file is prerelease
		bool is_prerelease() const;
		//Returns true if file is patched
		bool is_patched() const;
		//Returns true if private build
		bool is_private_build() const;
		//Returns true if special build
		bool is_special_build() const;
		//Returns true if info inferred
		bool is_info_inferred() const;
		//Retuens file flags (raw DWORD)
		uint32_t get_file_flags() const;

		//Returns file version most significant DWORD
		uint32_t get_file_version_ms() const;
		//Returns file version least significant DWORD
		uint32_t get_file_version_ls() const;
		//Returns product version most significant DWORD
		uint32_t get_product_version_ms() const;
		//Returns product version least significant DWORD
		uint32_t get_product_version_ls() const;

		//Returns file OS type (raw DWORD)
		uint32_t get_file_os_raw() const;
		//Returns file OS type
		file_os_type get_file_os() const;

		//Returns file type (raw DWORD)
		uint32_t get_file_type_raw() const;
		//Returns file type
		file_type get_file_type() const;

		//Returns file subtype (usually non-zero for drivers and fonts)
		uint32_t get_file_subtype() const;

		//Returns file date most significant DWORD
		uint32_t get_file_date_ms() const;
		//Returns file date least significant DWORD
		uint32_t get_file_date_ls() const;

		//Returns file version string
		template<typename T>
		const std::basic_string<T> get_file_version_string() const
		{
			return get_version_string<T>(file_version_ms_, file_version_ls_);
		}

		//Returns product version string
		template<typename T>
		const std::basic_string<T> get_product_version_string() const
		{
			return get_version_string<T>(product_version_ms_, product_version_ls_);
		}
		
	public: //Setters
		//Sets if file is debug-built
		void set_debug(bool debug);
		//Sets if file is prerelease
		void set_prerelease(bool prerelease);
		//Sets if file is patched
		void set_patched(bool patched);
		//Sets if private build
		void set_private_build(bool private_build);
		//Sets if special build
		void set_special_build(bool special_build);
		//Sets if info inferred
		void set_info_inferred(bool info_inferred);
		//Sets flags (raw DWORD)
		void set_file_flags(uint32_t file_flags);

		//Sets file version most significant DWORD
		void set_file_version_ms(uint32_t file_version_ms);
		//Sets file version least significant DWORD
		void set_file_version_ls(uint32_t file_version_ls);
		//Sets product version most significant DWORD
		void set_product_version_ms(uint32_t product_version_ms);
		//Sets product version least significant DWORD
		void set_product_version_ls(uint32_t product_version_ls);

		//Sets file OS type (raw DWORD)
		void set_file_os_raw(uint32_t file_os);
		//Sets file OS type
		void set_file_os(file_os_type file_os);

		//Sets file type (raw DWORD)
		void set_file_type_raw(uint32_t file_type);
		//Sets file type
		void set_file_type(file_type file_type);

		//Sets file subtype (usually non-zero for drivers and fonts)
		void set_file_subtype(uint32_t file_subtype);

		//Sets file date most significant DWORD
		void set_file_date_ms(uint32_t file_date_ms);
		//Sets file date least significant DWORD
		void set_file_date_ls(uint32_t file_date_ls);

	private:
		//Helper to convert version DWORDs to string
		template<typename T>
		static const std::basic_string<T> get_version_string(uint32_t ms, uint32_t ls)
		{
			std::basic_stringstream<T> ss;
			ss << (ms >> 16) << static_cast<T>(L'.')
				<< (ms & 0xFFFF) << static_cast<T>(L'.')
				<< (ls >> 16) << static_cast<T>(L'.')
				<< (ls & 0xFFFF);
			return ss.str();
		}

		//Helper to set file flag
		void set_file_flag(uint32_t flag);
		//Helper to clear file flag
		void clear_file_flag(uint32_t flag);
		//Helper to set or clear file flag
		void set_file_flag(uint32_t flag, bool set_flag);

		uint32_t file_version_ms_, file_version_ls_,
			product_version_ms_, product_version_ls_;
		uint32_t file_flags_;
		uint32_t file_os_;
		uint32_t file_type_, file_subtype_;
		uint32_t file_date_ms_, file_date_ls_;
	};

	//Returns full version information:
	//file_version_info: versions and file info
	//lang_lang_string_values_map: map of version info strings with encodings with encodings
	//translation_values_map: map of translations
	const file_version_info get_version_info(lang_string_values_map& string_values, translation_values_map& translations, uint32_t index = 0) const;
	const file_version_info get_version_info_by_lang(lang_string_values_map& string_values, translation_values_map& translations, uint32_t language) const;

protected:
	//Root resource directory. We're not copying it, because it might be heavy
	const pe_base::resource_directory& root_dir_;

	//Helper function of creating bitmap header
	const std::string create_bitmap(const std::string& resource_data) const;
	//Helper function of creating icon headers from ICON_GROUP resource data
	//Returns icon count
	uint16_t format_icon_headers(std::string& ico_data, const std::string& resource_data) const;
	//Helper function of creating cursor headers from CURSOR_GROUP resource data
	//Returns cursor count
	uint16_t format_cursor_headers(std::string& cur_data, const std::string& resource_data, uint32_t language, uint32_t index = 0xFFFFFFFF) const;
	//Helper function of parsing string list table
	const string_list parse_string_list(uint32_t id, const std::string& resource_data) const;
	//Helper function of parsing message list table
	const message_list parse_message_list(const std::string& resource_data) const;

	//Helper function to get ID list from entry list
	static const resource_id_list get_id_list(const pe_base::resource_directory::entry_list& entries);
	//Helper function to get name list from entry list
	static const resource_name_list get_name_list(const pe_base::resource_directory::entry_list& entries);
	
protected: //VERSION INFO helpers
	//L"VS_VERSION_INFO" key of root version info block
	static const u16string version_info_key;

	//Returns aligned version block value position
	static uint32_t get_version_block_value_pos(uint32_t base_pos, const unicode16_t* key);

	//Returns aligned version block first child position
	static uint32_t get_version_block_first_child_pos(uint32_t base_pos, uint32_t value_length, const unicode16_t* key);

	//Returns full version information:
	//file_version_info: versions and file info
	//lang_string_values_map: map of version info strings with encodings
	//translation_values_map: map of translations
	const file_version_info get_version_info(lang_string_values_map& string_values, translation_values_map& translations, const std::string& resource_data) const;

	//Throws an exception (id = resource_incorrect_version_info)
	static void throw_incorrect_version_info();

protected:
	//Helper structure - finder of resource_directory_entry that is named
	struct has_name
	{
	public:
		bool operator()(const pe_base::resource_directory_entry& entry) const;
	};

	//Helper structure - finder of resource_directory_entry that is not named (has id)
	struct has_id
	{
	public:
		bool operator()(const pe_base::resource_directory_entry& entry) const;
	};
};

//Derived class to edit PE resources
class pe_resource_manager : public pe_resource_viewer
{
public:
	//Constructor from root resource directory
	explicit pe_resource_manager(pe_base::resource_directory& root_directory);

public: //Resource editing
	//Removes all resources of given type or root name
	//If there's more than one directory entry of a given type, only the
	//first one will be deleted (that's an unusual situation)
	//Returns true if resource was deleted
	bool remove_resource_type(resource_type type);
	bool remove_resource(const std::wstring& root_name);
	
	//Removes all resource languages by resource type/root name and name
	//Deletes only one entry of given type and name
	//Returns true if resource was deleted
	bool remove_resource(resource_type type, const std::wstring& name);
	bool remove_resource(const std::wstring& root_name, const std::wstring& name);
	//Removes all resource languages by resource type/root name and ID
	//Deletes only one entry of given type and ID
	//Returns true if resource was deleted
	bool remove_resource(resource_type type, uint32_t id);
	bool remove_resource(const std::wstring& root_name, uint32_t id);

	//Removes resource language by resource type/root name and name
	//Deletes only one entry of given type, name and language
	//Returns true if resource was deleted
	bool remove_resource(resource_type type, const std::wstring& name, uint32_t language);
	bool remove_resource(const std::wstring& root_name, const std::wstring& name, uint32_t language);
	//Removes recource language by resource type/root name and ID
	//Deletes only one entry of given type, ID and language
	//Returns true if resource was deleted
	bool remove_resource(resource_type type, uint32_t id, uint32_t language);
	bool remove_resource(const std::wstring& root_name, uint32_t id, uint32_t language);
	
	//Adds resource. If resource already exists, replaces it
	//timestamp will be used for directories that will be added
	void add_resource(const std::string& data, resource_type type, const std::wstring& name, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);
	void add_resource(const std::string& data, const std::wstring& root_name, const std::wstring& name, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);
	//Adds resource. If resource already exists, replaces it
	//timestamp will be used for directories that will be added
	void add_resource(const std::string& data, resource_type type, uint32_t id, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);
	void add_resource(const std::string& data, const std::wstring& root_name, uint32_t id, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);

	//Adds bitmap from bitmap file data. If bitmap already exists, replaces it
	//timestamp will be used for directories that will be added
	void add_bitmap(const std::string& bitmap_file, uint32_t id, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);
	void add_bitmap(const std::string& bitmap_file, const std::wstring& name, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);

	//Removes icon group and all its icons by name/ID and language
	void remove_icon_group(const std::wstring& icon_group_name, uint32_t language);
	void remove_icon_group(uint32_t icon_group_id, uint32_t language);

	//Removes cursor group and all its cursors by name/ID and language
	void remove_cursor_group(const std::wstring& cursor_group_name, uint32_t language);
	void remove_cursor_group(uint32_t cursor_group_id, uint32_t language);

	//Removes bitmap by name/ID and language
	void remove_bitmap(const std::wstring& name, uint32_t language);
	void remove_bitmap(uint32_t id, uint32_t language);

	//Dtermines, how new icon(s) or cursor(s) will be placed
	enum icon_place_mode
	{
		icon_place_after_max_icon_id, //Icon(s) will be placed after all existing
		icon_place_free_ids //New icon(s) will take all free IDs between existing icons
	};

	//Adds icon(s) from icon file data
	//timestamp will be used for directories that will be added
	//If icon group with name "icon_group_name" or ID "icon_group_id" already exists, it will be appended with new icon(s)
	//(Codepage of icon group and icons will not be changed in this case)
	//icon_place_mode determines, how new icon(s) will be placed
	void add_icon(const std::string& icon_file, const std::wstring& icon_group_name, uint32_t language, icon_place_mode mode = icon_place_after_max_icon_id, uint32_t codepage = 0, uint32_t timestamp = 0);
	void add_icon(const std::string& icon_file, uint32_t icon_group_id, uint32_t language, icon_place_mode mode = icon_place_after_max_icon_id, uint32_t codepage = 0, uint32_t timestamp = 0);
	
	//Adds cursor(s) from cursor file data
	//timestamp will be used for directories that will be added
	//If cursor group with name "cursor_group_name" or ID "cursor_group_id" already exists, it will be appended with new cursor(s)
	//(Codepage of cursor group and cursors will not be changed in this case)
	//icon_place_mode determines, how new cursor(s) will be placed
	void add_cursor(const std::string& cursor_file, const std::wstring& cursor_group_name, uint32_t language, icon_place_mode mode = icon_place_after_max_icon_id, uint32_t codepage = 0, uint32_t timestamp = 0);
	void add_cursor(const std::string& cursor_file, uint32_t cursor_group_id, uint32_t language, icon_place_mode mode = icon_place_after_max_icon_id, uint32_t codepage = 0, uint32_t timestamp = 0);

	//Sets/replaces full version information:
	//file_version_info: versions and file info
	//lang_string_values_map: map of version info strings with encodings
	//translation_values_map: map of translations
	void set_version_info(const file_version_info& file_info, const lang_string_values_map& string_values, const translation_values_map& translations, uint32_t language, uint32_t codepage = 0, uint32_t timestamp = 0);

private:
	//Root resource directory. We're not copying it, because it might be heavy
	pe_base::resource_directory& root_dir_edit_;

	//Helper to remove resource
	bool remove_resource(const pe_base::resource_directory::entry_finder& root_finder, const pe_base::resource_directory::entry_finder& finder);

	//Helper to remove resource
	bool remove_resource(const pe_base::resource_directory::entry_finder& root_finder, const pe_base::resource_directory::entry_finder& finder, uint32_t language);

	//Helper to add/replace resource
	void add_resource(const std::string& data, resource_type type, pe_base::resource_directory_entry& new_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, uint32_t codepage, uint32_t timestamp);
	void add_resource(const std::string& data, const std::wstring& root_name, pe_base::resource_directory_entry& new_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, uint32_t codepage, uint32_t timestamp);
	void add_resource(const std::string& data, pe_base::resource_directory_entry& new_root_entry, const pe_base::resource_directory::entry_finder& root_finder, pe_base::resource_directory_entry& new_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, uint32_t codepage, uint32_t timestamp);

	//Add icon helper
	void add_icon(const std::string& icon_file, const resource_data_info* group_icon_info /* or zero */, pe_base::resource_directory_entry& new_icon_group_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp);
	
	//Add cursor helper
	void add_cursor(const std::string& cursor_file, const resource_data_info* group_cursor_info /* or zero */, pe_base::resource_directory_entry& new_cursor_group_entry, const pe_base::resource_directory::entry_finder& finder, uint32_t language, icon_place_mode mode, uint32_t codepage, uint32_t timestamp);

	//Remove icon group helper
	void remove_icons_from_icon_group(const std::string& icon_group_data, uint32_t language);

	//Remove cursor group helper
	void remove_cursors_from_cursor_group(const std::string& cursor_group_data, uint32_t language);

	//Returns free icon or cursor ID list depending on icon_place_mode
	const std::vector<uint16_t> get_icon_or_cursor_free_id_list(resource_type type, icon_place_mode mode, uint32_t count);
};


//Helper class to read version information
//lang_string_values_map: map of version info strings with encodings
//translation_values_map: map of translations
class version_info_viewer
{
public:
	//Useful typedefs
	typedef std::pair<uint16_t, uint16_t> translation_pair;
	typedef std::vector<std::wstring> translation_list;

public:
	//Default constructor
	//strings - version info strings with charsets
	//translations - version info translations map
	version_info_viewer(const pe_resource_viewer::lang_string_values_map& strings,
		const pe_resource_viewer::translation_values_map& translations);

	//Below functions have parameter translation
	//If it's empty, the default language translation will be taken
	//If there's no default language translation, the first one will be taken

	//Returns company name
	const std::wstring get_company_name(const std::wstring& translation = std::wstring()) const;
	//Returns file description
	const std::wstring get_file_description(const std::wstring& translation = std::wstring()) const;
	//Returns file version
	const std::wstring get_file_version(const std::wstring& translation = std::wstring()) const;
	//Returns internal file name
	const std::wstring get_internal_name(const std::wstring& translation = std::wstring()) const;
	//Returns legal copyright
	const std::wstring get_legal_copyright(const std::wstring& translation = std::wstring()) const;
	//Returns original file name
	const std::wstring get_original_filename(const std::wstring& translation = std::wstring()) const;
	//Returns product name
	const std::wstring get_product_name(const std::wstring& translation = std::wstring()) const;
	//Returns product version
	const std::wstring get_product_version(const std::wstring& translation = std::wstring()) const;

	//Returns list of translations in string representation
	const translation_list get_translation_list() const;

	//Returns version info property value
	//property_name - required property name
	//If throw_if_absent = true, will throw exception if property does not exist
	//If throw_if_absent = false, will return empty string if property does not exist
	const std::wstring get_property(const std::wstring& property_name, const std::wstring& translation = std::wstring(), bool throw_if_absent = false) const;

	//Converts translation HEX-string to pair of language ID and codepage ID
	static const translation_pair translation_from_string(const std::wstring& translation);

public:
	//Default process language, UNICODE
	static const std::wstring default_language_translation;

private:
	const pe_resource_viewer::lang_string_values_map& strings_;
	const pe_resource_viewer::translation_values_map& translations_;
};

//Helper class to read and edit version information
//lang_string_values_map: map of version info strings with encodings
//translation_values_map: map of translations
class version_info_editor : public version_info_viewer
{
public:
	//Default constructor
	//strings - version info strings with charsets
	//translations - version info translations map
	version_info_editor(pe_resource_viewer::lang_string_values_map& strings,
		pe_resource_viewer::translation_values_map& translations);
	
	//Below functions have parameter translation
	//If it's empty, the default language translation will be taken
	//If there's no default language translation, the first one will be taken

	//Sets company name
	void set_company_name(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets file description
	void set_file_description(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets file version
	void set_file_version(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets internal file name
	void set_internal_name(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets legal copyright
	void set_legal_copyright(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets original file name
	void set_original_filename(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets product name
	void set_product_name(const std::wstring& value, const std::wstring& translation = std::wstring());
	//Sets product version
	void set_product_version(const std::wstring& value, const std::wstring& translation = std::wstring());

	//Sets version info property value
	//property_name - property name
	//value - property value
	//If translation does not exist, it will be added to strings and translations lists
	//If property does not exist, it will be added
	void set_property(const std::wstring& property_name, const std::wstring& value, const std::wstring& translation = std::wstring());

	//Adds translation to translation list
	void add_translation(const std::wstring& translation);
	void add_translation(uint16_t language_id, uint16_t codepage_id);
	
	//Removes translation from translations and strings lists
	void remove_translation(const std::wstring& translation);
	void remove_translation(uint16_t language_id, uint16_t codepage_id);

private:
	pe_resource_viewer::lang_string_values_map& strings_edit_;
	pe_resource_viewer::translation_values_map& translations_edit_;
};
}
