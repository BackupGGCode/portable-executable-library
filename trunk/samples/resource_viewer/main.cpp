#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include <pe_resource_manager.h>
#include "lib.h"

//������, ������������, ��� ������ ������� PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: resource_viewer.exe PE_FILE" << std::endl;
		return 0;
	}

	//��������� ����
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		//������� ��������� PE ��� PE+ ������ � ������� �������
		std::auto_ptr<pe_base> image = pe_factory::create_pe(pe_file);

		//��������, ���� �� ������� � �����
		if(!image->has_resources())
		{
			std::cout << "Image has no resources" << std::endl;
			return 0;
		}

		//�������� �������� ���������� ��������
		std::cout << "Reading PE resources..." << std::hex << std::showbase << std::endl << std::endl;
		const pe_base::resource_directory root = image->get_resources();

		//��� ���������� ������ � ������������ � �������� �������� ������� ��������������� ������
		//���� ����� ��������� ��������� �� PE-������ ����� �������
		//� ������������� ��������������� ������� ��� ��������� ������, ��������, ���������, ��������� ������
		//� ������ ���������, � ����� ���������� � ������
		pe_resource_viewer res(root);

		//������� ���� ��������, ������� ������������ � PE-�����
		pe_resource_viewer::resource_type_list res_types(res.list_resource_types());
		for(pe_resource_viewer::resource_type_list::const_iterator it = res_types.begin(); it != res_types.end(); ++it)
			std::cout << "Present resource type: " << (*it) << std::endl;

		std::cout << std::endl;

		//������� ���������� � ������, ���� ��� ����������
		if(res.resource_exists(pe_resource_viewer::resource_version))
		{
			pe_resource_viewer::lang_string_values_map strings;
			pe_resource_viewer::translation_values_map translations;
			//�������� ������ �����, ��������� � ������� ���������� � �����
			pe_resource_viewer::file_version_info file_info(res.get_version_info(strings, translations));

			//�������� ���������� ����� � ��������� �����
			std::wstringstream version_info;
			//������� ��������� ������� ����������
			version_info << L"Version info: " << std::endl;
			version_info << L"File version: " << file_info.get_file_version_string<wchar_t>() << std::endl; //������ ������ �����
			version_info << L"Debug build: " << (file_info.is_debug() ? L"YES" : L"NO") << std::endl; //���������� �� ����
			version_info << std::endl;

			//������� ������ ��� ������ ����������:
			for(pe_resource_viewer::lang_string_values_map::const_iterator it = strings.begin(); it != strings.end(); ++it)
			{
				version_info << L"Translation ID: " << (*it).first << std::endl;

				//���������� ������ � ������� ����� ��� ������� ���������� (��������)
				const pe_resource_viewer::string_values_map& string_table = (*it).second;
				for(pe_resource_viewer::string_values_map::const_iterator str_it = string_table.begin(); str_it != string_table.end(); ++str_it)
					version_info << (*str_it).first << L": " << (*str_it).second << std::endl;

				version_info << std::endl;
			}
			
			//������� ��������� �������� (����������):
			for(pe_resource_viewer::translation_values_map::const_iterator it = translations.begin(); it != translations.end(); ++it)
				version_info << L"Translation: language: " << (*it).first << ", codepage: " << (*it).second << std::endl;

			{
				//������� ����, � ������� ������� ���������� � ������
				std::ofstream version_info_file("version_info.txt", std::ios::out | std::ios::trunc | std::ios::binary);
				if(!version_info_file)
				{
					std::cout << "Cannot create file version_info.txt" << std::endl;
					return -1;
				}

				std::wstring version_info_string(version_info.str());
				//������� �����, ����� �� �������� � �������� � ������� ������� � ����
				version_info_file.write(reinterpret_cast<const char*>(version_info_string.data()), version_info_string.length() * sizeof(wchar_t));

				std::cout << "version_info.txt created" << std::endl << std::endl;
			}

			//��� ���������� ������ ���������� � ������ ���� ����������� �����
			version_info_viewer version_viewer(strings, translations);
			std::wcout << "Original filename: " << version_viewer.get_original_filename() << std::endl << std::endl;
		}

		{
			//������, ���� �� � ���������� ������
			//��� ����� ������� ������ ��� ����� � �������������� ����� ������
			//��� ������� � ����� ������������ � ����� ���� (������):
			//��� �������
			//--> ��� �������
			//----> ���� �������
			//------> ������
			//----> ���� �������
			//------> ������
			//----> ...
			//--> ��� �������
			//--> ...
			//--> id �������
			//----> ���� �������
			//------> ������
			//----> ���� �������
			//------> ������
			//----> ...
			//--> id �������
			//--> ...
			//��� �������
			//...
			pe_resource_viewer::resource_id_list icon_id_list(res.list_resource_ids(pe_resource_viewer::resource_icon_group));
			pe_resource_viewer::resource_name_list icon_name_list(res.list_resource_names(pe_resource_viewer::resource_icon_group));
			std::string main_icon; //������ ������ ����������
			//������� ������ ������������� ����������� �������, ������� ��������, ���� �� ���
			if(!icon_name_list.empty())
			{
				//������� ����� ������ ������ ��� ������ ������� ����� (�� ������� 0)
				//���� ���� ���� �� ����������� ����� ��� �������� ������, ����� ���� ������� list_resource_languages
				//���� ���� ���� �� �������� ������ ��� ����������� �����, ����� ���� ������� get_icon_by_name (���������� � ��������� �����)
				main_icon = res.get_icon_by_name(icon_name_list[0]);
			}
			else if(!icon_id_list.empty()) //���� ��� ����������� ����� ������, �� ���� ������ � ID
			{
				//������� ����� ������ ������ ��� ������ ������� ����� (�� ������� 0)
				//���� ���� ���� �� ����������� ����� ��� �������� ������, ����� ���� ������� list_resource_languages
				//���� ���� ���� �� �������� ������ ��� ����������� �����, ����� ���� ������� get_icon_by_id_lang
				main_icon = res.get_icon_by_id(icon_id_list[0]);
			}

			//���� ���� ������...
			if(!main_icon.empty())
			{
				//�������� ���������� ������ � ����
				std::ofstream app_icon("main_icon.ico", std::ios::out | std::ios::trunc | std::ios::binary);
				if(!app_icon)
				{
					std::cout << "Cannot create file main_icon.ico" << std::endl;
					return -1;
				}

				app_icon.write(main_icon.data(), main_icon.length());

				std::cout << "main_icon.ico created" << std::endl;
			}
		}

		{
			//������� ��������� �������
			//���������� �������������� ������������ ��������� ������
			pe_resource_viewer::resource_id_list strings_id_list(res.list_resource_ids(pe_resource_viewer::resource_string));

			//������� ����� � ��������� �����
			std::wstringstream string_data;

			if(!strings_id_list.empty()) //���� � ��� ���� ����������� ��������� �������, ������� ��
			{
				//��� ����� ��������� ������
				for(pe_resource_viewer::resource_id_list::const_iterator it = strings_id_list.begin(); it != strings_id_list.end(); ++it)
				{
					string_data << L"String table [" << (*it) << L"]" << std::endl;

					//���������� ����� �������
					pe_resource_viewer::resource_language_list langs(res.list_resource_languages(pe_resource_viewer::resource_string, *it));
					//��� ������� ����� ������� ������� �����
					for(pe_resource_viewer::resource_language_list::const_iterator lang_it = langs.begin(); lang_it != langs.end(); ++lang_it)
					{
						string_data << L" -> Language = " << *lang_it << std::endl; //������� ����
						//������� �����
						pe_resource_viewer::string_list strings(res.get_string_table_by_id_lang(*lang_it, *it));

						//�������, ������� ��� ������ � �����
						for(pe_resource_viewer::string_list::const_iterator str_it = strings.begin(); str_it != strings.end(); ++str_it)
							string_data << L" --> #" << (*str_it).first << L": " << (*str_it).second << std::endl; //ID ������: �� ��������
					}

					string_data << std::endl;
				}
				
				//������� ���������� ������ � ����
				std::ofstream strings_file("strings.txt", std::ios::out | std::ios::trunc | std::ios::binary);
				if(!strings_file)
				{
					std::cout << "Cannot create file strings.txt" << std::endl;
					return -1;
				}

				std::wstring strings_str(string_data.str());
				//������� �����, ����� �� �������� � �������� � ������� ������� � ����
				strings_file.write(reinterpret_cast<const char*>(strings_str.data()), strings_str.length() * sizeof(wchar_t));

				std::cout << "strings.txt created" << std::endl;
			}
		}
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
