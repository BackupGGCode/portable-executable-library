#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include <pe_resource_manager.h>
#include "resource.h"
#include "lib.h"

//������, ������������, ��� ������������� ������� PE-�����
//��� ������ ������������� ������������ � �������� resource_viewer
//�������� ��������, ��� ������ ��������� ���������� � � x86, � � x64 ��������
int main(int argc, char* argv[])
{
	//��������� ���� (���� ����)
	std::ifstream pe_file(argv[0], std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << argv[0] << std::endl;
		return -1;
	}

	try
	{
		//������� ��������� PE ��� PE+ ������ � ������� �������
		std::auto_ptr<pe_base> image = pe_factory::create_pe(pe_file);

		//���� ������� ����� �������� � ���������:
		//� ��� ������ �������������� ������ � ���������� � ������ CUSTOM
		//������ ������� �� ���� �������� ������ ����������
		//���� ������ - ������� ������ �� ���������� CUSTOM � ���������� �� ��� ������� ������ exe-�����
		//����� - ������� ���������� CUSTOM
		//�������, �������� �����-������ ���������� � ������ � �����

		//��������, ���� �� ������� � �����
		if(!image->has_resources())
		{
			std::cout << "Image has no resources" << std::endl;
			return 0;
		}

		//�������� �������� ���������� ��������
		std::cout << "Reading PE resources..." << std::hex << std::showbase << std::endl << std::endl;
		pe_base::resource_directory root = image->get_resources();

		//��� ���������� ������ � ������������ � �������� �������� ������� ��������������� ������
		//���� ����� ��������� ��������� �� PE-������ ����� ������� � �������������� ��
		//� ������������� ��������������� ������� ��� ��������� ������, ��������, ���������, ��������� ������
		//� ������ ���������, � ����� ���������� � ������
		//� �������������� ������, ��������, �������� � ���������� � ������
		pe_resource_manager res(root);

		//��� ������ ��������, ��� ���������� CUSTOM ����
		if(!res.resource_exists(L"CUSTOM"))
		{
			std::cout << "\"CUSTOM\" resource directory does not exist" << std::endl;
			return -1;
		}

		//������� ���� ������ �� ���� ����������: �� �����, ��� �� ID=100 � ��� ���� � ���������� ����, ������� ������ ���
		//�������� �� �� �������� ������� (����� ���� �������� �� �����, �� ��� �������, �.�. ��� ������������)
		const pe_resource_viewer::resource_data_info data = res.get_resource_data_by_id(L"CUSTOM", IDR_CUSTOM1);

		//���������� ������ �������� �� ��� ������� ������
		//������ ���������� - ��� ������ �� ��� ������ ������, ������� ������� ����� ������ � ������ ����� ������
		//�������, ��� ������� ���� ����������� �������, � ����� ������� � ����������������, � �� �����������
		//�������� ������ ������ � ������ MAIN_ICON
		res.add_icon(data.get_data(), //������ ����� ������
			L"MAIN_ICON", //��� ������ ������ (�������, � ��� ��� �������� ������ ������, ��� ����� ���������� � ���� ������)
			0, //���� - ��� �������
			pe_resource_manager::icon_place_after_max_icon_id, //������� ������������ ������ � ������������ ������ - ��� �� �������, ��� ��� �� ������� ����� ������
			data.get_codepage(), //�������� �������� Codepage
			0 //Timestamp - �������
			);
		
		//������ ������ ��� �������� ���������� CUSTOM
		res.remove_resource(L"CUSTOM");
		
		//������ �������� ���������� � ������
		pe_resource_viewer::file_version_info file_info; //������� ���������� � �����
		file_info.set_special_build(true); //��� ����� ����������� ����
		file_info.set_file_os(pe_resource_viewer::file_version_info::file_os_nt_win32); //�������, �� ������� �������� ����
		file_info.set_file_version_ms(0x00010002); //������ ����� ����� 1.2.3.4
		file_info.set_file_version_ls(0x00030004);

		//������ �������� ������ � ����������� � ���������� (��������)
		pe_resource_viewer::lang_string_values_map strings;
		pe_resource_viewer::translation_values_map translations;

		//��� ������ �� �������� � ������������ ���� ��������������� �����
		version_info_editor version(strings, translations);
		//������� ���������� - default process language, UNICODE
		//����� ������� � ���������� ���� � ���������
		version.add_translation(version_info_editor::default_language_translation);
		//������ ����� ��������������� ��� ��������� ��������� (default_language_translation)
		//���� ����� ���, �� ��� ������ ���������
		//���� ������ ��� �� ����� ����������, �� ����� ��������� ��������� (default_language_translation)
		//����� �������, ���������� ����� add_translation ����� ���� �� ��������
		//� ���: ������������� ������������� ��� ��������� ������, ��� ������� ����
		version.set_company_name(L"Kaimi.ru DX"); //��� ��������-�������������
		version.set_file_description(L"Generated file version info"); //�������� �����
		version.set_internal_name(L"Tralala.exe"); //���������� ��� �����
		version.set_legal_copyright(L"(C) DX Portable Executable Library"); //��������
		version.set_original_filename(L"resource_editor.exe"); //������������ ��� �����
		version.set_product_name(L"PE Resource Editor Example"); //��� ��������
		version.set_product_version(L"x.y.z"); //������ ��������

		//����� ����� �������� ���� ����������� ������: ��� ����� ��������� � ���������� � ������,
		//�� Windows Explorer ���� �� �� ��������� � ��������� �����
		version.set_property(L"MyLittleProperty", L"Secret Value");

		//��������� ���������� � ������
		res.set_version_info(file_info, strings, translations, 1033); //1033 - ������� ����
		
		//�������� ������������� ������ ������ ��������
		//��� ���������� .rsrc
		//�������������� ���������� ��� ����, ����� Windows Explorer ���� ������� �� ����� ������ ������
		image->section_from_directory(IMAGE_DIRECTORY_ENTRY_RESOURCE).set_name("oldres");

		//����������� �������
		//��� ����� ����� ������� ������, ��� �� ������ ��������������,
		//������� ������� �� � ����� ������, ����� ��� �����������
		//(�� �� ����� ��������� ������������ ������, ���� ������ ������ �� � ����� ����� �����)
		pe_base::section new_resources;
		new_resources.get_raw_data().resize(1); //�� �� ����� ��������� ������ ������, ������� ����� � ��� ����� ��������� ������ ������ 1
		new_resources.set_name(".rsrc"); //��� ������
		new_resources.readable(true); //�������� �� ������
		pe_base::section& attached_section = image->add_section(new_resources); //������� ������ � ������� ������ �� ����������� ������ � ������������� ���������
		
		//������ ����������� �������, ���������� �� � ����� ������ ����� ������ � �������� PE-���������, ������� ���� ����� ��������� ���������� ��������
		image->rebuild_resources(root, attached_section);
		
		//������� ����� PE-����
		std::string base_file_name(argv[0]);
		std::string::size_type slash_pos;
		if((slash_pos = base_file_name.find_last_of("/\\")) != std::string::npos)
			base_file_name = base_file_name.substr(slash_pos + 1);

		base_file_name = "new_" + base_file_name;
		std::ofstream new_pe_file(base_file_name.c_str(), std::ios::out | std::ios::binary | std::ios::trunc);
		if(!new_pe_file)
		{
			std::cout << "Cannot create " << base_file_name << std::endl;
			return -1;
		}

		//������������ PE-����
		image->rebuild_pe(new_pe_file);

		std::cout << "PE was rebuilt and saved to " << base_file_name << std::endl;
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
