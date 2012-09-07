#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ����� ������ � ������� ������� PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: import_adder.exe PE_FILE" << std::endl;
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

		//������� ������ ������������� ��������� � �������
		pe_base::imported_functions_list imports = image->get_imported_functions();

		//�������� ����� ����������, �� ������� ����� ������������� �������
		pe_base::import_library new_lib;
		new_lib.set_name("kaimi_dx.dll"); //����� ��� ����� testdll.dll

		//������� � ��� ���� �������� �������
		pe_base::imported_function func;
		func.set_name("Tralala"); //���� ������ - �� ����� Tralala
		func.set_iat_va(0x1); //������� ��������� ���������� ����� import address table

		pe_base::imported_function func2;
		func2.set_ordinal(5); //������ ������ - �� �������� 5
		func2.set_iat_va(0x2); //������� ��������� ���������� ����� import address table

		//�� ������� ������������ ������ (0x1 � 0x2) ��� �����, � ������� ����� �������� ������ ������������� �������
		//��� ������� ��� �������, � ���������� ������ ���� ������� ������������ ������

		//������� �������
		new_lib.add_import(func);
		new_lib.add_import(func2);
		imports.push_back(new_lib); //������� ��������������� ���������� � ��������

		//����� ������������� � ������������ �������

		//�� �� ������ ����������� ������� ��������
		//��� ����� ����� ������� ������, ��� �� ������ ��������������,
		//������� ������� �� � ����� ������, ����� ��� �����������
		//(�� �� ����� ��������� ������������ ������, ���� ������ ������ �� � ����� ����� �����)
		pe_base::section new_imports;
		new_imports.get_raw_data().resize(1); //�� �� ����� ��������� ������ ������, ������� ����� � ��� ����� ��������� ������ ������ 1
		new_imports.set_name("new_imp"); //��� ������
		new_imports.readable(true).writeable(true); //�������� �� ������ � ������
		pe_base::section& attached_section = image->add_section(new_imports); //������� ������ � ������� ������ �� ����������� ������ � ������������� ���������

		//���������, ���������� �� ��������� ������������ ��������
		pe_base::import_rebuilder_settings settings(true, true); //����� ������������ ��������� PE � ������� ���� IMAGE_DIRECTORY_ENTRY_IAT
		image->rebuild_imports(imports, attached_section, settings); //������������ �������

		//������� ����� PE-����
		std::string base_file_name(argv[1]);
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
