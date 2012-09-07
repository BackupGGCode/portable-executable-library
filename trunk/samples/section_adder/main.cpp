#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ������ � PE-���� � �������� � ��� �����-������ ������
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: section_adder.exe PE_FILE" << std::endl;
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
		
		//������ ����� �������� ������ ����� ���� ������������, ����� PE-���� �� ����������
		//������� ����� ������
		pe_base::section new_section;
		new_section.readable(true).writeable(true); //������ ������ ��������� ��� ������ � ������
		new_section.set_name("kaimi.ru"); //������ ��� ������ - �������� 8 ��������
		new_section.set_raw_data("Tralala"); //������������� ������ ������

		//��������� ������. ��� ������ ������������� �������������
		//����� ������ ������ �� ��� ����������� ������ � �������������� ��������
		//������ ������ ������ � ������ �������� ������, � ��� ������ ���� ��������� ������ ������ ��� ����������� ������
		pe_base::section& added_section = image->add_section(new_section);

		//���� ����� �������� ����������� ������ ������, �� �������� ��� ���:
		image->set_section_virtual_size(added_section, 0x1000);
		
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
