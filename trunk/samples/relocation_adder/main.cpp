#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ����� ��������� � ������� ��������� PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: relocation_adder.exe PE_FILE" << std::endl;
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

		//���������� � ������� ��� ��������� ������ �� ������ ��������� � PE-�����
		//����� ���� �� ���������� ������ (ABSOLUTE) � �� �����������, ������� � ����� false
		//��� ������ ��� ����� �� �����
		pe_base::relocation_table_list tables = image->get_relocations(true);
		
		//������� ����� ������� ���������
		pe_base::relocation_table new_table;
		new_table.set_rva(0x5678); //������������� ����� ��������� � ������� - �� �����������, ��� �������, ������� ������������ PE ������ ����� �� ����������
		//������� � ������� ����� ���������
		new_table.add_relocation(pe_base::relocation_entry(10, 3)); //��� 3 - HIGHLOW-���������, RRVA = 10, �.�. RVA = 0x5678 + 10
		//��������� �������
		tables.push_back(new_table);

		//����� ������������� � ������������ ���������, �� ������ ����� �� �����, ��� ��� ���� �� ����������, ���� ���-�� � ��� ��������
		//���� �� ������� � EXE-����� ���������, �� ��� ����� ���������, � DLL ����� ������ �� �����
		//�� ������ ����������� ���������
		//��� ����� ����� ������� ������, ��� �� ������ ��������������,
		//������� ������� �� � ����� ������, ����� ��� �����������
		//(�� �� ����� ��������� ������������ ������, ���� ������ ������ �� � ����� ����� �����)
		pe_base::section new_relocs;
		new_relocs.get_raw_data().resize(1); //�� �� ����� ��������� ������ ������, ������� ����� � ��� ����� ��������� ������ ������ 1
		new_relocs.set_name("new_rel"); //��� ������
		new_relocs.readable(true); //�������� �� ������
		pe_base::section& attached_section = image->add_section(new_relocs); //������� ������ � ������� ������ �� ����������� ������ � ������������� ���������

		image->rebuild_relocations(tables, attached_section); //������������ ��������, ���������� �� � ������ ����� ������ � ������� ����� ������ ������ ��������� � PE-���������

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
