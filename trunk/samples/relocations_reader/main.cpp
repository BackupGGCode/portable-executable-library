#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� ������� � �������� ���������� � ���������� PE ��� PE+ �����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: relocations_reader.exe PE_FILE" << std::endl;
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
		
		//��������, ���� �� ��������� � �����
		if(!image->has_reloc())
		{
			std::cout << "Image has no relocations" << std::endl;
			return 0;
		}

		std::cout << "Reading PE relocations..." << std::hex << std::showbase << std::endl << std::endl;

		//�������� ������ ������ ���������
		const pe_base::relocation_table_list tables = image->get_relocations();

		//����������� ������� ��������� � ������� ���������� � ���
		for(pe_base::relocation_table_list::const_iterator it = tables.begin(); it != tables.end(); ++it)
		{
			const pe_base::relocation_table& table = *it; //������� ���������
			std::cout << "RVA [" << table.get_rva() << "]" << std::endl //������������� �����
				<< "=========="
				<< std::endl;

			//���������� ��� ���������
			const pe_base::relocation_table::relocation_list& relocs = table.get_relocations();
			for(pe_base::relocation_table::relocation_list::const_iterator reloc_it = relocs.begin(); reloc_it != relocs.end(); ++reloc_it)
			{
				std::cout << "[+] " << (*reloc_it).get_item() << std::endl;
			}

			std::cout << std::endl;
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
