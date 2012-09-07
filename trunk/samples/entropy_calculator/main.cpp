#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� ��������� �������� ����� � ������ PE
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: entropy_calculator.exe PE_FILE" << std::endl;
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
		//������� �������� �����
		std::cout << "File entropy: " << pe_base::calculate_entropy(pe_file) << std::endl;

		//������� ��������� PE ��� PE+ ������ � ������� �������
		std::auto_ptr<pe_base> image = pe_factory::create_pe(pe_file);

		std::cout << "Sections entropy: " << image->calculate_entropy() << std::endl; //������� �������� ���� ������

		//����������� ������ � ������� �� �������� �� �����������
		const pe_base::section_list sections = image->get_image_sections();
		for(pe_base::section_list::const_iterator it = sections.begin(); it != sections.end(); ++it)
		{
			if(!(*it).empty()) //���� ������ �� ����� - ��������� �� ��������
				std::cout << "Section [" << (*it).get_name() << "] entropy: " << pe_base::calculate_entropy(*it) << std::endl;
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
