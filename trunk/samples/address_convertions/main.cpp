#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������������� ������ ��� PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: address_convertions.exe PE_FILE" << std::endl;
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

		//�������� ������ ������
		std::cout << "Reading PE sections..." << std::hex << std::showbase << std::endl << std::endl;
		const pe_base::section_list sections = image->get_image_sections();

		//����������� ������ � ������� ���������� � ���
		for(pe_base::section_list::const_iterator it = sections.begin(); it != sections.end(); ++it)
		{
			const pe_base::section& s = *it; //������
			std::cout << "Section [" << s.get_name() << "]" << std::endl //��� ������
				<< " -> RVA: " << s.get_virtual_address() << std::endl //����������� ����� (RVA)
				<< " -> VA: " << image->rva_to_va_64(s.get_virtual_address()) << std::endl //����������� ����� (VA)
				<< " -> File offset: " << image->rva_to_file_offset(s.get_virtual_address()) //�������� �������� ������, ����������� �� �� RVA
				<< std::endl << std::endl;
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
