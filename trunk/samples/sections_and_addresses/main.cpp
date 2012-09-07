#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� � �������� � PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: sections_and_addresses.exe PE_FILE" << std::endl;
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

		//������� ��� ������, � ������� ��������� ����� ����� PE-�����
		//� ������ PE-������ ����� ����� ����� ���������� � ���������, ����� section_from_rva ������ ����������
		std::cout << "EP section name: " << image->section_from_rva(image->get_ep()).get_name() << std::endl;
		//����� "�����" (raw) ������ ������
		std::cout << "EP section data length: " << image->section_data_length_from_rva(image->get_ep()) << std::endl;

		//���� � PE-����� ���� �������, ������� ��� ������, � ������� ��� ���������
		if(image->has_imports())
			std::cout << "Import section name: " << image->section_from_directory(IMAGE_DIRECTORY_ENTRY_IMPORT).get_name() << std::endl;
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
