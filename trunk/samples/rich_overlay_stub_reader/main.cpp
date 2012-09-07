#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ���������� � ����� PE-����� � rich overlay, ������� ��������� ��� ���������� MS Visual Studio
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: rich_overlay_stub_reader.exe PE_FILE" << std::endl;
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

		//������� ����� DOS stub'�
		std::cout << "Image stub length: " << image->get_stub_overlay().length() << std::endl << std::endl;

		//����������� ��� RICH-������
		pe_base::rich_data_list data = image->get_rich_data();
		for(pe_base::rich_data_list::const_iterator it = data.begin(); it != data.end(); ++it)
		{
			//������� ���������� � ������
			std::cout << "Number: " << (*it).get_number() << std::endl
				<< "Times: " << (*it).get_times() << std::endl
				<< "Version: " << (*it).get_version() << std::endl
				<< std::endl;
		}

		//��������� ���������� � ���, ���� �� � ����� ������� � ����� (� ��������� �������������, ��������, ����)
		std::cout << "Has overlay in the end: " << (image->has_overlay() ? "YES" : "NO") << std::endl;
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
