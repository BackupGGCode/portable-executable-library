#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� �������� ������ �� PE-����� � ����������� ���
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: pe_stripper.exe PE_FILE" << std::endl;
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
		
		//������ DOS stub � rich overlay
		image->strip_stub_overlay();

		//������ �������� DATA_DIRECTORY (�������)
		//����� ����� ���������� �������� ����� ��� ������
		image->strip_data_directories(0);

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

		//������������ PE-���� � ������ ������ DOS-header
		//���������� ������� ��� �� ����, �� ����������� NT-��������� � DOS-���������
		//��� ���������� ������������� ��������� �������� ������� ����� � ����� ����� ������,
		//� ���������� ���� ������ ������ ���������� ������� ������
		image->rebuild_pe(new_pe_file, true);
		
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
