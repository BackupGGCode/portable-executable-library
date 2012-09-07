#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ������� ���������� � .NET PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: basic_dotnet_viewer.exe PE_FILE" << std::endl;
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

		//���� ����� �� .NET, �������
		if(!image->is_dotnet())
		{
			std::cout << "Image is not .NET" << std::endl;
			return 0;
		}
		
		std::cout << "Reading basic dotnet info..." << std::hex << std::showbase << std::endl << std::endl;
		
		//�������� .NET-��������� PE-�����
		const pe_base::basic_dotnet_info info(image->get_basic_dotnet_info());

		//������� ��������� ����������
		std::cout << "Major runtime version: " << info.get_major_runtime_version() << std::endl //������ ��������
			<< "Minor runtime version: " << info.get_minor_runtime_version() << std::endl
			<< "Flags: " << info.get_flags() << std::endl //�����
			<< "RVA of resources: " << info.get_rva_of_resources() << std::endl //RVA ��������
			<< "RVA of metadata: " << info.get_rva_of_metadata() << std::endl //RVA ����������
			<< "Size of resources: " << info.get_size_of_resources() << std::endl //������ ��������
			<< "Size of metadata: " << info.get_size_of_metadata() << std::endl; //������ ����������

		//��������� ����� ����� .NET
		if(info.is_native_entry_point())
			std::cout << "Entry point RVA: ";
		else
			std::cout << "Entry point token: ";

		std::cout << info.get_entry_point_rva_or_token() << std::endl;
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
