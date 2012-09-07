#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� ������� � �������� ���������� �� ��������� PE ��� PE+ �����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: exports_reader.exe PE_FILE" << std::endl;
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

		//��������, ���� �� �������� � PE-�����
		if(!image->has_exports())
		{
			std::cout << "Image has no exports" << std::endl;
			return 0;
		}

		std::cout << "Reading PE exports..." << std::hex << std::showbase << std::endl << std::endl;
		
		//�������� ������ ���������� �� ��������� � ������ �������������� �������
		pe_base::export_info info;
		const pe_base::exported_functions_list exports = image->get_exported_functions(info);

		//������� ��������� ���������� �� ��������:
		std::cout << "Export info" << std::endl
			<< "Library name: " << info.get_name() << std::endl //��� ����������
			<< "Timestamp: " << info.get_timestamp() << std::endl //��������� �����
			<< "Ordinal base: " << info.get_ordinal_base() << std::endl //���� ���������
			<< std::endl;

		//����������� ������ � ������� ���������� � ���
		for(pe_base::exported_functions_list::const_iterator it = exports.begin(); it != exports.end(); ++it)
		{
			const pe_base::exported_function& func = *it; //�������������� �������
			std::cout << "[+] ";
			if(func.has_name()) //���� ������� ����� ���, ������� ��� � ������� �����
				std::cout << func.get_name() << ", name ordinal: " << func.get_name_ordinal() << " ";

			//������� �������
			std::cout << "ORD: " << func.get_ordinal();
			
			//���� ������� - ������� (������������� � ������ DLL), ������� ��� ��������
			if(func.is_forwarded())
				std::cout << std::endl << " -> " << func.get_forwarded_name();

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
