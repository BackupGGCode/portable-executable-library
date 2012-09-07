#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� ������� � �������� ���������� �� �������� PE ��� PE+ �����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: imports_reader.exe PE_FILE" << std::endl;
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
		
		//��������, ���� �� ������� � �����
		if(!image->has_imports())
		{
			std::cout << "Image has no imports" << std::endl;
			return 0;
		}

		std::cout << "Reading PE imports..." << std::hex << std::showbase << std::endl << std::endl;

		//�������� ������ ������������� ��������� � ���������
		const pe_base::imported_functions_list imports = image->get_imported_functions();

		//����������� ��������������� ���������� � ������� ���������� � ���
		for(pe_base::imported_functions_list::const_iterator it = imports.begin(); it != imports.end(); ++it)
		{
			const pe_base::import_library& lib = *it; //������������� ����������
			std::cout << "Library [" << lib.get_name() << "]" << std::endl //���
				<< "Timestamp: " << lib.get_timestamp() << std::endl //��������� �����
				<< "RVA to IAT: " << lib.get_rva_to_iat() << std::endl //������������� ����� � import address table
				<< "========" << std::endl;

			//����������� ��������������� ������� ��� ����������
			const pe_base::import_library::imported_list& functions = lib.get_imported_functions();
			for(pe_base::import_library::imported_list::const_iterator func_it = functions.begin(); func_it != functions.end(); ++func_it)
			{
				const pe_base::imported_function& func = *func_it; //��������������� �������
				std::cout << "[+] ";
				if(func.has_name()) //���� ������� ����� ��� - ������� ���
					std::cout << func.get_name();
				else
					std::cout << "#" << func.get_ordinal(); //����� ��� ������������� �� ��������

				//����
				std::cout << " hint: " << func.get_hint() << std::endl;
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
