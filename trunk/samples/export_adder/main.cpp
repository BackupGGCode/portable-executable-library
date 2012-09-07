#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ����� ������� � ������� �������� PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: export_adder.exe PE_FILE" << std::endl;
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

		//������� ������ �������������� ������� � ���������� �� ��������
		pe_base::export_info info;
		pe_base::exported_functions_list exports;

		//���� ��������� � ����� ���, ���� ����� ������ ����������, �� ��� �� ������, ��� ��
		//�� ����� ������� ������� ��������� � ����
		try
		{
			exports = image->get_exported_functions(info);
		}
		catch(const pe_exception&)
		{
			//��� ������� ���������, ��� ��� ������
			//�������� ���������� �� ��������� �������
			info.set_name("MySuperLib.dll");
			info.set_ordinal_base(5);
		}

		//������� ����� �������������� �������
		pe_base::exported_function func;
		func.set_name("SuperKernelCall"); //��� �������������� �������
		func.set_rva(0x123); //������������� ����� ����� ����� �������������� ������� (������������, ����� ��� �������)

		//���������� ��������� ������� �������, ������� �� ���������, ����� �� ���� ���������
		//��� ����� ���� ��������������� �������
		func.set_ordinal(pe_base::get_export_ordinal_limits(exports).second + 1); //������� ��� ������� = ������������ ������� ����� ������������ ��������� + 1
		exports.push_back(func); //������� ������� � ���������
		
		//����� ������������� � ������������ ��������
		//��� �������� ���������� �� ��������� (info)
		//�� �� ������ ����������� ������� ���������
		//��� ����� ����� ������� ������, ��� �� ������ ��������������,
		//������� ������� �� � ����� ������, ����� ��� �����������
		//(�� �� ����� ��������� ������������ ������, ���� ������ ������ �� � ����� ����� �����)
		pe_base::section new_exports;
		new_exports.get_raw_data().resize(1); //�� �� ����� ��������� ������ ������, ������� ����� � ��� ����� ��������� ������ ������ 1
		new_exports.set_name("new_exp"); //��� ������
		new_exports.readable(true); //�������� �� ������
		pe_base::section& attached_section = image->add_section(new_exports); //������� ������ � ������� ������ �� ����������� ������ � ������������� ���������

		image->rebuild_exports(info, exports, attached_section); //������������ ��������, ���������� �� � ������ ����� ������ � ������� ����� ������ ������ �������� � PE-���������

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
