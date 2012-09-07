#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� ������������� TLS (Thread Local Storage) � PE-������
int main(int argc, char* argv[])
{
	/*
	if(argc != 2)
	{
		std::cout << "Usage: tls_editor.exe PE_FILE" << std::endl;
		return 0;
	}
	*/

	//��������� ����
	argv[1] = "../../../mimimi/tests/Project1orig.exe";
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

		//������� ���������� � TLS PE-�����
		//���� TLS ���, ���� ����� �������� ����������
		pe_base::tls_info info = image->get_tls_info();
		
		//����������� TLS
		//��, ��������, ����� ����� ������� ������, ��� �� ������ ��������������,
		//������� ������� ��� � ����� ������, ����� ��� �����������
		//(�� �� ����� ��������� ������������ ������, ���� ������ ������ �� � ����� ����� �����)
		pe_base::section new_tls;
		new_tls.get_raw_data().resize(1); //�� �� ����� ��������� ������ ������, ������� ����� � ��� ����� ��������� ������ ������ 1
		new_tls.set_name("new_tls"); //��� ������
		new_tls.readable(true); //�������� �� ������
		pe_base::section& attached_section = image->add_section(new_tls); //������� ������ � ������� ������ �� ����������� ������ � ������������� ���������

		if(info.get_callbacks_rva() != 0) //���� � TLS ���� ���� �� ���� �������
			info.add_tls_callback(0x100); //������� ����� ������� � TLS - ������������� �����, ������ �����, �����������, ������� ��������� �� ���������� (������ ��� �������)

		info.set_raw_data("Hello, world!"); //��������� ��� ������� "�����" ������ TLS
		info.set_raw_data_start_rva(image->rva_from_section_offset(attached_section, 0)); //���������� �� � ������ ����������� ������
		info.recalc_raw_data_end_rva(); //���������� ����� �������� ����� "�����" ������

		//������������ TLS, ���������� �� � 50-�� ����� (����� ���������, ������ ����� ������������� ���������) ����� ������ � ������� ����� ������ TLS � PE-���������
		//�� ��������� ������� ������������ ����� TLS-�������� � "�����" ������ TLS, ���������� �� �� ��������� � ��������� info �������
		//����� expand ��������� ������, ��� ������ ������������� "�����" ������
		//tls_data_expand_raw ��������� ��������� "�����" ������ ������, �� ���� ������ � �����
		//tls_data_expand_virtual ��������� ��������� ����������� ������ ������ � ������� TLS
		//���� �� ������ ����� ��� ������ TLS, ����� �������� ������ �� �����, ��� ������ ������ �������� �� �����
		image->rebuild_tls(info, attached_section, 50); 

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
