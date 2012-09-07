#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� �������� ������� ���������� � PE-�����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: basic_info_viewer.exe PE_FILE" << std::endl;
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

		//������� ������������� �������� ��� PE-����� � ������� ��������� ������� ������,
		//�� ����� �������� ��� PE-����� � �������, ���������������� ����� �� ���������� ������� get_pe_type
		//����� �� ������ ������� ��� ��������� ��� PE-�����:
		std::cout << "PE file type: " << (image->get_pe_type() == pe_base::pe_type_32 ? "PE32 (PE)" : "PE64 (PE+)") << std::endl;
		
		//�������� ����������� ����� PE-�����
		std::cout << "Calculated checksum: "<< std::hex << std::showbase << pe_base::calculate_checksum(pe_file) << std::endl;
		//������� ����������� ����� �� ��������� ����� (��� ��-��������� ��� ������ ����� 0)
		std::cout << "Stored checksum: " << image->get_checksum() << std::endl;

		//������� �������������� PE-�����
		std::cout << "Characteristics: " << image->get_characteristics() << std::endl;
		
		//������� ����� ����� �����
		std::cout << "Entry point: " << image->get_ep() << std::endl;
		
		//������� ������������
		std::cout << "File alignment: " << image->get_file_alignment() << std::endl;
		std::cout << "Section alignment: " << image->get_section_alignment() << std::endl;
		
		//������� ���� ������ � 64-������ ���� (������������ ��� PE � PE+)
		std::cout << "Image base: " << image->get_image_base_64() << std::endl;
		
		//������� ����������
		std::cout << "Subsystem: " << image->get_subsystem() << std::endl;
		std::cout << "Is console: " << (image->is_console() ? "YES" : "NO") << std::endl;
		std::cout << "Is windows GUI: " << (image->is_gui() ? "YES" : "NO") << std::endl;
		
		//�������, ����� ���������� ���� � �����
		std::cout << "Has bound import: " << (image->has_bound_import() ? "YES" : "NO") << std::endl;
		std::cout << "Has config: " << (image->has_config() ? "YES" : "NO") << std::endl;
		std::cout << "Has debug: " << (image->has_debug() ? "YES" : "NO") << std::endl;
		std::cout << "Has delay import: " << (image->has_delay_import() ? "YES" : "NO") << std::endl;
		std::cout << "Has exception directory: " << (image->has_exception_directory() ? "YES" : "NO") << std::endl;
		std::cout << "Has exports: " << (image->has_exports() ? "YES" : "NO") << std::endl;
		std::cout << "Has imports: " << (image->has_imports() ? "YES" : "NO") << std::endl;
		std::cout << "Has reloc: " << (image->has_reloc() ? "YES" : "NO") << std::endl;
		std::cout << "Has resources: " << (image->has_resources() ? "YES" : "NO") << std::endl;
		std::cout << "Has security: " << (image->has_security() ? "YES" : "NO") << std::endl;
		std::cout << "Has tls: " << (image->has_tls() ? "YES" : "NO") << std::endl;
		std::cout << "Is .NET: " << (image->is_dotnet() ? "YES" : "NO") << std::endl;
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
