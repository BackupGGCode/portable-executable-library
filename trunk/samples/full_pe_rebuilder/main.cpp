#include <iostream>
#include <fstream>
#include <sstream>
#include <pe_factory.h>
#include <pe_32_64.h>
#ifdef PELIB_ON_WINDOWS
#include "lib.h"
#endif

using namespace pe_bliss;

//������, ������������, ��� � ���� ������� PE-����
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: image_config_editor.exe PE_FILE" << std::endl;
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
		//����� �����, ������� �� �������� �� ��������� � ����
		std::auto_ptr<pe_base> new_image;

		{
			//������� ��������� PE ��� PE+ ������ � ������� �������
			std::auto_ptr<pe_base> image = pe_factory::create_pe(pe_file);

			//������� ����� ������ �����
			new_image.reset(image->get_pe_type() == pe_base::pe_type_32
				? static_cast<pe_base*>(new pe32(image->get_section_alignment()))
				: static_cast<pe_base*>(new pe64(image->get_section_alignment())));

			//�������� ������ ��������� ������� ������ � �����
			new_image->set_characteristics(image->get_characteristics());
			new_image->set_dll_characteristics(image->get_dll_characteristics());
			new_image->set_file_alignment(image->get_file_alignment());
			new_image->set_heap_size_commit(image->get_heap_size_commit_64());
			new_image->set_heap_size_reserve(image->get_heap_size_reserve_64());
			new_image->set_stack_size_commit(image->get_stack_size_commit_64());
			new_image->set_stack_size_reserve(image->get_stack_size_reserve_64());
			new_image->set_image_base_64(image->get_image_base_64());
			new_image->set_ep(image->get_ep());
			new_image->set_number_of_rvas_and_sizes(new_image->get_number_of_rvas_and_sizes());
			new_image->set_subsystem(image->get_subsystem());

			//�������� ��� ������������ ����������
			for(unsigned long i = 0; i < image->get_number_of_rvas_and_sizes(); ++i)
			{
				new_image->set_directory_rva(i, image->get_directory_rva(i));
				new_image->set_directory_size(i, image->get_directory_size(i));
			}

			//�������� ������ ������
			{
				const pe_base::section_list& pe_sections = image->get_image_sections();
				for(pe_base::section_list::const_iterator it = pe_sections.begin(); it != pe_sections.end(); ++it)
					new_image->set_section_virtual_size(new_image->add_section(*it), (*it).get_virtual_size());
			}
		}


		//���������� ����������� ����� ������ PE-�����
		//� �������� �� (��� �������)
		{
			std::stringstream temp_pe(std::ios::out | std::ios::in | std::ios::binary);
			new_image->rebuild_pe(temp_pe);
			new_image->set_checksum(pe_base::calculate_checksum(temp_pe));
		}


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

		//������������ PE-���� �� ������ ������
		new_image->rebuild_pe(new_pe_file);

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
