#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//������, ������������, ��� ������� � �������� ���������� � Image Config (������������ ������������ �����) PE ��� PE+
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: pe_config_reader.exe PE_FILE" << std::endl;
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

		std::cout << "Reading PE image config info..." << std::hex << std::showbase << std::endl << std::endl;
		
		//�������� ������������
		const pe_base::image_config_info info = image->get_image_config();

		//������� ������ ������������
		//��������� � ����� - � MSDN
		std::cout << "Critical section default timeout: " << info.get_critical_section_default_timeout() << std::endl
			<< "Decommit free block threshold: " << info.get_decommit_free_block_threshold() << std::endl
			<< "Decommit total free threshold: " << info.get_decommit_total_free_threshold() << std::endl
			<< "Global flags clear: " << info.get_global_flags_clear() << std::endl
			<< "Global flags set: " << info.get_global_flags_set() << std::endl
			<< "VA of lock table prefix: " << info.get_lock_prefix_table_va() << std::endl
			<< "Max allocation size: " << info.get_max_allocation_size() << std::endl
			<< "Process affinity mask: " << info.get_process_affinity_mask() << std::endl
			<< "Process heap flags: " << info.get_process_heap_flags() << std::endl
			<< "Security cookie VA: " << info.get_security_cookie_va() << std::endl
			<< "CSDVersion: " << info.get_service_pack_version() << std::endl
			<< "Timestamp: " << info.get_time_stamp() << std::endl
			<< "Virtual memory threshold: " << info.get_virtual_memory_threshold() << std::endl
			<< std::endl;

		//������� ������ SE-���������
		const pe_base::image_config_info::se_handler_list& se_handlers = info.get_se_handler_rvas();
		for(pe_base::image_config_info::se_handler_list::const_iterator it = se_handlers.begin(); it != se_handlers.end(); ++it)
			std::cout << "SE Handler: " << (*it) << std::endl;
	}
	catch(const pe_exception& e)
	{
		//���� �������� ������
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
