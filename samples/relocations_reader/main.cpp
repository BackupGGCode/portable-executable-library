#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//Пример, показывающий, как считать и получить информацию о релокациях PE или PE+ файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: relocations_reader.exe PE_FILE" << std::endl;
		return 0;
	}

	//Открываем файл
	std::ifstream pe_file(argv[1], std::ios::in | std::ios::binary);
	if(!pe_file)
	{
		std::cout << "Cannot open " << argv[1] << std::endl;
		return -1;
	}

	try
	{
		//Создаем экземпляр PE или PE+ класса с помощью фабрики
		std::auto_ptr<pe_base> image = pe_factory::create_pe(pe_file);
		
		//Проверим, есть ли релокации у файла
		if(!image->has_reloc())
		{
			std::cout << "Image has no relocations" << std::endl;
			return 0;
		}

		std::cout << "Reading PE relocations..." << std::hex << std::showbase << std::endl << std::endl;

		//Получаем список таблиц релокаций
		const pe_base::relocation_table_list tables = image->get_relocations();

		//Перечисляем таблицы релокаций и выводим информацию о них
		for(pe_base::relocation_table_list::const_iterator it = tables.begin(); it != tables.end(); ++it)
		{
			const pe_base::relocation_table& table = *it; //Таблица релокаций
			std::cout << "RVA [" << table.get_rva() << "]" << std::endl //Относительный адрес
				<< "=========="
				<< std::endl;

			//Перечислим все релокации
			const pe_base::relocation_table::relocation_list& relocs = table.get_relocations();
			for(pe_base::relocation_table::relocation_list::const_iterator reloc_it = relocs.begin(); reloc_it != relocs.end(); ++reloc_it)
			{
				std::cout << "[+] " << (*reloc_it).get_item() << std::endl;
			}

			std::cout << std::endl;
		}
	}
	catch(const pe_exception& e)
	{
		//Если возникла ошибка
		std::cout << "Error: " << e.what() << std::endl;
		return -1;
	}

	return 0;
}
