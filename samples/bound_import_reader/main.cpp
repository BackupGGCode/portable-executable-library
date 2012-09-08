#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//Пример, показывающий, как считать и получить информацию о привязанном импорте PE-файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: bound_import_reader.exe PE_FILE" << std::endl;
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
		
		//Проверим, есть ли привязанный импорт у PE-файла
		if(!image->has_bound_import())
		{
			std::cout << "Image has no bound import" << std::endl;
			return 0;
		}

		std::cout << "Reading PE bound import..." << std::hex << std::showbase << std::endl << std::endl;
		
		//Получаем информацию о привязанном импорте
		const pe_base::bound_import_module_list modules = image->get_bound_import_module_list();

		//Выведем импортируемые модули и форварды
		for(pe_base::bound_import_module_list::const_iterator it = modules.begin(); it != modules.end(); ++it)
		{
			const pe_base::bound_import& import = *it; //Импортируемая библиотека
			std::cout << "Module: " << import.get_module_name() << std::endl //Имя модуля
				<< "Timestamp: " << import.get_timestamp() << std::endl; //Временная метка

			//Перечислим форварды для модуля - модули, на которые ссылается этот:
			const pe_base::bound_import::ref_list& refs = import.get_module_ref_list();
			for(pe_base::bound_import::ref_list::const_iterator ref_it = refs.begin(); ref_it != refs.end(); ++ref_it)
			{
				std::cout << " -> Module: " << (*ref_it).get_module_name() << std::endl //Имя модуля, на который ссылается родительский модуль
					<< " -> Timestamp: " << (*ref_it).get_timestamp() << std::endl; //Временная метка
			}
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
