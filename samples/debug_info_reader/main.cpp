#include <iostream>
#include <fstream>
#include <pe_factory.h>
#include "lib.h"

//Пример, показывающий, как считать и обработать отладочную информацию PE или PE+ файла
int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		std::cout << "Usage: debug_info_reader.exe PE_FILE" << std::endl;
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
		
		//Проверим, есть ли отладочная информация у файла
		if(!image->has_debug())
		{
			std::cout << "Image has no debug information" << std::endl;
			return 0;
		}

		std::cout << "Reading PE debug information..." << std::hex << std::showbase << std::endl << std::endl;

		//Получаем отладочную информацию, находящуюся в PE-файле
		const pe_base::debug_info_list info_list = image->get_debug_information();
		
		//Перечисоляем все отладочные записи
		for(pe_base::debug_info_list::const_iterator it = info_list.begin(); it != info_list.end(); ++it)
		{
			const pe_base::debug_info& info = *it;

			//Выведем тип отладочной информации
			std::cout << "Debug info type: ";
			switch(info.get_type())
			{
			case pe_base::debug_info::debug_type_borland:
				std::cout << "Borland";
				break;

			case pe_base::debug_info::debug_type_clsid:
				std::cout << "CLSID";
				break;

			case pe_base::debug_info::debug_type_codeview:
				std::cout << "CodeView";
				break;

			case pe_base::debug_info::debug_type_coff:
				std::cout << "COFF";
				break;

			case pe_base::debug_info::debug_type_exception:
				std::cout << "Exception";
				break;

			case pe_base::debug_info::debug_type_fixup:
				std::cout << "Fixup";
				break;

			case pe_base::debug_info::debug_type_fpo:
				std::cout << "FPO";
				break;

			case pe_base::debug_info::debug_type_misc:
				std::cout << "Misc";
				break;

			case pe_base::debug_info::debug_type_omap_from_src:
				std::cout << "OMAP from src";
				break;

			case pe_base::debug_info::debug_type_omap_to_src:
				std::cout << "OMAP to src";
				break;

			default:
				std::cout << "Unknown";
			}

			std::cout << std::endl;

			std::cout << "Timestamp: " << info.get_time_stamp() << std::endl << std::endl; //Временная метка

			//Получим дополнительную информацию, если таковая имеется
			switch(info.get_advanced_info_type())
			{
			case pe_base::debug_info::advanced_info_pdb_7_0:
				{
					std::cout << "Advanced info - PDB 7.0" << std::endl; //PDB 7.0
					pe_base::pdb_7_0_info advanced = info.get_advanced_debug_info<pe_base::pdb_7_0_info>();
					std::cout << "PDB file name: " << advanced.get_pdb_file_name() << std::endl; //Имя файла PDB
					std::cout << "Age: " << advanced.get_age() << std::endl; //Возраст (билд)
				}
				break;

			case pe_base::debug_info::advanced_info_pdb_2_0:
				{
					std::cout << "Advanced info - PDB 2.0" << std::endl; //PDB 2.0
					pe_base::pdb_2_0_info advanced = info.get_advanced_debug_info<pe_base::pdb_2_0_info>();
					std::cout << "PDB file name: " << advanced.get_pdb_file_name() << std::endl; //Имя файла PDB
					std::cout << "Age: " << advanced.get_age() << std::endl; //Возраст (билд)
				}
				break;

			case pe_base::debug_info::advanced_info_misc:
				{
					std::cout << "Advanced info - Misc" << std::endl; //Misc
					pe_base::misc_debug_info advanced = info.get_advanced_debug_info<pe_base::misc_debug_info>();
					std::cout << "Advanced data is EXE name: " << (advanced.is_exe_name() ? "YES" : "NO") << std::endl; //Если данные в структуре - имя EXE-файла

					//Выведем строковые данные
					if(advanced.is_unicode())
						std::wcout << advanced.get_data_unicode() << std::endl;
					else
						std::cout << advanced.get_data_ansi() << std::endl;
				}
				break;

			case pe_base::debug_info::advanced_info_coff:
				{
					std::cout << "Advanced info - COFF" << std::endl; //COFF
					pe_base::coff_debug_info advanced = info.get_advanced_debug_info<pe_base::coff_debug_info>();
					std::cout << "LVA to first line number: " << advanced.get_lva_to_first_line_number() << std::endl; //Адрес первого элемента в массиве номеров строк
					std::cout << "LVA to first symbol: " << advanced.get_lva_to_first_symbol() << std::endl; //Адрес первого элемента в массиве символов
					std::cout << "Number of line numbers: " << advanced.get_number_of_line_numbers() << std::endl; //Количество номеров строк
					std::cout << "Number of symbols: " << advanced.get_number_of_symbols() << std::endl; //Количество номеров строк
					std::cout << "RVA of first byte of code: " << advanced.get_rva_to_first_byte_of_code() << std::endl; //RVA первого байта кода
					std::cout << "RVA of first byte of data: " << advanced.get_rva_to_first_byte_of_data() << std::endl; //RVA первого байта данных
					std::cout << "RVA of last byte of code " << advanced.get_rva_to_last_byte_of_code() << std::endl; //RVA последнего байта кода
					std::cout << "RVA of last byte of data: " << advanced.get_rva_to_last_byte_of_data() << std::endl; //RVA последнего байта данных

					std::cout << std::endl << "Symbol list:" << std::endl;

					//Получим список символов
					const pe_base::coff_debug_info::coff_symbols_list& symbols = advanced.get_symbols();
					for(pe_base::coff_debug_info::coff_symbols_list::const_iterator symbol_it = symbols.begin(); symbol_it != symbols.end(); ++symbol_it)
					{
						//Выведем информацию об отладочных символах
						const pe_base::coff_debug_info::coff_symbol& symbol = *symbol_it; //Отладочный символ
						std::cout << "Index: " << symbol.get_index() << std::endl
							<< "RVA: " << symbol.get_rva() << std::endl
							<< "Section number: " << symbol.get_section_number() << std::endl
							<< "Storage class: " << symbol.get_storage_class() << std::endl
							<< "Type: " << symbol.get_type() << std::endl
							<< "Is file: " << (symbol.is_file() ? "YES" : "NO") << std::endl
							<< "Symbol: " << symbol.get_symbol() << std::endl << std::endl;
					}
				}
				break;

			case pe_base::debug_info::advanced_info_codeview_4_0:
				std::cout << "Advanced info - CodeView 4.0" << std::endl; //CodeView 4.0
				break;

			case pe_base::debug_info::advanced_info_codeview_5_0:
				std::cout << "Advanced info - CodeView 5.0" << std::endl; //CodeView 5.0
				break;
			}

			std::cout << std::endl << "==========" << std::endl << std::endl;
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
