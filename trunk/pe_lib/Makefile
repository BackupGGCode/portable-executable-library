OBJS = pe_base.o pe_32_64.o pe_factory.o pe_resource_manager.o pe_exception.o
LIBNAME = pebliss
LIBPATH = ../lib
CXXFLAGS = -O2 -Wall -fPIC -DPIC -I.

ifdef PE_DEBUG
CXXFLAGS  += -g -O0
endif

all: $(LIBPATH)/lib$(LIBNAME).a

clean:
	rm -f $(OBJS) lib$(LIBNAME).a
	rm -rf ../lib

lib$(LIBNAME).a: $(OBJS)
	ar -cvr lib$(LIBNAME).a $(OBJS)
	ranlib lib$(LIBNAME).a

$(LIBPATH):
	mkdir -p ../lib

$(LIBPATH)/lib$(LIBNAME).a: lib$(LIBNAME).a $(LIBPATH)
	cp -d lib$(LIBNAME).a ../lib
