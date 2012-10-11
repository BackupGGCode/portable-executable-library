TARGETS = pe_bliss samples_pack
TARGETS_CLEAN = pe_clean samples_clean

all: $(TARGETS)

clean: $(TARGETS_CLEAN)

pe_bliss:
	$(MAKE) PE_DEBUG=$(PE_DEBUG) -C ./pe_lib

samples_pack: pe_bliss
	$(MAKE) PE_DEBUG=$(PE_DEBUG) -C ./samples

pe_clean:
	$(MAKE) -C ./pe_lib clean

samples_clean:
	$(MAKE) -C ./samples clean

