.PHNOY : install

uoj_run : run_program_conf.h run_program_sandbox.h run_program.cpp uoj_run.h
	g++ run_program.cpp -o uoj_run -O2 -lseccomp -pthread

install : uoj_run
	cp uoj_run /usr/bin/
