OWLURL=https://haltp.org/files/ol-0.1.23.c.gz

sure: main
	./main foo bar baz | grep "2e2f6d61696e 666f6f 626172 62617a"
	# everything seems to be in order

main: main.c
	cc -O -o main main.c

ol.c:
	curl $(OWLURL) | gzip -d > ol.c

ol: ol.c
	cc -O -o ol ol.c

main.c: ol main.scm core.scm
	./ol -o main.c main.scm

clean:
	-rm main main.c

mrproper: clen
	-rm ol ol.c

.phony: sure clean 
