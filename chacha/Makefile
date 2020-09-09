
all: known_answer_test


known_answer_test: known_answer_test.c chacha.c
	gcc -Wall -std=c99 -o$@ $^


.PHONY: clean
clean:
	rm -f known_answer_test

