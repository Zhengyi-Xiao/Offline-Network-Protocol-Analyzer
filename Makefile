CC = g++
CFLAGS = -Wall
DEBUG = -DDEBUG -g
COVERAGE = --coverage 

sample:
	python3 main.py test.txt

clean:
	rm *.txt