CC = g++
CFLAGS = -Wall
DEBUG = -DDEBUG -g
COVERAGE = --coverage 

all: 
	python3 main.py

sample:
	python3 main.py test.txt

tcp:
	python3 main.py tcp2.txt

http:
	python3 main.py http.txt

clean:
	rm test.txt