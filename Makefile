# INFO8012: Digital Forensics
#   Lab 4 - File System Analysis
#
# By:
#      BOONEN Antoine
#      MATAIGNE Florian
#
# Date:
#      14/05/2021

TARGET=fileslack

CC=gcc
CFLAGS=-Wall -Wextra -Wshadow -Wmissing-prototypes
LFLAGS=-Wall -Wextra -Wshadow -Wmissing-prototypes

OBJ=fileslack.o

.PHONY: clean clean-all

################## RULES ##################

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LFLAGS) -o $(TARGET) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

################# CLEANERS ################

clean:
	rm -f *.o

clean-all: clean
	rm -f $(TARGET)

################### END ###################
