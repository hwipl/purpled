# Set project name
OUT     = purpled

# Set path configuration
INCDIR  =
SRCDIR  =
OBJDIR  =
LIBDIR  =

# Set commands
CC      = @cc
RM      = @rm -f

# Set compilation flags
CFLAGS  = -g -O2 -Wfatal-errors -Wall -Wstrict-prototypes `pkg-config --cflags glib-2.0` `pkg-config --cflags purple`
LDFLAGS = `pkg-config --libs   glib-2.0` `pkg-config --libs   purple`

# Getting files in directories
INC     = defines.h config.h
SRC     = purpled.c
OBJ     = $(SRC:.c=.o)
LIB     =


# Setting paths for prerequisites
VPATH   = $(SRCDIR):$(OBJDIR):$(INCDIR)

# Setting default target (i.e. project name)
$(OUT)  : $(OBJ)
	@echo "- linking of: $@"
	$(CC) $(addprefix $(OBJDIR), $(OBJ)) -o $@ $(addprefix $(LIBDIR), $(LIB)) $(LDFLAGS)

# Rewritting objects compilation rule
%.o     : %.c $(INC)
	@echo "- compilation of: $@"
	$(CC) -c $(addprefix $(SRCDIR), $(@:.o=.c)) -o $(addprefix $(OBJDIR), $@) -I $(INCDIR) $(CFLAGS)

# Generals targets
.PHONY  : all clean fclean re

all     : $(OUT)

clean   :
	@echo "- cleaning objects directory"
	$(RM) $(addprefix $(OBJDIR), $(OBJ))
	$(RM) *~

fclean  : clean
	@echo "- erasing project: $(OUT)"
	$(RM) @rm -f $(OUT)

re      : fclean all

