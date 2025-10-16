// SPDX-License-Identifier: GPL-2.0-or-later

#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "get_value.h"

/* XXX check for failed strdup */

/* prompt the user with the name of the field being changed and the
   current value.
   return value:
   0   -> success
   < 0 -> error, -errno as code
   input argument:
   NULL  -> Ctrl-D was pressed
   ""    -> Field was cleard by user. User can enter a space or
            "none" to do this.
   def   -> User entered only <return>.
   input -> User entered something new . */
int
get_value(const char *def, const char *prompt, char **input)
{
  char buf[BUFSIZ];
  char *cp;

  *input = NULL;

  printf("\t%s [%s]: ", prompt, def);
  if (fgets(buf, sizeof(buf), stdin) != buf)
    {
      /* print newline to get defined output.  */
      printf("\n");
      return 0;
    }

  if ((cp = strchr(buf, '\n')) != NULL)
    *cp = '\0';

  if (buf[0]) /* something is entered */
    {
      /* if none is entered, return an empty string. If somebody
	 wishes to enter "none", he as to add a space.  */
      if(strcasecmp("none", buf) == 0)
	{
	  *input = strdup("");
	  return 0;
	}

      /* Remove leading and trailing whitespace. This also
	 makes it possible to change the field to empty or
	 "none" by entering a space.  */

      /* cp should point to the trailing '\0'.  */
      cp = &buf[strlen(buf)];

      while(--cp >= buf && isspace(*cp))
	;
      *++cp = '\0';

      cp = buf;
      while (*cp && isspace(*cp))
	cp++;
      *input = strdup(cp);
      return 0;
    }
  *input = strdup(def?:"");
  return 0;
}

#ifdef TEST
int
main (int argc, char **argv)
{
  char *cp;

  cp = get_value ("test", "t1");

  printf("cp=\"%s\"\n", cp);

  return 0;
}
#endif
