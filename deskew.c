/*
 * Copyright 2012 Giorgio Vazzana
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Compile: gcc -Wall -O deskew.c -o deskew

#include <stdio.h>

int main(int argc, char *argv[])
{
	int c1, c2;

	while (1) {
		c1 = fgetc(stdin);
		c2 = fgetc(stdin);

		if (c1 == EOF || c2 == EOF)
			break;

		if (c1 == '0' && c2 == '1')
			printf("0");
		else if (c1 == '1' && c2 == '0')
			printf("1");
	}

	return 0;
}
