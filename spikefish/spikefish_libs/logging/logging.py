# This file is part of Pointix
# Copyright (C) 2020 Spikefish Solutions

# Pointix is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Pointix is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Pointix.  If not, see <https://www.gnu.org/licenses/>.

from datetime import datetime
from module import severeHandle

#There should be a python module name 'module.py' in the main program directory that contains severeHandle()
#This way the exit handling can be specific to each program


def logging(level, message, function, e=0):

    loggingFile = open("logging.txt", "a")
    severity = {'1': 'Severe', '2': 'Warning', '3': 'Informative'}

    loggingFile.write(f'{datetime.now()}: {severity[level]} - {message} - in {function}\n')

    if severity[level] == 'Warning':
        if e != 0:
            loggingFile.write(str(e) + '\n')
        loggingFile.close()
        return()
    elif severity[level] == 'Severe':
        if e != 0:
            loggingFile.write(str(e) + '\n')
        loggingFile.close()
        severeHandle()
    else:
        loggingFile.close()
        return()