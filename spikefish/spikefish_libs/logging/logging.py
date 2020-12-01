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