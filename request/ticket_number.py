import random
import string
import time


def ticket_number(size=4, chars=string.ascii_uppercase + string.digits):
    generate = str('TCK' + (str(time.ctime()[22:])) + (str(time.ctime()[4:][:4].upper())) \
                   + ''.join(random.choice(chars) for _ in range(size)))
    return generate.replace(' ', '')

