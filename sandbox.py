from datetime import datetime, timedelta


t = timedelta(minutes=2)
a = datetime.now() + t
# if datetime.now() > a:
    # send mail
print(a)