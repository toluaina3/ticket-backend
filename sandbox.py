import requests



def send_simple_message():
	return requests.post(
		"https://api.mailgun.net/v3/mail.bigbot.ng/messages",
		auth=("api", "6594095f0c4e08de274388f898138e8e-e5da0167-1a2144af"),
		data={"from": "Excited User <mailgun@bigbot.ng>",
			"to": ["toluaina3@gmail.com", "support@bigbot.ng"],
			"subject": "Hello",
			"text": "Testing some Mailgun awesomness!"})


print(send_simple_message())