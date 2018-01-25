import sys
import smtplib
from email.mime.text import MIMEText
from email.utils import formatdate

# Change from address, password, to address
FROM_ADDRESS = 'sender@example.com'
MY_PASSWORD = 'sender_password'
TO_ADDRESS = 'receiver@example.com'
BCC = ''
SUBJECT = 'Indicator_matched'


class Send_alert:

    def create_message(self,from_addr, to_addr, bcc_addrs, subject, malURL, URL, src):
        malURL = malURL.replace('.','[.]')
        URL = URL.replace('.','[.]')
        body = 'Proxy log matched with indicator: ' + malURL + '\n' + URL + '\n' + 'Source IP:' + src
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to_addr
        msg['Bcc'] = bcc_addrs
        msg['Date'] = formatdate()
        return msg


    def send(self,from_addr, to_addrs, msg):
        ssmtpobj = smtplib.SMTP('smtp.gmail.com', 587)
        ssmtpobj.ehlo()
        ssmtpobj.starttls()
        ssmtpobj.ehlo()
        ssmtpobj.login(FROM_ADDRESS, MY_PASSWORD)
        ssmtpobj.sendmail(from_addr, to_addrs, msg.as_string())
        ssmtpobj.close()
        print('Send alert mail!')

    def alert(self, malURL, URL, src):
        to_addr = TO_ADDRESS
        subject = SUBJECT
        msg = self.create_message(FROM_ADDRESS, to_addr, BCC, subject, malURL, URL, src)
        self.send(FROM_ADDRESS, to_addr, msg)

def main():
    sa = Send_alert()
    sa.alert(sys.argv[1], sys.argv[2], sys.argv[3])

if __name__ == '__main__':
	main()
