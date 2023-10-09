import requests

xml = """<?xml version='1.0' encoding='utf-8'?>
<a>б</a>"""

xml2 = """<?xml version="1.0" encoding="UTF-8"?>\r\n<stuMessages xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://cody.glpconnect.com/XSD/StuMessage_Rev1_0.xsd" timeStamp="28/03/2021 19:21:35 GMT" messageID="0edwde58fc0010058376de409d6f601a">\r\n<stuMessage>\r\n<esn>0-2121111111</esn>\r\n<unixTime>1623954046</unixTime>\r\n<gps>N</gps>\r\n<payload length="9" source="pc" encoding="hex">0x004646CD26F0790A00</payload>\r\n</stuMessage>\r\n</stuMessages>"""

xml3 = """<?xml version="1.0" encoding="UTF-8"?><stuMessages xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://cody.glpconnect.com/XSD/StuMessage_Rev1_0.xsd" timeStamp="21/11/2021 06:09:51 GMT" messageID="71bbd8382ccb10068f6beb6579f81b14"><stuMessage><esn>0-4360553</esn><unixTime>1637475007</unixTime><gps>N</gps><payload length="9" source="pc" encoding="hex">0x004DB2872F1C350A00</payload></stuMessage></stuMessages>"""

headers = {'Content-Type': 'application/xml'} # set what your server accepts
out = requests.post('http://148.251.67.210:24842', data=xml3, headers=headers).text

print(out)
