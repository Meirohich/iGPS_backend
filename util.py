import time
import json
from bson.json_util import dumps
#import csv
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
#import datetime

def decodeStuPay(strp):
  
  lat = strp[4:10]
  logt = strp[10:16]

  ilat=int(lat,16)
  ilogt=int(logt,16)
  
  latt = ilat * (90.0/2**23)
  longtt = ilogt * (180.0/2**23)

  lngtt=0.0

  if (longtt > 180):
  	lngtt = longtt - 360

  #print(strP)
  #print(lat,ilat, latt, logt, ilogt, longtt)

  return latt,-lngtt

def decodeStPay(strp):
  
  bat = strp[2:4]
  lat = strp[4:10]
  logt = strp[10:16]

  dbin = bin(int(bat,16))
  #print(dbin)
  if dbin == '0b0':
    dbin='0b00000000'
  ilat=int(lat,16)
  ilogt=int(logt,16)
  
  if dbin[7] == '0':
    batst = "GOOD"
  else:
    batst = "LOW"

  latt = ilat * (90.0/2**23)
  longtt = ilogt * (180.0/2**23)

  lngtt=0.0

  if (longtt > 180):
  	lngtt = longtt - 360
  else:
        lngtt = -longtt
  #print(strP)
  #print(lat,ilat, latt, logt, ilogt, longtt)

  return batst, latt,-lngtt

sxml = '<?xml version="1.0" encoding="UTF-8"?>'
SSS1 = 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
SSS2 = 'xsi:noNamespaceSchemaLocation="http://cody.glpconnect.com/XSD/StuResponse_Rev1_0.xsd" '


def getfile(dstmp, mssID, crrID,sok,nn):
    header = sxml+"\n<stuResponseMsg "+SSS1+"\n"+SSS2+"\ndeliveryTimeStamp= "+dstmp+" messageID="+mssID+" correlationID="+crrID+">\n"
    #stateVal
    if sok == 1:
      stok = "Store OK"
      pss = "pass"
    else:
      stok = "don't recieve file"
      pss = "fail"

    stt = " <state>" + pss + "</state>\n"
    stm = " <stateMessage>"+stok+" "+nn+"</stateMessage>\n"
    ret1="</stuResponseMsg>"
    
    
    respStr=header+stt+stm+ret1

    return respStr

def getfiler(delivTS,mesID,corrID,sok):
  root = Element('stuResponseMsg')
  root.set('xmlns:xsi','http://www.w3.org/2001/XMLSchema-instance')
  root.set('xsi:noNamespaceSchemaLocation','http://cody.glpconnect.com/XSD/ProvisionMessage_Rev1_0.xsd')
  root.set('deliveryTimeStamp', delivTS)
  root.set('messageID', mesID)
  root.set('correlationID', corrID)

  state = SubElement(root, 'state')
  #state.text = pss
  stMes = SubElement(root, 'stateMessage')
  #stMes.text = 'Store OK'
  if sok==1: 
    state.text = 'pass'
    stMes.text = 'Store OK'
  else: 
    state.text = 'fail'
    stMes.text = ''
  return root

