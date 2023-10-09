import time
import json
from bson.json_util import dumps
#import csv
#from xml.etree.ElementTree import Element, SubElement, Comment, tostring
from lxml import etree #as ET

from lxml.etree import Element, SubElement, Comment, tostring
#import xml.etree.cElementTree as etree
#import datetime
#import uuid

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
    dbin = '0b00000000'
  ilat=int(lat,16)
  ilogt=int(logt,16)
  dbinlen = len(dbin)

  if dbin[dbinlen-3] == '0':
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



def getStufile(axs, aasd,delivTS,mesID,corrID,sok):
  location_attribute = '{%s}noNamespaceSchemaLocation' % axs
  root = etree.Element('stuResponseMsg',attrib={location_attribute: aasd})
  root.set('deliveryTimeStamp', delivTS)
  root.set('messageID', mesID)
  root.set('correlationID', corrID)
  
  state = SubElement(root, 'state')
  stMes = SubElement(root, 'stateMessage')
  if sok==1: 
    state.text = 'pass'
    stMes.text = 'Store OK'
  else: 
    state.text = 'fail'
    stMes.text = ''

  #xmll = etree.tostring(root, encoding='utf-8')
  return root#xmll #root #

def getPrvfile(axs, aasd,delivTS,mesID,corrID,sok):
  location_attribute = '{%s}noNamespaceSchemaLocation' % axs
  root = etree.Element('prvResponseMsg',attrib={location_attribute: aasd})
  root.set('deliveryTimeStamp', delivTS)
  root.set('messageID', mesID)
  root.set('correlationID', corrID)
  
  state = SubElement(root, 'state')
  stMes = SubElement(root, 'stateMessage')
  if sok==1: 
    state.text = 'PASS'
    stMes.text = 'Store OK'
  else: 
    state.text = 'fail'
    stMes.text = ''

  #xmll = etree.tostring(root, encoding='utf-8')
  return root   #xmll 

def get_curms():
	ms = int(time.time())
	return ms

def getEUP(sn,ut,pl):
	pass

def stuMsgJsn(esn,ut,gps,pl):
    x ={"esn":esn, "unixTime":ut, "gps": gps, "payload": pl}
    print(x)
    #dxx= dumps(x)
    return x

def getStuMsg(esn,ut,gps,pl):
   pass

def getStuMsgs(dstmp, mssID,esni,ut,pl ):
    pass
