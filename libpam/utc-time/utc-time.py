#!/usr/bin/env python
import time
print 'Content-Type: text/javascript'
print ''
print 'var timeskew = new Date().getTime() - ' + str(time.time()*1000) + ';'
