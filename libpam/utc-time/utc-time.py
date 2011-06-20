#!/usr/bin/env python
import time
t = time.time()
u = time.gmtime(t)
s = time.strftime('%a, %e %b %Y %T GMT', u)
print 'Content-Type: text/javascript'
print 'Cache-Control: no-cache'
print 'Date: ' + s
print 'Expires: ' + s
print ''
print 'var timeskew = new Date().getTime() - ' + str(t*1000) + ';'
