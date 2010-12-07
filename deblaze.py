#!/usr/bin/env python

"""
    deblaze - A remote method enumeration tool for flex servers
    Created by Jon Rose
	Copyright (C) 2009-2010 Trustwave Holdings, Inc.
 
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
import sys
sys.path.append("pyamf/")
import pyamf
from pyamf.flex import ArrayCollection
from pyamf.remoting.client import RemotingService
import sys
from optparse import OptionParser
import logging
import re
import httplib
import pprint
import urllib
import os, subprocess
import StringIO
import base64
import Image
import datetime

'''
Disclaimer: Quick and dirty hacktool for flex remoting server.  I suck at python.
'''

findings = []
htmlCodes = [
    ['&', '&amp;'],
    ['<', '&lt;'],
    ['>', '&gt;'],
    ['"', '&quot;'],
]

commonfunctions = ['activate',
'addChild',
'addEventListener',
'addHandler',
'addStyleToProtoChain',
'appendChild',
'apply',
'attribute',
'attributes',
'callLater',
'charAt',
'child',
'children',
'concat',
'contains',
'copy',
'createAutomationIDPart',
'createCursor',
'dataForFormat',
'deactivate',
'deepClone',
'descendants',
'disconnect',
'dispatchEvent',
'elements',
'end',
'execute',
'getAssociatedFactory',
'getAutomationChildAt',
'getChildAt',
'getDate',
'getDefinitionByName',
'getFullYear',
'getItemAt',
'getModule',
'getMonth',
'getSandboxRoot',
'getStyle',
'hasComplexContent',
'indexOf',
'initThemeColor',
'internalSetCredentials',
'itemToLabel',
'length',
'load',
'localName',
'localToGlobal',
'logout',
'measure',
'move',
'name',
'nodeKind',
'notification',
'notifyStyleChangeInChildren',
'onTweenEnd',
'onTweenUpdate',
'parent',
'pop',
'push',
'recordAutomatableDragCancel',
'recordAutomatableDragDrop',
'recordAutomatableDragStart',
'regenerateStyleCache',
'remove',
'removeChild',
'removeEventListener',
'replayAutomatableEvent',
'resolveAutomationIDPart',
'setActualSize',
'setCredentials',
'setNotification',
'setStyle',
'setTweenHandlers',
'setVisible',
'setWidth',
'shift',
'slice',
'splice',
'split',
'styleChanged',
'stylesInitialized',
'substr',
'text',
'toFixed',
'toLowerCase',
'toString',
'toXMLString',
'updateDisplayList',
'updateParent',
'watcherFired',
'willTrigger',]


dark_pixel_b64 = \
"""/9j/4AAQSkZJRgABAgAAZABkAAD/7AARRHVja3kAAQAEAAAAUAAA/+4ADkFkb2JlAGTAAAAAAf/b
AIQAAgICAgICAgICAgMCAgIDBAMCAgMEBQQEBAQEBQYFBQUFBQUGBgcHCAcHBgkJCgoJCQwMDAwM
DAwMDAwMDAwMDAEDAwMFBAUJBgYJDQsJCw0PDg4ODg8PDAwMDAwPDwwMDAwMDA8MDAwMDAwMDAwM
DAwMDAwMDAwMDAwMDAwMDAwM/8AAEQgA8AJYAwERAAIRAQMRAf/EAIAAAAEEAwEBAQAAAAAAAAAA
AAABAgMEBQYHCAkKAQEAAAAAAAAAAAAAAAAAAAAAEAABAwMDAgQEBAQDBgcBAAABAAIDEQQFIRIG
MQdBUWETcYEiCJEyQhShUiMVscFi8NHxMxYJ4XKCklMkF6IRAQAAAAAAAAAAAAAAAAAAAAD/2gAM
AwEAAhEDEQA/APgGgEAgEAgEAgEAgEAgEAgEAgEAgEAgEAgEAgEAgEAgKIFofJAUKBdvqgNqA2hA
tB5ICg8kCoBAIBAIBAIBAIBAIBAIBAIBAIBAIBAIBAIEoPJAUHkgKBAm0IDagNvqgShQJQ+SAQCA
QCAQCAQCAQCAQCAQCAQCAQCAQCAQCAQCAQCAQCAQCBaFAu1AtAgKICgQFB5IFQCAQCAQCAQCAQCA
QCAQCAQCAQCAQCAQCAQJuHSoQKgEAgEAgEAgEAgEAgEAgEAgSg8kBQICgQJt9UCbSgSh8kAgEAgE
AgEAgEAgEAgEAgEAgEAgEAgWhKBdqBaBAqAQCAQCAQCAQCAQCAQCAQCAQLQhAiBaFAUKA2lAu0oD
agXaEBtCA2hAbQgNoQNJY3qUCMEkxLYIXSOALiGguIA6mgQdo7U/b53M7yZmDD8UxccTpqn97kHm
CBoHrtc4/ABB9DcD/wBpjl91gZLjP9xYMdnp4S+xtbeydJbNc07SHudI1zhXTSiDw93Q+0jvP2pb
JcZnBx5CwbdTWjLmwmbJIZIBufWAkSaAitARUgVrog80v9yJ745WFkkZLXscKOaRoQR4FAB4PXRA
4UPQgoHbUBtKBNpQFCgRAIBAIBAIBAIBAIBAIBAIDqgSgQMQCAQCAQCAQCAQCAQCBaFAu31QLQIF
QCAQCAQCAQCAQCAQCAQLQ+SBdqA2+qBdoQLQeSAQCAQCAQCAQCAQCAQISB1NEEZlHgKoIzI4+gQD
GhzgHODR4koPdnaPuR9uXZnt+2/sLzI8y7tcut5bHmtjlMG24wtvjXua8WMAkuIXPc57GufJ4/lA
A6h9BvtP71cW5hNNccX7dRcCDbeeWztGEzWd5JYNZLdNgD/qY7Y4vaNxoRQVQfVSz5BZfvrnHTZB
7zYY5mXZj4gC10bg9s0ooC4nbsO0daVog8h8xsbTknOcba3uPt54cBYsv7y2uC18kU91Kb+Rjo3a
tJlkhBJr+WiD89n3JX3CMn3a5PfcDxsuKxE89ZbaQijrgCk0jWjRjXvBIbU0CDhTWtfQUId5DxQb
VacLy+Rtm3GNdBeSbdzrJsgZMB6B9A74A1QYC9sMljJfZyFnPZyj9E7HMJ+FRqgqiXzH4IHh7T4/
igegEBQeSBKBAm0IDb6oEoUCUPkgEAgEAgEAgEAgEEaAQCAQCAQCAQCBaFA6gQKgEAgEAgEAgEAg
EAgEC0KBdvqgWgQFAgVAIBAIBAIBAIBAICh8kC0PkgKFAu0oANJIaPqc40a0ak/AILV9j77GSMhy
NpLZTyMbIyCZpY/Y4VaS11CKjUVCC9gOMcq5VdtsuL8byfIrxxo21xlnNeSVP+mJjig65B9sXeye
AXl9xSDA2mxrjd53K43GNDSARpd3MTvHoAgzLPtb5PbyFmf7j9ueMNawPklveQsnaCWbw0CwiunO
JH8oKDkfI+BuwDnut+S4jkdqw7RfYz94Iy7XQC8tbZ/h/LRBoPyogz3FuPZblvI8HxjA2UmRzXIL
6DH4mwiFXzXFzII4mNHq5wCD9GnEft25P2P4lwXFWPGW291xeQTWvI9lReX0Q33scwDqubPR/t7h
oBtGhQdjm5/254F3KtuN815PHiLq84Y/kJklLGQRYyQPbbx7jRzXBjNwb+ah0QfOvu398vGd/PrH
heAvJMlya2lgs+Uzva0GaRzmyPbBQlkbWPcGDcXV1NOgD46Ze5kyGUu7mVxLpZCXOOvigktWwsII
A3eaDabG79ogxvLXDyNEG9xZp9zbstbtzbthFZGTAPbT1DqhBg7nB8bvnE/sxaPP6oCWj/2jRBjj
wKwuDS2yboCRoZAHN/hqgkg7R8lvd39ovMdfkV2xm6jge70DZS0V+aDEZLtv3Bw7HS3/ABLIm3ZX
ddQQmeIU6/1Id7f4oNLeXRuLJo3RPaaOY4EEH4FAAg9DVAqAQCAQJQeSAoEBQIE2+qA2oEoUCIBA
II0BSqBaHyQIgUCqBwFECoBAIBAIBAIBAIBAIBAtD5IChQLtQLQIFQCAQCAQCAQLQ+SAofJAUPkg
KFAu31QLQIFQCAQCDM4DAZXlGWtMHhLYXeSvS/8AbwF7IwRGwyPJfIWtADWkmpQekuKfblibx1oe
T9xsRb3EzHOmwuOlEkzHA0ax0zhtBPidpHqg92dssb2O7OcbyVtxqPhOU5VO90+T5tm2wZa8xLJL
fY6K3jaLraGjc7c9oqanadKB5phsOw2FgfkeMYuTl0shO7OXVg5ls95NXFkuUqXUI6xQkeqDGZ7v
DaOtDjw68/btBjtsbBcuZbMBk9xgDGCNtGvJIAZ8KIOSZ3neRlEkLLSHFtkfvl/pD3nvoGuc6V9X
kmmuvWqDn0mZLnuMry9zmkCvwog13MX5lsBAwkgPBdr6H/MoNIfbyNZE4sIMxcY9NC0GlR8wQg/Q
N/25ftL4J2Q43g/up+4zkGH4lyDkNqZu1+Hz93DZR46xuWFoyEguHM3XFxG7+kB+SM7vzv8AoD1b
93X3r8d7fds+S3PCJ8ZyFt7Fa2XC85HIy4gffSvDn3DACQ9sLK+YJ6oPzodxu7/LO5vLsnzXkWRd
e5S/ggt5JQ0RtENtE2GKNrGgBoaxgFAEHJmZKW5vo3Su+iPduLjoSKmn4oMl/wBH3txxi55e0NNh
DfG0ma38wNAd59KkBBprgGO+mo+KCeK7dENNT5oMhDlHdC6nmgy0GSOh3FBl7fI1oXOoPTr8kGbj
zRjod5ZT8oBo75lBn8ZzrO2bmC3ycu2IhzQXH6aa1qNQg2O55la8kZHByCaC8cBt9+7tILqjfAbn
j3Kf+pBql52/4/k5QcfLjpmuBNbSV1pJrr9UU7i0U8NpQafleA4mw37eVw2jmAF1tdsc5wr4bmNo
g53fW8VnKYor+3yTa6S23uU/CRjUFWh8kAgEAgEAgEAgQiqBNqBKFBEgUVQPQJQIFQCAQCAQCAQC
AQCAQCB21AtB5IFQCAQCAQCAQLRA6gQFAgWgQCAQCAQCAQFD5IFoUC7UBt9UHoL7WsOc73z4Xh2x
+67INyUTWeZOPuaIMj3R/dYbkORfeWrfeglntcja0DAWu3MeA1tNpHVvkQg5xe88uosfiWcfY7Bm
G3EGQktXbPfkZ0cdutSOtSan0Qahccszd29wmv5X0AFXOJNEHUO0WEsOVcgjbd5fHjJ2r2T4/EZT
3C28kY4O9ttC1pr0LSakdAgznMcl3lzOQzGNHbdmLtbHJ3EH7ezwLXewZyXMtxNJE8kbalmtSNal
Both2p7vZXIx4+DgOcN7dRS3MEU1hJbNdHE0ue5rpGsZQAHSvwQdJ4R9t/N8tzHjFh3DxGQ4twu9
uI5+Q5ezEN7dRWI+qQxW8MkjvdeBtYHNpuIrpVBju7PFOJcY5S48ayFza47DPbbYy05BZyW1zdQ2
ziILkQNa8f1WgF7HHR1dSCg5xyznvM+4+bn5BzjlGU5Xl3hrf7hlLqS4e1jdGRxh5IYxo0a1oDQN
AEGv3Vxd3EdvFPdSzQWoLbWB73OZGHGrgxpNG1OpoglY2luaeSDCBh+s9fqKC7ZZrKYzeyxvpYYX
u3S2td0LyP54nVY75hBjXvMji9wG4klzhp1QMcxruhofNBA0fVsJ2v8AI9CgnEs8elNB6ILltcZC
Y7LeKWYj9MbC4/8A8goLkBzcm24t8PcXkLHVeTDK6N1OoJZT56oNgu+4OSGKvcFNxrD2NtfQtje6
G3linbQ1DhI6Vzqn1Qc7bc3DNWTyNHhRxQS/3G+pt/dSU/8AMgljLZSJLl77hw6Nc4oOocP4NNl7
bN8gubX2cTg7WW4lcATGHRs0qfHUhBy51KuoaipofNAlB5IEoECbfVAbSgagEAgEAgD0KCKgQKgE
AgEAgEAgEAgEB1QODfNAlEChvmgcgEAgEAgEAgWhQKG+aByAQCAQCA6oFoUC7fNAtAgKUQKgWhQG
0oF2oDaEHrH7HI2SfdP2kZIKsdfXYcPMfsbhB1r73O3F9xju9z5lpbVs2XV7eytJA2xtkq8tqddp
d0601QfOd7y0uZX6a1CCE1ADv5q0QPiuJIntexxa5hBa4GhBHQgoPePYv7tchi8fccJ7jS22Wxt1
aG2xefyVsy7dEYwXQxXYcC6SMGoY8EPYTXdt6B0bmPbrleU7Vx97O33JbzI9uM3k34jleEguHmKx
yDdsohewPq5r2OaWSV3D8rvqGoeYpeOQ8lvX3Bzr7TL+2La3/v8APLdwMAJ2xRXEpcI+tAJWfDVB
oHLO3HczjrSMpgrm/wAfEN0N5C390xrKVBDoxVradNAEHMYb64ZM4C3a4u/NC1pBG3rQIMscpYzR
wso+CRo/qbxVtfQj/cgy7djrUuje2RtOrSCP4IMLs2/OqCo4VJOnVA3aUCUp4IIpHRNH9Snw8UFu
O/sYoYHAS3FyyQF8EkbPa2Dw37nF1fLaEHXrDvH3pbhxh+O8iv8AjvHYKtit8ZFb42KNjq/T7lvF
CfHzqevVBqOTzfOsjbGHPcwyT7HUm0lu5nMNTU0jc6mvqEGiXDrSLSEGZ56yyGvzogxxcXGp19ED
2tqKu0agniePcYD9Laivw80H0KyWHm4h9nWUzkokii5dlbbF4RklBRhDZ7p7B1+vbGD8EHz6oUCI
BAIBAIEIQJtKBKFAiAQRoBAIBAIBAIBAIBAoFUD0AgEAgEAgEC0KBdqBaBAqAQCAQCAQKAUDqBAq
AQLtQLtQLQeSBaeiBaFAu31QG1AoHzQexPsHxU2U+7HtLHFtDbS9ubq43V1jjtZd1AAan6kH0t/7
l3BLfOY/l/MsW1pvMFdwuvAzr7dzDE+RpBHX63/+0oPz8SNDJXtILg0kBAj3bqU0AFAEDOg80BU1
r4oOw8P7z8w4xwrkXbX+8Xh4Nya5ZkLvEwybDDkIWe3HdwnwcWgNe3o4AV1a0gNax/JbmCcysvpH
udo50pNXDydWtaoO58I7wZTjpit47iO6x/6sRdEy2wB6+1ruhJ/0Gn+lB3XHxdqe61xEbvDxYnkp
dutJo3C3uzINd0F1DsEp8muFfNqDVs79p+NzucglxvMn4O1lkAy1vd2XvzQtI1ljia+Hdr1boPEH
9KDceR/9vkx8SyHKe3Pd235PdYlsZusNd2BsJ5A788kYFxI4Nb8Cg8P884NzXthl4cHzHHC2u7m1
jvbQhwe2W2lLgyVj29QS0j5UKDR2XULj9RMZ9en4oHSTRRiu8OJ6BuqDM4bjXI+TOcMNjpJIWmhu
SNrK+Qd4n0CDs3G/txz2S/q5S5EEbG+5cbfpZGwfmdJI+gaB4k0ogys+F7ccQZTEwQcnv4wRJk59
37CN4OvtmofcHT9FGf6ig5lnuWGaQPa4SzRDbDJtaxrB5RRMAYwfAV8yg5re3d1evLpHEtJ6IKft
nxKCQRhrS4jQIIHPJP8AkgzXHMVNn+QYfD2rC+fKXkFpBGBUl80jWDQfFB9U/wDuDW9p2+7Xfb92
fxx2x2GLOYv2AUrPODuDvMtG0HyQfKKhQIgSgQIWoEofJAiAQCAQJSqBC1BCgEAgEAgEAgECgVQO
AQKgEAgEAgEDgPNA5AIBAIBAIBAtCgcAECoCiB21AtAgVAoBKBdqBaDyQOA+SBdpQKGIHbAgdtHk
g9m/YBlrbB/dP2/yFyxpjbb5SJj312skls5GRvcAQSA4jxQfYLv3ZY3mON7gcfy99Hjsdy3GgRZG
UEx29zbUfC9wbuNCWFhp4OQfmr5LjJcPn8xiphSbHXk9u8jzjeW/5IK8bre7MNsyxigmftZ77XSF
p6DcQ4u1PU0+QQPy2EyWLe51zZystXPcy3vNjhFLtJbVriPGnxQYehQdd7DduH92+8Hb3t6Mfk8j
acmzVra5aHDxCa9ZYmQG6lia7SscQc4k6ACqD2V9zv2N5Xt7d8hvu39jM+94paTZLk3CA/3ZnYm2
ldC/NY6rjI63aQPdjdVzCdzSWmjA+csN1JGagmg8UG1YjlV/jZopre4dG+Jwcwg+I1Qeu+JfcJfX
9hb22dZFmYLbaJIbkkTxU/VFM0h7QfEA/FB6O4x3PwV5FNcYjkD8bcOG52JyH9SOmpc1rmCpFOnU
oHc34bwvv5hsc64u4spNhWvjssxgrtk77dkv1PY+EgyNAdqWuZoa9EHP+E/Zv2qt7+f/AK05Plc/
AWSiC0t2tsGxSBhdEJHN96Q1cA135aA1QPzn2tdqsRfw2uMw1zeM90SCe4v5bjeSAfaaIxG0tBNN
QTp+IZvkF/2/7WQx2WUEc2ahj/8Aq8Mxuz921rQA39wae3ax+r/q/lY5B5P593ezXJm/tLuWKzxE
Tt1txmwLmWLCOjptx33L/wDVJoP0tCDg+SzF1evc6SQmvqg1153HXUlBGWEav/pj16oNp4pxHIcr
vHw2YFvZ2w35HKSj+lAwAuJJ8yAaD5mgBKDEciurCS8/Y4gVxWPrHbTEUfO7TfM49TvI08hRBrzt
ugHWmqD079n3EH8w798Gsm27p2WNxJfFg8HwRuMRPwlLUHo3/uXZz9531x3HIrtl5acXwNpHayse
X/TPGxxrUNINWk0p4oPnUQUDaBA2iBKHyQCAQIQEDaIEQCAQV0AgEAgEAgWhQOoECoBAIBAIBAIH
bUDkAgEAgECgfJA4AIFQCBQCgcBRAqBaFAu1A6nogWhQPDfRA7agcB5IFofJAu1A7b6IHBp8qIPU
v2Zwvk+4Ph8bXsj3wX4MkjmsAH7d36nEAfig+yffPHXFnxC/uZ4XUbZzFpPRzdhILSOoqAg/PT3W
t9nOuVSf/Nk7iXz/AOY8v0/FBz+0cGXEVRqHCiD0LnJI5u3ETTKHvjyYhew0ruq59CB6O0qg0vt/
ncZwfmOF5Zf8LwvOrfETe8/i+ebO/H3JA0EzLeWFxoaEDdTzBGiD6UO+937cYrvjvdDCfaxZcR75
8Suo58FfYCdmIsPc9v23yz3OO/bPkj2FzfZfA7c00c+hKCbvL94tvyDJ8K5Zf2HHsJlOU8fy+K7m
4PG5uXIPvMFkxHIzHi4gtJf20m9rnx1JLHOo+jSQQ+SrLyyxuZvJMSZJcYZXttGXzWe4+3cfpZMG
bmB23qRpX0QX8rh8MzGw5fDZyKZ88xZPx2Vr23UDSKh4eAY5GV0/MHdPpI1QYrH3htJBJ7hYR4VP
+AQbfZ8wltQ0RSvJGocTT8AgzFvzE/u2X8PuWeQaajJWsjre4DvMSRFrv4oO+8V+5DuFiIora5y1
ny2zjLf/AKnIoBNLtHgL2D25wfIuLkGf5v8Actn8xZRWPHLNvAmOhLMneWl5+9yFw5/5mw3bo2G3
i9Gt9w+Lgg8r5HOSSe42I+22V5kk1Jc97jUue4klzj4kklBqcs75XGlXHxKCjKWsqZpKHwY3qgrt
ke//AJLBG3/5HaoMrhsTLlryS1gLXPiglubi7lcGxxRQsL5HuLiAdBRorqSB1NEHc87Pxsdt8fge
L3cttcsibNyra7dHvlq9sO9ob7jztDpKmgNB+kNaHnW5iYxxZENG+J1JQVmw0qSdUH0w/wC3Th4M
TnO5ndC+aGWXBuPPcyZwJaJ5y4x9CP1RgdfFB5Z+5Dm0/cLu/wAnz8zmuMQtsfG9gAa4WcLYi4Ae
DiCUHCi0oEofJA0t+SBu1AiBCAgTagbQoBAlECbUFVAIBAIBA4DzQOQCAQCAQCAQCB9B5IFQCAQC
B21A6iAQCBwagWgQKgUAoHUCBUDtqB4aAgfQeSBaFAu3zQOA8ggcGkoH7Agft9EDtpQd8+2bEYXM
95OLY/kDZ5MZMLgyxWsfuTPcyMuYyNpc1pLiKfUQ0dSg+0+e4txvFcRvsfgLvMyYLMh1lPico5ks
Frce0Q39vJFLLG0SirS0UqaHwQfB/vXif2POc9Cz6mMudjXadGtA8PKiDkcNq4zxadTVB2XkvbvN
43C47n3uxScfzhitSwOIkZctj6OZShB2EgoNDEXmgcIkCPtI5WlkkQc09QQgxU/HoX6wPdCf5XfU
3/egrtwd/awvlnxk15AWksubV+rKeLhtfoPEED4hBem41Zz4q0yuL5DYZCWY+3eYZ++2yFrJ0+uK
QbHsNNHxvcP5tp0Qa9c42/sXUnt3tHg+lWn4OFQfkUFdk7mGlSCPBBkYcjIz8p1QXo5Z7g6kuc7p
VATSw24eJpBI9poGBBipLyed3twN2jyb5eZKC1Z4me5rJtGxoJfPK4MibQVNXOpX/bqgk/aPmADC
5rf1SOFAR/pHX/BBkrdklpDNbwSPZHcANuQCR7gBDgHgdQCAaINrx8RZxq72jW5uTX4MaB/mg0G+
hInIA8+iCv7NKDag+snZK0//ADb7L83mX/0r3uxyF8Dm12l2PxbGucSdKjeAKevgg+W2TnN5kb+7
dqbm4kkqOn1OJQUNqBpb6IGFqBhaUDSECUCBpHzQIgSgQNogRBTQCAQKEDggVAIBAIBAIBAoFfgg
cBRAqAQCBQKoHAUQKgEDg3zQOAogECgeaB/RAoFUChqCQNQOA8kDg3zQOA8kDg2qB4YPFA8N9EDw
2qBwYgkDEDwz0QenPs+srG7+4XgMeVjEtgyS4kngJIEmyFxDCR0BNK+iD9E/Kcv2/wCfcav+31td
47++y29MNZ4u1EI92CMmsUraBzm0qAfEAjog/Oz9wvHXN5I25kihiupTJb34t2uZE64tZXwSuaHa
03RlBwC2w5NxCA2ri4AIPSncNzm9j+G45ri3bn5TM3+bbA7bX4VKDzWy29EEwtvRA8WlUDxaedUG
/ces3CGM0IIZ1+JqgmvuJ4bKTVvMdE6ZtH++we3Iaf6m0J+aCrynjFzkcN+zxDRbSRANtoWv9sOH
698hDnPqB0JpXX0QcKsMXYXEOUjvnSWt5hoJprlxkZseWkRsYwUrXe4CgJr10QYWzhMjhp1QbvZY
4gwgt1cUBh8ViL7PZODNxSf20QSe5fscW/tHF7WtmcRoQCaEHQ180GEw9rAb6Yt2XFravO2rSWyA
OoOtKVHmPkgzs0IlfukbUA/RH+lvwHRBGYq/JBGYvJBvuNsd+EtGUNZPckAr4lxH+SDUb7FOdMXN
bUipc3x0QY6HGST3UEDGkulkaxo9SaIPqd9yVxFwbtlwDtrbgxR9v+F2sGQttAwZG/j/AHV04AAH
cXSAHXwQfKMsNNUEZYEDCzyQMLfNA3aEDS30QMLQUDS2iBpCBm0IEIIQNPQoKCAQKB5oHoBAIBAI
BAICiB4CBUAgEAgEDwKIFQFKoHgUQKgUCqBwFECoHBqB4b8kD0Dg3zQOA8kDg2qCQNQPAPkgkaxB
IGoHhvkEDwwlBK2NBM2P0QdY7K5C6w3cXBXtnMbe6d7tvFcA7Sz9wwxucCPIOKD69Y3mlphbfHsj
kiso4XR/tpXU3yuYA7d/MTpVB4q+5KYcx7h85yTMWzFPGWt7oWUTgYgL+zjme+MBrSGvla93xJ9U
HnfG8XmleJWMLSwgsoOtP9yCfnWRvX8d43hHN3WsL5bmWauvvgujAI9WglBy5tu4/pKC0yzJ/wCC
C2yy9P4ILLbHd+mo+CDpHH8a/wBuNrY6nY0U+SDOjEPF05xYfpNUGRiw0kzdwjp1B0pTyQeI7vEz
Xs2ayoe2O1t5pnbqisjy80axta08z0CC7gMcJKSPo2NgL5Hu0AaBUknyAQdAw/7PJ+xd2L99swOB
LxtILD9QI8NNfgg0i947mMm7NXGKhluorANffQQVcTE8lwdtb+ZrdtT5dUCcctHxRXQcaEllW+Go
qDX1BQbA6BBC639EED4SAdEHVLCwmFtY29HNbDbRl/nV7d1PwKDCXuMMk73tFD0PxQb72X4fByLu
pwnH3kTXWTcpFc5FkoOw21sfem3loJDSxhB0QdY+6rls/I7jPZa5ka64z2Uc87PpFHOLgA2g0DQB
0QeGS0+SCMsCBhjQRuYgjLUDCwoGEeYQMIQNI9KIGFiBlCgYQgx+0oFA80CoBAIBAIBAIFAQPQCA
QCAQKBVA+iAQAFUDwKIFQKBVA9AoFUDwPJA8CiBUDwEDgCUEgageB5IJA1BKGIHgeSCQMqgmDB5f
JBK1iCZsfogsNh1QbpwWd1hynEXDTtDJTuFaB2hIBPxQfQa3m/ucNm50Jbcm3Mewu3BocKmvVpI6
g00QabmsLkMlyKYTmS4lyljDHqC5zn2Dixrjp+Ysm8PJB6S7Iv8AtfxuMzvFu5uLz19zjKsfb5a4
jtXQxYKGE1jlYHtD2vc8fW4gigp5oPn33PxFvZyOhsZHXePZkpmYzIlhjbdW8clw1kzAfB4oaeFU
HLY7In9Pkgux2B8kEWSvcRgohNlbyO1qKxw6ulf/AOWMan49EGtYe85f3DyDsPwDEiFoLWy5Cdzf
cAcaA61DflU+qD2j2m+2vOcSa675BmJ77M5qMyzwhr5IgWDUGQ1G4DoTSqDp972uvYg6UWxNK1oP
4oJbfg0WOwmTvryMCSC1mmbHStfbjLqfwQfJEX99lYby7uZIxHdA2kEDKN27ZGS7GMb0aGj4fNB6
Y+37tTH3C5NBa5OPbxLjphu+USu0bcSu+q2sAfH3CN8lP0CmhcEHcs12FxkXcnO3NkzZx7lJkORw
8FYxFKY3+6+Ij8okDh06Gvog8T8xsrnhd/y3httmHWrMRkDa5CJ9GSXNtbb44NhH1OJqdzaU1aUE
HFGG6w7JHMG9sjo9/wDMBqPwrRBnH2dEFZ9s4II47OSeaK3ij9yad7YomAVLnPIaBT1JQe/e4P2+
ZXtHhcRdcqvLeB+Vs2S2U4OtxL7bHOgER+sPjDhu0o2oQeXJceTduMY0roaVFEHY+0uPmx+Qy2bg
a6G4scdLGJ2naWmf6KB4DqbhVvnQoOM99b91xfYqyJ1rJPIzrqdAf8UHn90VPDogiMaCMxkIGFnh
RBGY0EZjIQRlvpVAwsHggjLUEZCBhagjLUGNQCAQCAQCAQCB4AQKgEAgEAgcB5oHIBAoFUD0AgcB
5oHIFAqgeGoJECgVQPQODf8AgglAogeBVBK1qCQBBIG1QTNYglayqCdsfogsNiQWmReiCyyPpQIM
9gYdmZxT5B9BuWVB8UHt/DZX3LCeWBzXxWr2iV8byHOLKhzCegAdofgUGXu7WTN2+Fuv7ndYS6xs
0V7DcWe1tw0sBPttcdzRWtDUGqDq3Cc1ks9yma3uJLnKZvJuAmlyMzr24v2yMewG4lf7km00pX9N
KCgQcJ+5LP5TkGWwGBynG7XATcNbPjoxabY/dYzaxolgaxjY5IwwNcWja/8AMEHl3KZDDcegE+Yv
Y7PcKxQH6ppKfyRtq4/Hog45n+6d7dF1tx62/t0J0F7LR9w71aNWs/ifVBvnbH7c+cdzJoc3mny4
rB3LhJJf3BL7q4b5saa0r/M78Cg+jPBOzOG4Nj22WDtjYODKPum091zv5nPcNSg7HhmPwTPaZIXR
l7nne5x+p7qu6knUklBf5xzTC8bwLrzIXMUEzx9Ic4AkkaIOAcw53i7vtrzm+gvGte3j+RfDPE76
2vNpIGkU1rUhB8gOKWd1kMzbWllbvvLyb6bS0YKl8ryGtHwJOvog+lmL4zmcFwm045wXIi1ueKSC
/u75oAbm83+a7Erv/iH/ACmeoH8qCxed9XZPC4McZwjstz7O3b7FuCLhHJay2rQbk3Bd+RrNNSg+
eHdvKX2e5/yTOX9l+wuMldu922rupJCGxyajr9TSaoMlw/k2Ax+PjxWRlktJw90huS0uiO+lBVtX
Aj4U9UHTYobe8hFxZzx3UDq7ZoXte38WoK8lif5UGb4U9+J5rxHLx44ZaTE5iyvmYx35bg207ZRE
6mtHbaFB7l5Dkcr3EvM3zLm+RknyeaZpeXAbDFbmQlzbW0jkBLYgXamoc8gbqlBwOHil8J5fdja6
MPNHMB6A+SDebA22CxN3ZwyNM18+OW72ncWtNWsBDakVJJ1CDx33Ivn5Tl9+06x4+lvGR6an+JQa
C+I+SCu6JBA6MhBEW+iCMsQRFqCMtQROYgjLT5II3N8QghLfkgY4aEIMOgEAgEAgECgVQOAogVAI
BAIBA4DxQOQCBQKoHAUQKgeBRAqBQKoJA35IHoFAqgeB5IHtagkAogeBVBM1qCUCqCVrOiCUN9EE
7GILLI0Flkfogstj6aILMcJdpT5IMlDadKoMlEP2UttdgD/6sglAP+kEoPTfbqHJO7f8eEF2+0vL
wG5ubwMZKXCVzpSSHk/mLvDX4IN6jmy8YlfcQ/u2z3DWxw2wNWQ1Ir4kuOlP8kHqTsPaYm055w29
ycW193lbPGxxz03B91J7bWnboQK1QeFfvzzF/wBuO6+Q4bx7IOma2a8muMjM735YHGdzTBE4lzWh
tKnSoJppRB4J45xTl3cLMfs8JYXWcyVw6s9w4lwbX9UsrzQD4lB9Ieyf2a4LButM/wBwZ4+QZePb
LBhmNP7OJ41+quspHrQehQe+bbE47Hwtt7e3jhjia1rQwUa0dKABBqHKOU4Tj9rLPe3UFsyEEufI
4DTz1QeHe4/3c4fFzT2XE7f+/wB+2rWygkW7HDoS79VPRB5M5Bf94u8N0+9yMd9eQN/qss4WuZCx
pBIoPE0FQg02XK8/45YZHBXM91HY39u+1uLe4BIEcg2uoT00KDofZvthnsjk+KcjtsicLYz5G+H9
zZQy0xsMM0rGN/1GZja+p8qIPpJY4y2srSCztGbIIoQ2FnlQf466lBoWM7fYzFcr5JzaxsxHlsva
MgkcNB7gqNzfIyHbuPjRB5q+5/t1gePwdvb7BtDrqXFXVnytoYGFuTtJg2UubuLw5weHfUBpSleq
DesT9nnG+b9quFcgx+UkwHLshh4bm9nBM1tPJLVzN8ZoQdpAO0j5oPJnOOzXdXtDeSz3thctso3f
TnMY50lu4DUby3VvweEGBxfc/IQ7Y8zZx5GMaG4jpDMPU0G0/gEHonstncByXnvH2WN21l1A6W4/
Y3I9uU+3E8/TqWup10JQe+craTTYuVskImMbBWo3V610pQCiDjtvPfY6f2bD22wjYWQzs3QxsGha
3UH1oghzBtn21/PF7YF+C6eaJrWue7bt3Gg8AKIPC2W/r5bJzBznh076Pd1IBoK/ggxLo/MIKz4k
FZ8SCs+P0QQlhQRlvpRBE5vogiLUEbm16IIHN9EELmoIyPAoMGgEAgEAgEDx0QKgEAgEAgUCqB6A
QCB4CBUDwKIFQOAQPAqgegUCqB6B4H4oJAKIHgeKCZo/8UEoCCZrUEoHgEE7WdEFpjEFtkaCyxld
AgvQ2xNCR49aoMnDABSg180GXt7apGmlfNBNkbQ/2+chuux23/2lB677acfy+X4/gcbhcReZOeDH
wGSCzgkncwe2NXCNrto0pr/ig7QeE8j45cWMGZwN9jrq8IbbWs0Lmyvdp9Gz8wd9Q+kgH0QYXknO
Mj2rzXFLjOcK5liI8VnrLMzcgfgb2Gwa21eXFgu3xtBe7QVbWg1qg8x/c5jcR327zWnMeMX01xx3
kUct/dPmP/2WPml3PjcKClHlwGnQIPUvaLt9x7hOGt2QWsFiGtaXRAASGv6neNfig7Re8kxuKhdM
53tsoal30N08au18EHn7l/enPX0kuK4FhJ83kT9JmiaRCw+b5OiDhN72V7hdw7k33czlrra2kO5m
DsSSxtdaPNQDRBu/Hft67ece9uWLGHK3LCHCa6O4VH+gaIOr3WDdeOkdLExxl1k2tDK06fkpTog5
J3t4rE/t7mphj4Jrx77aGK4MYMrPcmaKtcBWqDUO3vGeU2nb6P8AteOg/cYiW5usAXvc2RxkDY77
fQFoZIWjUmv9JumqD09YREx24IFHRtp+CDZcbi5LzIYzGQSCGbI3kNvC+ldpLg6tPQAkoOT9/O29
lLieW8bt7z+9zftGZ3jfIC2Ae/d2Ic3JWocwB/8AytxaHeMOlakoNk4NzDHW/GuO4qCVgZjcda2j
dtA3+nE1poB01CDebm+x2StX28xjuIpARKDR4NR08UHkful9tPCOSma/wcIwOXkq981mA2JzjqN8
OjfwoUHAO2HZnlPEO45kybnR2VrZz/s8taODS6R5awNo4EtJBNf8UH0Nw09zZ20G54yMTI3G4sJa
bpG7aUrpqSdEGgZGK2u7i4kx0L4WNe4GGRwc5rgaOaSPJBq/L7c2PGru820khjcZaDShB/wKDxML
eoe8jV7iSfHzQU5banQU+aChJCRX0CCo6PzQVnxIKzokEBj/AAQQFqCJzaoIXN/FBGWjVBA5nVBA
5tKoNeQCAQCAQOA8UDkAgEAgEDgEDkAgEDwPNAqBR1QPQCB46IJUAgeBRA8BBKBRA4CqCVjUEwHg
gmY1BMB4ILDG9EFljEF1kfTRBaZHWiDIQwa1p/BBlIYTpogykFsTQkaIM9a2pJH0nr0ogzLsZ78T
IiNJHNa7w0dog9B80yHIeDd5s1xrtrDLFZt/t9u3DWNzPHBG2PFWc00jix4IPuyVoXHWug0KDufF
rXvrl7myssEH3V9eywW2Rbb/ALmZ0EkDqBstyHABzW1q17yR+bqg9gcy55x/7duN43Bcxyt3yrun
zC2P/TfC8HdOnhc8vBc+6EUhe9pc4737Cwbfpq4UIeWs7xHluQxme7y9zccyxPG8NDcX5yMRxfus
9xsUNvj4GMJe58krWNM20ud+YjwDC4/kmPuiy1xjG4i6uoWTstLtvtXBjeA5rg1x+oEGtQSgfc4K
1vnmTJvkyBJr7crjs+bRRBk7e2t7WNsFrbR20TfyxRMDW/gAgsexv6inyQMbYBgAjbtA6ACiC1Gx
4o1wp6oOX96cblMrwv8AtOJuX215kchbRNfGKuLRue5jepBcG0BaK+SDaODYjheH4F/0rZ5puN5R
jsbBjMjhrvc0zzXErT+6i82x+6WPcdQWkeNSGTtbGewnkx11sfc42R1tM6N1WOdHQVaSOh9Qg6Li
4hZ8fzXIXW8UtxZe7FijK8MpK6HY+RgpVxi90HQj4oOSc2gyN/DiI8VtfPFJa3Msdy7d+eJtTuI1
E+243fNtUHl+67Jc84rNJccK5I3J2jSXMxt0S0hvXaCT/mgfadweVcakFpzDA3WMe36Td7XOiPqH
gIOtcX5PDyq7gssNeR3F9LG6Rtu97S4tYNXDWvp8UHV7XgcpYy5vaQza7nv/ACaakgiunxQYjkkF
hjLJtxLdxNgf9LZ2PDgaeRaSfBBqmT4L3Qkiw3L8PlcE/jeVt47nD2+bEpHsmrXzskYxjtaE03Ea
dEGmd7sVh8VxWCz45mszmI7m5hdeXskbYbMPYC14jDQHFkhH5SXAH1QeSpMc+NgD46bhuGngeiDE
zWhH6a/JBi5bfrp/BBjpbcipp8kFF8ZbXRBWeyqCq+NBVexBXc1BEW+aCFzUEJFUELhofgg1ZAIB
AIFAqgegEAgEAgEEiAQCBwHigcgEDwKIFQOaED29UD0DgPFA8BBI0IHoJWhBMBRBI0IJ2igQTsag
tsagtxs9EFyNtUGRgiPX/JBlIY+miDMW8G5w08qINis7EvI0qg3THYKSXbRmpQdCxXEpZi0GI1H1
V+CD6J9kOx2A7kdx+7fczl17DZYqG+t8NjLVznWz7t1tj4Ld+6SmrGtYQSOgr0Qe9JsHicHj8Tw9
l/ZccPHI3XeTssGHWkU5kZRjfec9xkiY57hJUAvNKhoQfMTvv357ffbjn8uOAcCxdzyfIRA5fuFd
O/fXMkZc36DOXGRobtAbEKMaA0NaGgBB4I5N97MvN+Lz8c5LLkrsXeSssjknzwx3UN5/b55biGKS
J8rdjC+QE7SKhrQdKoPXXHvvu+1juhjJcJ3i7fWXCMrLjGWVny7D42b24JogGNlNrbvkp9IG0tJc
2lPJB4uxXfDllr3RueJdtMlL3c4rfTCDjljkYnxXtzsj3PdbSU95hcQ4tZJuoNEHp/j3efh9/kG4
LkP7ngXJejsNyFn7Vsjxo5sNy6kT6HwJa7/Sg7QyMEA0FCKg9ag+qCyIQR4H4ID2ATWg08UGj9we
S4fiGFiyOZun28BnGz2HFk7ywbi2MgihPQk9B4INGt7BuaPE+TRY+C9ymPuRknYl9xJZG6tZz7zr
f9xE3c1zKtdup56aoOr2WOyV9Z5PPXc0P93yt7NdTWkLnOjh911WwtcQDIY20buIBdStKoIuR8lu
LbhthgJ2TW9yLuSe5bp/TF1sLYiAKh42Bz69Ktb4Goa/mLE5HGcevom3DpcbdNx2b/bOMe6xuazW
k73M8YLhro6k9JGhBPd3TLWKS4lkjgt4QX3NxK4MYxgFS4k6Cnqg8292+8MeN4VlMlxOOHIhkxsH
5W8grBDPJt9r2Y5W0mL2+4Qeg2OqKUqG7/bf3G+y7j3bLhXLO8/Ls1B3pxN7e3N/isPZyuM0DJ3e
xFJMyOOICaL6XD3fyuNRVB3a2++v7MM/nLmPL8T5VxLGXNy229nS4tn2ha0mUGK4d7Dw8Uo1haW1
3amoDk/fjsY2+wc3e37cOfs592uyUlQ7HyiY27hVroLm3I3RTN21c1zB1qNDoFnD9p/ubj4lgcr2
F7vY/nPH+4mDhv4OG5K4soclD+3cY7i3iF979uZLSerXiOWNzXH/AJYqg4Zk+yHfrjWVkzHevDZL
G5HKQvbYC/uoLlz9rgX7fYllDR400CDV7/jUsLaGM6eYQaXe4p8datP4INauLM66UOqDDTW5GlEG
Lng0Jpqgxj49SgquZXwQVXsQVXNQVnhBC4fxQQOFEEbhUH4INT2+qBDogRABBIgEAgEAgECjqgeg
ECjqgegEAgkQCCQdAgeOiB7UDkEiB46BA5vVBMxBKNUE7RqgmA1QWWjyQW40FxnRBdhGoHqgzEIG
iDK24BI8kGwWgbVBvmIhjc5gICDuXFsfZSbd4AB/UUHovjXGsfOxrmOYCBUOdRB2O055ecAwVzYW
uCk5tjWZF2ZtONz3FuGR30pBmlYbiOrgQCQwP6nRB547vfc3l+Zf3KxFjNx69v3Os22F7c/s5nsA
0MTJ/bI3V6g6+J6IPmj3ayuaxVibXM4q6sW5KJ8OObeNO2VrdC6NxJ3BtfzAnwQeVz/sEHR+1nAI
u5HKIePTcitePMdG6Z087S+SUNpWO3jBaHyHwBcEH0g4Z2mw/bC0xt32xf8A2jmUTpHXXcXIRQ5L
IBrwWBlnDPH+3tfpLg4hj3Gv5kHRbvjuD5niY8N3FhPMJhEIZMvftZ77yP1l0YYGuHm0BBzCftt3
d7Wtdf8AZvl45ZxmFpd/+ecgeZmsYNQ21ke5pbSuga5vrXog6J2/754vkkIs+YYe57f8jt3GK+x9
/Uwe400JZMQ0gE9NwHxKDvsMkU0LJoJWzwygOimY4Oa4HoWuGhCDn3P8Rgr84K/zeNdk/wCz3D32
EftumZHLNtaJHxjQgbRqRQdUGk4W5yZyFxdyTQ28Ekk7jYRtIc4u2hm4uJ/KNTSmvog2OzzN3AJb
R8oc10xc3b0DXGoHx9UGE5ZNcZSZ7HXDi9oEp3OdXd/M4ghzvq1NSgwPNu5Le2fF8hye4x1zlorc
RWhsLWVsQlkncGxskc6v0FwBP0npWlaIOEcck5v3buhmueXDrHDH6sdxi0a+KyiaQXVINd7w0fme
SfKnRB5a76c2nzXJrjjFhL7XGuKzvt7CzYKNdcBrWTTO83Et2gnwHxQcL3OP6kC1cUHov7cu5vdL
tdy29uO3tvLmLPlVlJieV8Ql902WUtJQQ0StjILZIXkSRSt+pjx/KXNcH1H7KW+X4RdvzMW3Cx39
0zLwYedvu3WPvJYRHdiCdsgDGTEDe0hwIDdAQg7XyCeDlsrrzM3LryZwJ9yV24Nr+lo8EHBeXcVx
DGudEGh5BoB40QeaeRYqGOSQNaOuiDl1/aNY40Hmg1a6hAJ9EGBnYBVBiZ4/GiDGvagqvAQU5GoK
rm/JBXPUoIXD/igru6H4INUQMPVAiBwHigcgEAgEAgEDwKIFQCBzUDkAgc1A5Ao6hBI3qgegc1A5
BIOoQSIHNQTMQSjqgnb4IJmoLLTRBaYUFth0QXInajw1QZWF/RBk4ZKUNUGdtZtR8Qg27H5AsLRW
nkaoOj4jkToA0B38UHWMNzu5Y1kYk0HQ1QdDteSnJe2J5zIToddEGeyOMxfJ8W/EZyys+QWbmlsN
pfRCb2yQQDHIC2SOhP6XAeiD5id3Pt95txWefJsY7MYRr3/t7q2LnxQtLidgbU7KeSDzBcWc9u8x
yxujc3qCKIL2Eiu2Xbb21nfZy2NJYLyNxa9krTVhYR411Qe8+0X3M4y+ig413Hc7H5NgEdvyNgrB
NTQGdgFWk+JGiD17att7iCG8tJor2zuQH215AQ+ORp1Ba4VBQWxPNFpG9zaepQaXyjDWXIIduRtm
zStH0TfleK+TgKoON2dzzLt3kBLg8pcPxLnfVZv+uKlf1ROq0/FtCg63gu57ubjIsls2WT8BPHaT
yxP3smfNH7m4MIq2g0IJKCSy9kkyvG10c75YnA0q5zSw7vMUPRAPuwy+jLXNaHENiaSBV3kgRz4r
s5Fpc5zoGsZISSCC766Bw9KIOc83fiOXSP4gL+O6yOPvrK9v8TG/+pHG3c5jpGeRr/h6IOlYq1bY
45lnbwtNAN8baeHWiDz/AN0vt8x/MLbJ5/j1o5ufkLpy6Joa6d9KmrRoSfXr5oPDNj275ZdZf+zj
BXk142Uwvt4o3OduBoRoPRB7Z7Y/ZfeZeG2yvMLS5wtk4BwtHyA3D/E/02j6R8UHt3ifbHiHA7Fm
P43hIrEn6X3lN1xJ6uedfwQZy5s2wMMrCAAdQDqQOqDQctyKS1a5rJdvnQoOU5rls0m7dIXDXWqD
lGXzP7guqanUoOe5C63EkdNaoNZuJASSgwU5rUoMXLrUdEGMk0QVHoKjwgqPQVnBBE4IKz0GpIGH
qgUCqByAQCAQCAQPAGiBUAgEDx0QKgEDmoHIHNQSNQOQKOoQPQSNPRBIgVvVBO31+SCUaFBMwoJg
UEzTRBaYSgssKC4x1CEF6KWlKnTwQZKOXVBk7ectI1QZmC4d1BQbJa35bQE6eaDa7DKuYR9R0og3
3F8icwgCWnw6oOr4LloY5m51QSK6/wCaDsOKzGOyTGx3bIpY3AsdE4At2mhIodDX1QcR7n/a9xrm
rZ8nwttvjcw5pe6ye0GCQnXR36T/AAQfO3nfbfl3Ar2XHZrCS2ftOIa4M+hw82kChHqg49ILiO5b
MzdFLE4OY8aEEagoPdHZXkHIc7hpb/t1cssuRcfjMvLO3N655xeUia2n7qydqbaSQj6wPpY/6tIy
Q0PUnHO4XEuTC1tbm5/6X5BM72ZuOZdzbe4ZO2m6JpcQ1510p1Hgg2y+xsjJdjwRH0J8QUGCzWKt
57J1u6MEFpDh1On+9B5DyvIeW8X7p4nh/E8N+/x87Jr3NOtoGyTTPu7WS1Y+Z76Na21a8ObUgVNT
X6aB6Rs4Jre0to5HulkihijuJjQ75GsAc8keLjqgjvLaO4fbwv8AejkYBO24iJYWndQAP8zTUDw6
oNN7m5y64jwPK5nFXJtb22LPau3tEj3SfoDqgh1XAAgjUaaIOD/b5Z3M+Uz/ACTIXUtznMjag5Ge
WpcTdz+6S9x6OpGNPIoPbmBxGUyRi9iF8ULhQzEU3D0qgy9zk8PYXTsHx8f37kjyWPEFX29q8f8A
yvboXD+Vv/qog7Bwztri+PxPv7+Nl5ya8/q5HIPa2rZX6kN2gAEeNAg3ibHzQlz43gtGpd8ugQap
l7+C3YfeaNwBrrQj8EHG+Q8lawSNil0AP0nSiDhmczb5XPq+tT/4IOZ5K9L99HedUGl3lw7XVBrV
zNWor51QYSaSpIQY2V3VBjZndfUoMfIUFVwqEFZ4QVHDzQVnePqghd0QV39Cg1BAw9UD+iAQCAQC
AQCCRAIBAo6oHoBAIHNQOQKOqCQdUD0AEEiBzUEo6IHtQStKCVBI09EE46IJWFBZa5BYa5BajdVB
ZY4oL8b/ADKDIRPpTVBk4JiKIMtbzmoNenUVQZ23uuh3fxQbBaXxFKOog2/HZd0bm/XqPVB0XD8n
lhLD7hPTxQdm49zrZsDpNoBp10QdPnm4XzXGnF8nxdvmLaRpbWZo3sr1LHjVp+CDzDzX7LeH56d9
/wAPz0mKZKatsbprZGgk9GuBaSAg7l9rv2jZLtzyu0zmQu7eS1imZLd3r5GbHRs1LGtBNQelD56o
LncPs3wjvXyPuHZOxUN/b8dvruPDZCwox81paQ++/wBuZnSWCjwx2oeBtcPpBQedb7jPfHsnjmZT
Gmbvf2qjYHEP3HL42ClRV7Q9xYB4nezT9CDYOJdzOCdw4Q3j2Va3Jlm6fjt9S3v4nU+oCMmkgHnG
SEGTixtpjsjkL5lsBdZIRsvZnCrntiFGNqegHkEGRs8fbhr2sBuGPqGscBuYw0+gOJrQHUIKN9i5
4Zm+2HSwkBkNerR4NQZi0wlsLVkmQt47v62yQwSND2hzTUOo4EVCDHuw3DuP5DKc0y5hxTbxsLcn
cPNIZZIt2wshaPqldup9IJOiCzjZea91YHvw8E3Bu3EdWS5aYbLzItBoRHtIIYR4MIHm/wDSg7jx
HjOC4Nbx29jYft7xpayFsg/rMOlJJqgVkcPysAAaPqI6IOkPks6B5d7UgG5xB111NfNBpmb5Kyzh
exkwePTr80HCORcvdO6Ue58Sg4zl80ZHO+vXw1Qc8vr8vJJd/FBql3c1J1618UGuXEta+Q6IMFcO
6mvWqDDTO6mvigx0rtDVBj5H1JQU3lBXcUFZ7tSgquKCu7xQQnoggeND8EGnoG/qQOQCAQCAQCAC
CRAIBAreqB6AQCBzUDkCjqgegkQCCQdAgUdUEg6oHoJGlBOCge1BO1BIOqCdpQTtKC0x1EFlrvVB
ZY9Bfim6IMhFLSmqDIxTkHQ/EIMrBP01QZmC5p4nx0QZq1vaU+o1CDYbTIubQ7tKINtsc45hH1H+
CDesXyyeIt/rEVQdWwfcB0ez3JS4D1qEHTbbk1hnY2W947dCTqN5b16/lIQdn4ByTi/C7a9nsMbI
6/itpYcRbW+0Qe5PC+Fz5yTUgNkNAOp6oDtXiL3E4PEiZhikuZb6WXHuLXbLaW7kdA120mlWGoB1
AQYPu99jvanvRbT5rFQu7e86k/rW3KcUzaz3xq03Vs0sDgT1ewtf41PQh8yubZTvz9sHKxwXvTgP
+rcNuDcHymFxreW40bJbXm1rZtOrJQH+BKDN4b7oe1VxeR210/K4QPoP3d9Z0iDvJxikkI/BB6cx
OWwPIcVDl8TlLS+xpG9t/byNfER41cDQHzBog5LyvvNxnGZdnEOK2d1z3nN3I22sOPYiN0rP3D67
InysBG4dXNYCQOtEHduB/bleuis+ed+b6PKchDPds+DxaYzFAmrYnjpNLoN1Kt8C5/gHQ8zyCSCe
3ZjMeZbiPTD4ljfbEYYaNmeSNsYaRoSKDwDnUaAxVu1tgDkMtejIZebc58lT7MO87nMha4l2p6ud
VzjqUGoZ3l5Zv2ybaCgIKDjuZ5XNIXbpNwPTXwQc0yWaMu47jrVBpd7fl1fqPX/JBrVzc6GhQYK4
n61OtUGEmmJrQ6aIMRNLWupQYyV1SUGNmeKEV1QUHuQVif8AggrPcgrPNaoK7vJBA49UEbuiCBx6
+gQaZr6oHD16oFQCAQCAQCBR1QPQCAQKK9QgegEAgeBRAqBzUDkEiAQPHRAqB4KCVAoOqCZp/ggl
CCVp/igmBqgkaUEzXIJ2uQWGPQWWuqgsMegtxykU1+KC/FN0NahBkop6UoUGRiuR5inmgykN1ShJ
HyQZeC+GlCEGVhvqePmgzltky2n1fPVBs1lm3MpST4HVBu2L5TNA5tJT9Pqg6lhucvDWB0u7zJKD
r3HO4k1jKy4tL0wzAiorVrqeBaagoPVfBPuAwLhb2XKLU2JcQBlLcGSEHzfH+dvxFUF7nr+2Xezh
GR4P3BtTlcdcXN0bLNYyCS5hsJI3P9i8jkZ7hYfa27mO/MSQAQg+LHef7VrvtvyiTDcgxvu4q4YH
YflWI/Je2uobctqXRveNA9p8qGh1QcJj7B93jy607bcLxN9ysctYy4xN/hpZWYq+tQQTNdDQRe0T
9bXkbT8qh9m/tr+2niH2ycdvMpe3FtyLuRkYfb5LzENrHZxOALsfjSdQ0n87gAX9DpQIL/L+cvus
zMyQxzWdu0iK0qaNld1L3DQkeh0+KDluQ5TFB7rhta6QfUWCladK/DwQcyzXLTIH7ZCPClUHMMpy
Jzy7+oTVBol7ld5P1fHqg1i5vid2o1qgwc93UnUeqDBz3YNSD4IMRNcVJ+OlUGMlnJJofwQY2WX1
QY6STr/BBj5HddUFVxqUED3IKzygruP8EEJP4oID1QMcUEDzofUINRQCAQCAQCAQCBzUDkAgEDm9
EDkAgEDwa/JAqAQSIHjogVA5qByBWoJAaIHoHtKCdpQOQStcgmBqgka5BOHIJQ/ognbIgsMkQWGv
PUFBZjmIogvRz/7VQXY5zp/vQZCO6pTVBeiuvWnzQZKK7IprU+hQZKG9I8Sfmgy0F+RSrqfNBmLf
JFtPq8fNBsNnnHMIo8inig3DH8mlaW0l6eqDfsZy19W1lr8/8EHRcJy6WG8xt3aTmO7xN3Ff4+Qm
ojuYXBzJaGoJBHiKEaHRB3+TlNp3Dwl1ieViNt3eXTLkZS3jjEe9kbIw90T2SkSODSHSMLatoC00
QZrtzxHEcOeb+45T/Z8De23v2+63kDp7v2/rjbCwCQAO+mTb9A61OiDQu4XOsxmZHRNndaYeMRui
xbS1zWSRjVweGsOrvqpRBwW/5KGBza7SK1ANAg0DJcjc7cN/U9EGj3uZL61cdUGqXeRJc76qanWq
DAT32tS/r6oMPPek1odPOqDES3ZJOtfmgxktx1+quiDHyTE+KCjJLTxQUZJOpqgpSPr4oKT3Vqgg
c7yQV3OQV3FBA4oISfxQRk0QQuKCF3Q/BBqiAQCAQCAQCAQSIBAIBAoNED0AgEDmoHIBA5p8EEre
iBUAgkQCB4NUDwfBA5BI1yCUH8EDwfFBKD5IJWnzQSB3mgla5BKHIJWu6ILDHoLLXj5oJ2yUQWmz
UQWWT9NUFyO4IQXWXB6hyC7HdEdSgyEV9rqfkUGQjvqU+qiDIxZAin1VHxQZW3yhaQd1Pmg2a0zL
tCH+KDdsXyH2i079UHU8Hz19tsHu0Aog3R/c53tbTJqR9Lgg0zK8z98P/qirtSfP/cg5jlM22YuO
6iDSrvJGrhvrrrqg1+e/JrUkfNBhbi+6/VXqgws14T4oMZLdeZ+SCjJcE1oaVQUny/h4oKj5uoBQ
UXz/AO1EFR8xPyQV3Pqggc4IK73oK7nIIXO/8UETj+CCInxKCNzkELvJAw9D8EGqIBAIBAIBAIBA
8HRAqAQCAQPHRAqAQCB4NUCoFHVBK0+CByAQOB8EDkAgkB8UDwaoHA0QSAoJAUD6oHhyCUOQSAoJ
A7/ggla/ogma9BK2RBO2X1QTNkQTtkognbN016eqC2ycV6/xQW2T+qC02cdf80FhlyR0PT1QW47w
jqf4oL0d747vlVBlrbJOaQK9dEGahyzwa7iPmgzMGdlbSkh0prVBkByKWgrIfxQRyZx7xq7+KDDX
GWdrV9ajzQYmXJVr9f8AFBiZr461dX5oMXLd1JNa/NBQkuSfGiCk+evigrumHmgqSXFdAgpvlrXV
BXc/yQQl3qghc9BC56CFzkELighcUESBhP4IIifFBGga40BQaqgEAgEAgEAgECg0QPQCAQCBzUDk
AgECt6oHoBBIgeCEBUeaBUDwUBUeaBwNEDw6iB9R5oHA/ggkDgPFA8O9aoHgg+KB4d4VQPDqeKCU
OHnRA8Op4oHiT1QSiT1QStkHmgmbJ6/xQStlp4oJhK3z/iglbKB0d/FBO2f/AFfxQWG3frp5IJ23
Q8a6ILLLlvg74oLDblv838UFuO8Ap9f8UGSiyDaV3aePRBbbkQP1oJxkwf10+aAORHi/r6oK8t80
1G/SngUFCS8A/K6n4IKT7vdoX/4IKz5x/MPxQV3zj+b+KCq+Ya0d8NUFV03qgruk9UEJkH8w/FBG
ZB5j8UELpK/qQRF/qgiLvVBCXDzQROePNBGTXxQMLh4FBGXDzQREivVAVHmgic7r/BB//9k=
"""
bg_b64 = \
"""iVBORw0KGgoAAAANSUhEUgAAAAEAAAJYCAIAAAAsaRvIAAAABGdBTUEAAK/INwWK6QAAABl0RVh0
U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAIiSURBVHjalFMJksQgCARzabL//y7LKcZk
pnZnqguCKNC2AP/94WjxFhoTEFFdlD8OgCnmuZY/5ZZy/55Q1Ba14euegooia8WAJf0xfscyoMDC
dlk4vizm63dajfO6xj5ihVXsuphVn2Orrem6roldzYZ/w/aMbStsq2OT703ttoa/mV3Nn7FvO2y7
+7v4hn2377/gcOyH2MPB/uG+xA//HlC7rRmvhlolVtm6X6vaGa02toxW1TaJNYu1Zn6rjmY4W/qG
c1g74TzZPz1+yveE64TL/Sv86+Jvw8X+ZbawtG8QrV8/F/zIGutVclBEC8QQq+uq3nkviJwlTlCI
8y2HNC57SXKI/LzcI/mgr4H3Ia8T5+pZli+PhnQfeA9jP+TnZAylfux/BWbtnOvZW3CCoL1rX1Ev
zuF+geMYc2CeZ/OA9dNzIftGmXmo/+AkObX6wSU893ziE2xGnavzQnbeyKX3aftRLVHUn3j6Arxx
8y0P+10LLwTJC0LqBd/uLniM85V/uxfyuS3uOc5J6JGmPjQW2v2qmeDJe+h9Us409Zx3AKlfknp+
92TafZ912u9+nKNvAvCh9X7now5veka9Wxx4H3X4qZe8X6tpOiPXOXZ9EuEw72dd9zsKrfhbV57H
N+X59NDYeLeQtTF5RUpO8o3G/u+axmEWq+t8vfKN/f2Q53Y+6a32WGOYA00fEO/DNR3coHPzfMfD
vb3U+YJfAQYA+QusQdBehRsAAAAASUVORK5CYII=
"""

bgcode_b64 = \
"""R0lGODlhBQAFAIABABQUFPz8/CH5BAEAAAEALAAAAAAFAAUAAAIIjAMHibz2TAEAOw==
"""

quote_b64 = \
"""R0lGODlhFAAPANUAAElJSVRUVC4uLiYmJkVFRQgICCkpKTg4OC8vLzIyMjo6OktLSywsLD8/Pyoq
Ki0tLVVVVQ4ODgsLC0FBQSQkJDMzMzc3N0hISFZWVhAQEDQ0ND09PTw8PDs7OwUFBRsbGysrKxYW
Fjk5OVlZWVBQUCcnJ1NTUxMTEzExMU9PTxkZGUdHR01NTURERFJSUigoKEJCQjY2Nj4+PldXV0ND
Q05OTkBAQDAwMDU1NQMDA////////////////////////yH5BAEAADkALAAAAAAUAA8AAAbZwJzQ
YwDUGAWh8CMLAAQSpQcHQwgImJvwloo5KjSc8kYblByCxKyQcRlKhgdqMRAGQC8QIoFbUCoyBg4P
CRY2ADknJA4MCBoKHQQHNBaNCSIyEyM5KjUPNzgcExM1FDQKN482LQsyOREmKDgNNCs1azINoQQE
NRAfQjUHIgABARUZOUUHTSMHIUoCFwo2GHVCBTMdGzViSjkSADYyBDMMYywbNibeSgMzNDY0ASdK
ODUNDSkU3znvFzYgRPiGg4SNBQL65QhxAIKWfjdm3Iii8FXFHEkuauwXBAA7
"""

bgmenu_b64 = \
"""iVBORw0KGgoAAAANSUhEUgAAAJUAAABQCAIAAACf5aAfAAAABGdBTUEAAK/INwWK6QAAABl0RVh0
U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAANeSURBVHja7JzrcqswDISDIXfCMLm8/4uS
cMQRdRSBKUwJRjPrHwwpX9zMbiRMVSspyzIRI01T5xydbP6P1+tV1/UmMAiWLwF/FSaAMDp5Pp/M
00h3u513iyF/pEGXmOudl2Zh1wF/G65/hreJ7UyKoqDXHHM8HUdh19TQkJ+DfxngWWAVS+SRZ+hI
UUiXksvlwlPwZT5yzI7/HP5dgGeHZdgR7F/SkSxM8jyXkSdPZFBy2h3O0dJvwPPC3jb2+50/yT8V
yPK8G4UDn0MufADPBat7nkqkTf6UqxU5C593V0pId4vB6hboXfRR2ObP1syf5OmPyGAR4aqqetcy
0sLkfD7ze7yF3RBEuosIy6hVjxCNVeSf90kFuApEpLtYcO9zRevR6XRSj3psLDJYdNgDBIeewpPj
8TjpkRPpbmGYmZAp6Xa7Vbc66Xx3qEuA48Jv/8ZbCHg98Id/kMMcrP2DdrbgHv+gnSG43z9oZwUO
+gftTMBD/kG79cO/+AftVg6n+/0ectiF2/9fghxG4cY/yGEXbv2DHEbhZv0COezCaZZlkMMuPLl+
BHhVMOpHtmHUj2zDqB+hfgQ4Hoz6EepHgOPBqB+hfgQ4Hoz6kW0Y9SPbMOpHtmHUj2zDWVEUcrf7
1P4v2DS0DLz57P/CfPP84PdvSrcn9X+R3xrA88K+T4E/l1tw6edpnudqwx8TcsaBr4bf1+Q3Dg5s
PwM8CVbb3tVJu1/68XjIzi/trupO8xA02okFyyiiRFqLUVVVcr/f2a1Np/8Lp92R90LsvvwGHGoe
8u7/Qv55w1QXn2Z5k2VYR8SFf+n/QvlT9X+Ry5neqQeygfoqAf4jrNYfPnNyamzjL9T/JdSFCbGy
cP8XtZD86P9yu93G9H+B0LHg3v4v3sLGv824/i+qkdZwNgA8Ixxq4dO4c71eu4ufbgstxMrysOz/
EvpTQFKW5aTbLIReGGYmZEp6OBzaTlqiTxYar6wNDpnieh8wVQru/uEH8EpgBzlMww5ymIYd5DAN
O8hhGnaQwzTsIIdp2EEO07CDHKZhBzlMww5ymIYd5DANO8hhGnaQwzTsIIdpGPUj2zDqR7Zh1I9s
w6gfoX4EOB6M+pFtGPUj2zDqR6gfAY4Ho36E+hHgeDDqR7bhfwIMAIc9EWduE4gCAAAAAElFTkSu
QmCC
"""



def buildHTML(*args):

    if len(findings) == 0:
        print "No findings to report"
        sys.exit(0)
    swfAnalysis = list(args)
    
    htmlReport = """
<html xmlns="http://www.w3.org/1999/xhtml"><head>
	<style type="text/css">
		/*
Template name: Blackbox
Template URI: http://templates.arcsin.se/blackbox-website-template/
Release date: 2006-06-01
Description: A mystic dark lightweight design.
Author: Viktor Persson
Author URI: http://arcsin.se/

This template is licensed under a Creative Commons Attribution 2.5 License:
http://templates.arcsin.se/license/
*/
*{margin:0;padding:0}a{color:white;text-decoration:none}body{background:#000 url(images/bg.png) repeat-x fixed left bottom;color:#777;font:normal 0.8em sans-serif,Arial;margin:20px 0;text-align:center}ul{margin:12px 0}li{list-style:url(images/li.gif);margin-left:18px}code{background:url(images/bgcode.gif);color:#777;display:block;font:normal 2em "Lucida Sans Unicode",serif;margin-bottom:12px;padding:3px 6px;white-space:pre}cite{background:url(images/quote.gif) no-repeat;color:#777;display:block;font:normal 1.1em "Lucida Sans Unicode",serif;margin-bottom:12px;padding-left:28px}.main{background:#000;border:3px double #EEE;border-color:#141414 #202020 #222 #202020;margin:20px auto 4px auto;text-align:left;width:600px}.gfx{background:#777 url(images/dark_pixel.jpg) no-repeat;height:240px}.gfx h1{color:#999;font:normal 2.6em Tahoma,sans-serif;padding:16px 20px}.menu a{background:#000 url(images/bgmenu.png) repeat-x;border-right:1px solid #222;border-top:1px solid #1A1A1A;color:#777;float:left;font-size:1.2em;padding-top:4px;width:149px;height:36px}.menu a span{padding-left:6px}.menu a:hover{background-position:left bottom;color:#888}.menu a#last{border-right:none;width:150px}.content{background:#1A1A1A;border-top:1px solid #1A1A1A;clear:both}.content h1{color:#999;font:bold 1.1em sans-serif,Arial;margin:0 0 4px}.content p{margin:0 0 12px}.item{background:#030303 url(images/bgitem.gif) repeat-x;padding:8px 10px}.resultTitle{font:normal 0.8em sans-serif,Arial; color:white}.result{padding:8px 10px;display:block;font:normal 0.8em sans-serif,Arial}.footer{background:#0A0A0A;color:#666;padding:5px}.footer .left,.footer .right{padding:0 12px}.footer .right,.footer .right a{color:#444}.footer .right a:hover{color:#999}.left{float:left}.right{float:right}.clearer{clear:both}
	</style>
<title>Deblaze - A remote method enumeration tool for flex servers</title>
<script>
function showhide(id){
        var divCollection = document.getElementsByTagName("div");
        for (var i=0; i < divCollection.length; i++) {
            if(divCollection[i].getAttribute("class") == "item") {
                if(divCollection[i].getAttribute("id") == id){
                divCollection[i].style.display = "";
                }
                else{divCollection[i].style.display = "none";}}}}
</script>
</head><body>
<div class="main">
<div class="gfx"><h1>Deblaze</h1><h4>A remote method enumeration tool for flex servers</h4></div>
		<div class="menu">
		<a href="#" onclick="showhide('1'); return(false);"><span>SWF Analysis</span></a>
		<a href="#" onclick="showhide('2'); return(false);"><span>Methods</span></a>
		<a href="#" onclick="showhide('3'); return(false);"><span>Errors</span></a>
		<a href="#" onclick="showhide('4'); return(false);"><span>Empty Results</span></a>
		<!--	   <a href="#" onclick="showhide('3'); return(false);"><span>About</span></a>-->
	</div>

        ---SWF---

		---METHODS---
		
		---FUZZ---
		
		---EMPTY---
		
			<script>
		showhide('1');
		</script>
<div class="footer"><span class="left">2009 deblaze-tool.appspot.com</span>
<span class="right"><a href="http://templates.arcsin.se/">Website template</a> by <a href="http://arcsin.se/">Arcsin</a></span>
<div class="clearer"><span></span></div>
</div></div></body></html>
"""

    dirname = 'report' + datetime.datetime.now().strftime("%d%B%Y-%H%M%S")
    print "Generating Report - " + dirname

    if not os.path.isdir('./' + dirname + '/'):
        os.mkdir('./' + dirname + '/')
        os.mkdir('./' + dirname + '/images/')

    res = ''
    reserr = ''
    resempty = ''

    for finding in findings:
        if(finding['error'] == 'true'):
            reserr += '<div class="item" id="3">'
            reserr += '<table>'
            reserr += '<tr><td class="resultTitle">URL</td><td class="result">' + htmlEncode(str(finding['url'])) + '</td></tr>'
            reserr += '<tr><td class="resultTitle">Service</td><td class="result">' + htmlEncode(str(finding['service'])) + '</td></tr>'
            reserr += '<tr><td class="resultTitle">Method</td><td class="result">' + htmlEncode(str(finding['method'])) + '</td></tr>'
            reserr += '<tr><td class="resultTitle">Params</td><td class="result">' + htmlEncode(str(len(finding['params'])) + ': ' + str(finding['params'])) + '</td></tr>'
            reserr += '<tr><td class="resultTitle">Result</td><td class="result">' + htmlEncode(str(finding['result'])) + '</td></tr>'
            reserr += '</table>'
            reserr += '</div>'
        elif(finding['result'] == 'None' or finding['result'] == '<flex.messaging.io.ArrayCollection []>'):
            resempty += '<div class="item" id="4">'
            resempty += '<table>'
            resempty += '<tr><td class="resultTitle">URL</td><td class="result">' + htmlEncode(str(finding['url'])) + '</td></tr>'
            resempty += '<tr><td class="resultTitle">Service</td><td class="result">' + htmlEncode(str(finding['service'])) + '</td></tr>'
            resempty += '<tr><td class="resultTitle">Method</td><td class="result">' + htmlEncode(str(finding['method'])) + '</td></tr>'
            resempty += '<tr><td class="resultTitle">Params</td><td class="result">' + htmlEncode(str(len(finding['params'])) + ': ' + str(finding['params'])) + '</td></tr>'
            resempty += '<tr><td class="resultTitle">Result</td><td class="result">' + htmlEncode(str(finding['result'])) + '</td></tr>'
            resempty += '</table>'
            resempty += '</div>' 
        else:
            res += '<div class="item" id="2">'
            res += '<table>'
            res += '<tr><td class="resultTitle">URL</td><td class="result">' + htmlEncode(str(finding['url'])) + '</td></tr>'
            res += '<tr><td class="resultTitle">Service</td><td class="result">' + htmlEncode(str(finding['service'])) + '</td></tr>'
            res += '<tr><td class="resultTitle">Method</td><td class="result">' + htmlEncode(str(finding['method'])) + '</td></tr>'
            res += '<tr><td class="resultTitle">Params</td><td class="result">' + htmlEncode(str(len(finding['params'])) + ': ' + str(finding['params'])) + '</td></tr>'

            if isinstance(finding['result'], ArrayCollection):     
                res += '<tr><td class="resultTitle">Result</td>'
                for item in range(finding['result'].length):
                    res += '<td class="result">' + htmlEncode(str(finding['result'].getItemAt(item))) + '</td>'
                res += '</td>'
            else:
                res += '<tr><td class="resultTitle">Result</td><td class="result">' + htmlEncode(str(finding['result'])) + '</td></tr>'
            res += '</table>'
            res += '</div>'
            
    if len(swfAnalysis) > 0:
        resswf = '<div class="item" id="1"><table align="center">'
        resswf += '<tr><td class="resultTitle">Gateways</td></tr>'
        for gateway in swfAnalysis[0]:
            resswf += '<tr><td class="result">' + htmlEncode(str(gateway)) + '</td></tr>'
        resswf += '<tr><td class="resultTitle">Services</td></tr>'
        for service in swfAnalysis[1]:
            resswf += '<tr><td class="result">' + htmlEncode(str(service)) + '</td></tr>'
        resswf += '<tr><td class="resultTitle">Methods</td></tr>'
        for method in swfAnalysis[2]:
            resswf += '<tr><td class="result">' + htmlEncode(str(method)) + '</td></tr>'  
        resswf += '</table></div>'
    else:
        resswf = '<div class="item" id="1"><table align="center"><tr><td class="resultTitle"><br>No SWF file</td></tr></table></div>'
      
    htmlReport = htmlReport.replace('---METHODS---',res)
    htmlReport = htmlReport.replace('---FUZZ---',reserr)
    htmlReport = htmlReport.replace('---EMPTY---',resempty)
    htmlReport = htmlReport.replace('---SWF---',resswf)    
    
    f = open(dirname + '/index.html', 'w')
    f.write(htmlReport)
    f.close()

    dark_pixel = base64.b64decode(dark_pixel_b64)
    pic = Image.open( StringIO.StringIO(dark_pixel))
    pic.save(dirname +'/images/dark_pixel.jpg', format= 'JPEG')
    
    bg = base64.b64decode(bg_b64)
    pic = Image.open( StringIO.StringIO(bg))
    pic.save(dirname +'/images/bg.png', format= 'PNG')

    bgcode = base64.b64decode(bgcode_b64)
    pic = Image.open( StringIO.StringIO(bgcode))
    pic.save(dirname +'/images/bgcode.gif', format= 'GIF')

    quote = base64.b64decode(quote_b64)
    pic = Image.open( StringIO.StringIO(quote))
    pic.save(dirname +'/images/quote.gif', format= 'GIF')

    bgmenu = base64.b64decode(bgmenu_b64)
    pic = Image.open( StringIO.StringIO(bgmenu))
    pic.save(dirname +'/images/bgmenu.png', format= 'PNG')


def htmlEncode(s, codes=htmlCodes):
    """ Returns the HTML encoded version of the given string. This is useful to
        display a plain ASCII text string on a web page."""
    for code in codes:
        s = s.replace(code[0], code[1])
    return s
    
class Deblaze:

    url = ''
    gatwayurl = ''
    service = ''
    method = ''
    creds = ''
    cookies = ''
    agent_string = ''
    params = ''
    fuzz = False
    methodsArray = []
    gatewaysArray = []
    servicesArray = []

    def __init__ (self, url = None, service = None, method = None, creds = None, cookies = None, agent_string = None, fuzz = False):

        self.url = url
        self.service = service
        self.method = method
        self.creds = creds
        self.cookies = cookies
        self.agent_string = agent_string
        self.gatewayurl = url
        self.fuzz = fuzz


    def auto(self):
        for gate in self.gatewaysArray:
            for serv in self.servicesArray:
                for meth in self.methodsArray:
                    self.method = meth
                    self.service = serv
                    self.gatewayurl = self.url + gate
                    #print "Gateway: " + self.gatewayurl + " Service: " + self.service + " Method: " + self.method
                    self.run()
        return
        
        
############################
# Simple Fuzz Function                              #
############################
    def fuzzReq(self, dblzResult):
        fuzzstr = ["'","*","@","%","<",">","(",")","?"]
        pcount = len(dblzResult['params'])
        newparams = ''
        if pcount > 0:
            for fstr in fuzzstr:
                newparams = ''
                for i in range(pcount):
                     newparams += fstr + "|"
                newparams = parse_params(newparams[0:-1])
                d = Deblaze(dblzResult['url'], dblzResult['service'], dblzResult['method'], self.creds, self.cookies, self.agent_string, False )
                d.run(*newparams)
    
    def run(self, *params):
        """
        Takes a url, service, method, credentials, cookies, useragent and parameters and makes
        the Flash remoting call.   Evaluates the response for enumerating 
        valid services and methods.  Fingerprints Flex technology based on
        responses.
 
        @return: Nothing
    
        """    
        gw = RemotingService(self.gatewayurl, user_agent=self.agent_string)
        
        amf_server_debug = {
        "amf": "true",
        "error": "true",
        "trace": "true",
        "coldfusion": "true",
        "m_debug": "true",
        "httpheaders": "true",
        "amfheaders": "true",
        "recordset": "true",
        }
    
        gw.addHeader('amf_server_debug', amf_server_debug)
    
        if self.cookies:
            gw.addHTTPHeader("Cookie", self.cookies)
    
        if self.creds:
            self.creds = self.creds.split(':')
            gw.setCredentials(self.creds[0], self.creds[1])
    
        targetService = gw.getService(self.service)
    
        try:
            methodcall = getattr(targetService, self.method)
            result = methodcall(*params)
        
            if result is None:
                if not options.quiet:
                    print("Empty Response - Valid service (" + self.service + ") and method (" + self.method + "), try different parameters")
                dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','false')])
                findings.append(dblzResult)
                if self.fuzz:
                    self.fuzzReq(dblzResult)
                return
        
            if isinstance(result, pyamf.flex.ArrayCollection):            
                collection = ArrayCollection(list(result))
                if collection.length == 0:
                    if not options.quiet:
                        print("Empty ArrayCollection - Valid service (" + self.service + ") and method (" + self.method + "), try different parameters - BlazeDS")
                    dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','false')])
                    findings.append(dblzResult)
                    if self.fuzz:
                        self.fuzzReq(dblzResult)
                    return
                if not options.quiet:
                    for item in range(collection.length):
                        print(str(collection.getItemAt(item)))
                dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',collection),('error','false')])
                findings.append(dblzResult)
                if self.fuzz:
                    self.fuzzReq(dblzResult)
                return
        
            if isinstance(result, (pyamf.TypedObject, list, unicode)):
                if not options.quiet:
                    print str(result)
                dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)), ('error','false')])
                findings.append(dblzResult)
                if self.fuzz:
                    self.fuzzReq(dblzResult)
                return
    
        ############################
        # Error Detection                                      #
        ############################    

            if result.code == "Server.Processing" and result.rootCause is not None:
                if not options.quiet:
                    print str(result.rootCause)
                dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result.rootCause)),('error','true')])
                findings.append(dblzResult)
                if self.fuzz:
                    self.fuzzReq(dblzResult)

        ############################
        # Service Detection                                  #
        ############################
        
        #AMFPHP server error message for incorrect Service - missing class/file
            if result.code == "AMFPHP_FILE_NOT_FOUND" and not options.quiet:
                print("Service %s not found - AMFPHP Server" % (self.service))
                return
            
        #BlazeDS invalid services - No destination with id 'products' is registered with any service
        # Service is Case Sensitive for blaze!!!
            if result.code == "Server.Processing"  and not options.quiet:
                m = re.findall("No destination with id '.*' is registered with any service",result.message)
                if len(m) > 0:
                    print("Service %s not found - BlazeDS" % (self.service))
                    return
         
        #GAE Python invalid services - 'description': u'Unknown service ProjectsServicze.get_by_code'
            if result.code == "Service.ResourceNotFound"  and not options.quiet:
                m = re.findall("Unknown service",result.description)
                if len(m) > 0:
                    print("Service %s not found - GAE Python" % (self.service))
                    return

       
        ############################
        # Method Detection                                  #
        ############################
        
        #GAE python
            if isinstance(result, pyamf.remoting.ErrorFault) or isinstance(result, pyamf.remoting.BaseFault):
                if result.code == "Service.MethodNotFound": #gae python 
                    if not options.quiet:
                        print("Method %s not found on service %s - GAE Python" % (self.method, self.service))
                    return
                           
        #AMFPHP The method {getServicesq} does not exist in class {Discoveryservice}.
            if result.code == "AMFPHP_INEXISTANT_METHOD":
                if not options.quiet:
                    print("Method %s not found on service %s - AMFPHP Server" % (self.method, self.service))
                return
           
        #Blazeds wrong method 
            if result.code == "Server.ResourceUnavailable" and result.level == "error" and result.details is not None: 
                m = re.findall("Method '.*' not found",result.details)
                if len(m) > 0:
                    if not options.quiet:
                        print("Method %s not found on service %s - Livecycle Data Services/BlazeDS" % (self.method, self.service))
                    return
        
        ############################
        # Parameter Detection                              #
        ############################
        
        #Livecycle Data Services/BlazeDS
            if result.code == "Server.ResourceUnavailable" and result.details is not None: #Blazeds params wrong
                m = re.findall(" arguments were sent but ([0-9]) were expected",result.details)
                if len(m) > 0:
                    #if not options.swf:
                    #    print("Error method %s requires %s params - Livecycle Data Services/BlazeDS" % (self.method, m[0]))
                    newparams = "0"
                    for i in range(int(m[0])-1):
                        newparams = newparams + "|" + str(i)
                    newparams = parse_params(newparams)
                    d = Deblaze(self.gatewayurl, self.service, self.method, self.creds, self.cookies, self.agent_string, self.fuzz )
                    d.run(*newparams)
                    return
                #check for parameter type problem
                m = re.findall("The expected argument types",result.details)
                if len(m) > 0:
                    if not options.quiet:
                        print(result.details + " - Livecycle Data Services/BlazeDS")
                    dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','true')])
                    findings.append(dblzResult)
                    return

        #PyAMF server error message for parameters
            if result.code == "TypeError":
                m = re.findall("takes exactly ([0-9]) arguments",result.description)
                if len(m) > 0:
                    if not options.quiet:
                        print("Resending with " + m[0] + " parameters - PyAMF")
                        dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','true')])
                        findings.append(dblzResult)
                    # some methods are like this     def get_by_code(self, code): and really take 1 parameter but say 2
                     #   print("Error method %s requires %s params - PyAMF Server" % (self.method, m[0]))
                    newparams = "0"
                    for i in range(int(m[0])-2):
                        newparams = newparams + "|" + str(i)
                    newparams = parse_params(newparams)
                    d = Deblaze(self.gatewayurl, self.service, self.method, self.creds, self.cookies, self.agent_string, self.fuzz )
                    d.run(*newparams)
                return

        #AMFPHP server error message for parameters"
            if result.code == "AMFPHP_RUNTIME_ERROR":
                m = re.findall("Missing argument ([0-9])",result.description)
                # not just for param errors
                if len(m) > 0:
                    if not options.quiet:
                        print("AMFPHP resending with" + m[0] + "parameters")
                        dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','true')])
                        findings.append(dblzResult)
                    newparams = "0"
                    for i in range(int(m[0])-1):
                        newparams = newparams + "|" + str(i)
                    newparams = parse_params(newparams)
                    
                    d = Deblaze(self.gatewayurl, self.service, self.method, self.creds, self.cookies, self.agent_string, self.fuzz )
                    d.run(*newparams)
                else:
                    if not options.quiet:
                        print(result.__dict__)
                    dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','true')])
                    findings.append(dblzResult)
                return
                    

        
        #Other error, print it all out
            if isinstance(result, pyamf.remoting.ErrorFault) and result.details is not None:  
                print "Other error: " + str(result.details)
             #   dblzResult = dict([('url', self.gatewayurl), ('service', self.service), ('method', self.method),('params', params),('result',str(result)),('error','true')])
              #  findings.append(dblzResult)
        
        except KeyboardInterrupt:
            choice = raw_input("Do you wish to quit? (y/n): ")
            if choice.lower().startswith("y"):
                sys.exit(1)
            elif choice.lower().startswith("n"):
                return
            else:
                sys.exit(1)
        
        except Exception, reason:
            print("Exception in call: %s" % (str(reason)))
        return
        
        
############################
#   Extracts remoting methods from SWF    #
############################
    def findRemotingMethods(self, swf):
 
        proc = subprocess.Popen(['./swfdump', '-D',swf,], 
                        shell=False, 
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        )
                        
        stdout_value = proc.communicate()[0]

        m = re.findall("flex.messaging.io",stdout_value)
        if len(m) is 0:
            print "No Remoting Libs found!"
            os._exit(1)


        m = re.findall("endpoint uri=\"http://{server.name}:{server.port}([A-Za-z_/]*)",stdout_value)
        if len(m) > 0:
        #print "##### Gateway URLs #####"
        #print m
            self.gatewaysArray = m    

#m = re.findall("findproperty <q>\[public\]::remObj(.*)",stdout_value)
#if len(m) > 0:
#   services.extend(m)
    
        services = []
        m = re.findall("destination id=\"([\w\d]*)\"",stdout_value)
        if len(m) > 0:
            #print "##### Remoting Services #####"
            services.extend(m)
            services = unique(services)
            #print services
            self.servicesArray = services


        m = re.findall("\[staticprotected]Object}::(.*), \d params",stdout_value)
        if len(m) > 0:
            #print "##### Methods #####"
            methodnames = []
            unique_matches = unique(m)
            for name in unique_matches:
                if(name not in commonfunctions):
         #       print name
                    methodnames.append(name)
            self.methodsArray = methodnames
        #print result.methods


############################
# Returns unique list                                 #
############################
def unique(s):
     """Return a list of the elements in s, but without duplicates.

     For example, unique([1,2,3,1,2,3]) is some permutation of [1,2,3],
     unique("abcabc") some permutation of ["a", "b", "c"], and
     unique(([1, 2], [2, 3], [1, 2])) some permutation of
     [[2, 3], [1, 2]].

     For best speed, all sequence elements should be hashable.  Then
     unique() will usually work in linear time.

     If not possible, the sequence elements should enjoy a total
     ordering, and if list(s).sort() doesn't raise TypeError it's
     assumed that they do enjoy a total ordering.  Then unique() will
     usually work in O(N*log2(N)) time.

     If that's not possible either, the sequence elements must support
     equality-testing.  Then unique() will usually work in quadratic
     time.
     """

     n = len(s)
     if n == 0:
         return []

     # Try using a dict first, as that's the fastest and will usually
     # work.  If it doesn't work, it will usually fail quickly, so it
     # usually doesn't cost much to *try* it.  It requires that all the
     # sequence elements be hashable, and support equality comparison.
     u = {}
     try:
         for x in s:
             u[x] = 1
     except TypeError:
         del u  # move on to the next method
     else:
         return u.keys()

     # We can't hash all the elements.  Second fastest is to sort,
     # which brings the equal elements together; then duplicates are
     # easy to weed out in a single pass.
     # NOTE:  Python's list.sort() was designed to be efficient in the
     # presence of many duplicate elements.  This isn't true of all
     # sort functions in all languages or libraries, so this approach
     # is more effective in Python than it may be elsewhere.
     try:
         t = list(s)
         t.sort()
     except TypeError:
         del t  # move on to the next method
     else:
         assert n > 0
         last = t[0]
         lasti = i = 1
         while i < n:
             if t[i] != last:
                 t[lasti] = last = t[i]
                 lasti += 1
             i += 1
         return t[:lasti]

     # Brute force is all that's left.
     u = []
     for x in s:
         if x not in u:
             u.append(x)
     return u


def banner():
    print """
         .___    __________.__                        
       __| _/____\______   \  | _____  ________ ____  
      / __ |/ __ \|    |  _/  | \__  \ \___   // __ \ 
     / /_/ \  ___/|    |   \  |__/ __ \_/    /\  ___/ 
     \____ |\___  >______  /____(____  /_____ \\___  >
          \/    \/       \/          \/      \/    \/ 
    jrose@owasp.org | jrose@trustwave.com | github.com/SpiderLabs
    """

def parse_params(params):
    """
    Takes a string parameter and splits on '|' and attemps to convert to basic
    types - int, float and string. More complex object notations are not
    accounted for (dicts, lists etc.)

    @return: A list of params converted into their scalar types.
    """
    p = []
    for x in params.split('|'):
        try:
            p.append(int(x))
        except ValueError:
            pass
        else:
            continue

        try:
            p.append(float(x))
        except ValueError:
            pass
        else:
            continue
        p.append(x)
    
    return eval('%s' % (p,))
    

if __name__ == "__main__":
    from optparse import OptionParser
    
    parser = OptionParser(description="A remote enumeration tool for Flex Servers", prog="deblaze", version="0.2", usage="%prog [option]")
    parser.add_option("-u", "--url", help="URL for AMF Gateway", dest="url")
    parser.add_option("-s", "--service", help="Remote service to call")
    parser.add_option("-m", "--method", help="Method to call")
    parser.add_option("-p", "--params", help="Parameters to send pipe seperated 'param1|param2|param3'")
    parser.add_option("-f", "--fullauto", help="URL to SWF - Download SWF, find remoting services, methods,and parameters", dest="swf")
    parser.add_option("--fuzz", help="Fuzz parameter values", action="store_true", dest="fuzz", default=False)
    parser.add_option("-c", "--creds", help="Username and password for service in u:p format", dest="creds")
    parser.add_option("-b", "--cookie", dest="cookie", help="Send cookies with request")
    parser.add_option("-A", "--user-agent", help="User-Agent string to send to the server", dest="useragent")
    parser.add_option("-1", "--bruteService", help="File to load services for brute forcing (mutually exclusive to -s)")
    parser.add_option("-2", "--bruteMethod", help="File to load methods for brute forcing (mutually exclusive to -m)")
    parser.add_option("-d", "--debug", help="Enable pyamf/AMF debugging", action="store_true")
    parser.add_option("-v", "--verbose", help="Print http request/response", action="store_true")
    parser.add_option("-r", "--report", help="Generate HTML report", action="store_true")
    parser.add_option("-n", "--nobanner", help="Do not display banner", action="store_true")
    parser.add_option("-q", "--quiet", help="Do not display messages", action="store_true")

    
    (options, args) = parser.parse_args()
    
    if not options.nobanner:
        banner()
        
    if not options.url and not options.swf:
        parser.print_help()
        sys.exit(1)
        
    if options.debug:
        logging.basicConfig(level=logging.DEBUG, format='%(message)s')
    
    if options.verbose:
        httplib.HTTPConnection.debuglevel  = 1
        httplib.HTTPSConnection.debuglevel = 1
	
    if not options.service and not options.bruteService and not options.swf:
        print("Service or service file required")
        sys.exit(1)
	
    if not options.method and not options.bruteMethod and not options.swf:
        print("Method or method file required")
        sys.exit(1)
    
    if options.params:
        params = parse_params(options.params)
    else:
        params = ""
    
    if options.cookie:
        cookies = options.cookie
    else:
        cookies = None
    
    if options.useragent is not None:
        useragent = options.useragent
    else:
        useragent = 'PyAMF/%s' % '.'.join(map(lambda x: str(x), pyamf.__version__))
        
    if options.swf:
        if not os.path.isfile('swfdump'):
           print "Missing swfdump in current path, please copy for automated mode"
           sys.exit(1)
        swfsplit = options.swf.split('/')
        #print swfsplit[-1]
        url = swfsplit[0] + '//' + swfsplit[2] + '/'
        print "Downloading SWF for analysis: " + options.swf
        
        webFile = urllib.urlopen(options.swf)
        localFile = open(swfsplit[-1], 'w')
        localFile.write(webFile.read())
        webFile.close()
        localFile.close()

        #result = findRemotingMethods(swfsplit[-1])
        print "Running deblaze automated mode"
        bigD = Deblaze()
        bigD.findRemotingMethods(swfsplit[-1])
        bigD.url = url
        bigD.fuzz = options.fuzz
        bigD.auto()
        if options.report:
            buildHTML(bigD.gatewaysArray, bigD.servicesArray, bigD.methodsArray )
        sys.exit(1)
    
    # Run through input file
    if options.bruteService:
        fh = open(options.bruteService, 'r')
        for line in fh:
            line = line.strip()
            d = Deblaze(options.url, line, options.method, options.creds, cookies, useragent, options.fuzz)
            d.run(*params)
        fh.close()
        if options.report:
            buildHTML()
        sys.exit(1)
    elif options.bruteMethod is not None:
        fh = open(options.bruteMethod, 'r')
        for line in fh:
            line = line.strip()
            d = Deblaze(options.url, options.service, line, options.creds, cookies, useragent,  options.fuzz)
            d.run(*params)
        fh.close()
        if options.report:
            buildHTML()
        sys.exit(1)
   
    else:
        d = Deblaze(options.url, options.service, options.method, options.creds, cookies, useragent,  options.fuzz)
        d.run(*params)
        if options.report:
            buildHTML()
        sys.exit(1)

