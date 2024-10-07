import pyshark

capture = pyshark.LiveCapture(interface='wlp1s0')
capture.sniff(timeout=1)
print(capture)