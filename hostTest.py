import socket

def hasHostname(ip):
  try:
    socket.gethostbyaddr(str(ip))
  except:
    return (False,None)
  return (True,(socket.gethostbyaddr(str(ip))[0]))

