def arecomprime(a, N):
	for i in range(2, a+1):
		if a % i == 0 and N % i == 0:
			return False
	return True

def mycoprime(N):
	coprimes = []
	for n in range(2, N):
		if arecomprime(n, N):
			coprimes.append(n)
	return coprimes

print(mycoprime(100))