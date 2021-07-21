import random

#quick pow and avoid big number
def qpow(e,order,n):
    r=1
    while(order):
        if (order & 1):
            r=r*e%n
        e=e*e%n
        order>>=1
    return r

#Meller-Rabin algorithm, times determine the precision
#larger times bring higher precision
def isprime(num1,times):
    #the num of 1,2,3 are all prime
    if(num1<=3 and num1>0):
        return 1
    #any odd num can be presented as num-1=m*2^k
    k=0
    temp=num1-1
    while(temp%2==0):
        temp//=2
        k+=1
    m=temp
    count=1
    rd=0
    res=0
    while(count<=times):
        rd=random.randint(2,num1)
        res=qpow(rd,m,num1)
        #Fermat's Little Theorem
        if(res !=1 and res != num1-1):
            order=1
            while(order<k and res !=num1-1):
                res=res*res%num1
                if(res==1):return 0
                order+=1
            if(res!=num1-1):return 0
        count+=1
    return 1

def generate_prime(bits,times):
    while 1:
        num=random.getrandbits(bits)
        if isprime(num,times):
            return num
        else:
            continue

#public key generator,p and q are 128 bits prime
def pub_key_gen(private_p,private_q):
    public_key=private_p*private_q
    return public_key

#Encryption
def encryption(plaintext,public_key):
    #use '&' to get last 16 bits of plaintext
    #65535=1111111111111111(16 bits)
    temp=plaintext&65535
    plaintext<<=16
    plaintext=plaintext+temp
    ciphertext=qpow(plaintext,2,public_key)
    return ciphertext

#Legendre symbol
def legendre(ciphertext,private_key):
    symbol=qpow(ciphertext,(private_key-1)//2,private_key)
    return symbol

#Find SQROOT
def find_sqr(private_p,ciphertext):
    if(private_p % 4 == 3):
        root=qpow(ciphertext,(private_p+1)//4,private_p)
        return root
    elif(private_p % 8 == 5):
        d = qpow(ciphertext, (private_p - 1) // 4, private_p)
        if(d==1):
            root=qpow(ciphertext, (private_p + 3) // 8, private_p)
        if (d == -1):
            root = 2*ciphertext*qpow(4*ciphertext, (private_p - 5) // 8, private_p)%private_p
        return root

def choose(lst):
     for i in lst:
        binary = bin(i)
        append = binary[-16:]   # take the last 16 bits
        binary = binary[:-16]   # remove the last 16 bits
        if append == binary[-16:]:
            return i
     return

def egcd(private_p, private_q):
    if private_p == 0:
        return private_q, 0, 1
    else:
        gcd, y, x = egcd(private_q % private_p, private_p)
        return gcd, x - (private_q // private_p) * y, y

def decryption(ciphertext, private_p, private_q):
    public_key=pub_key_gen(private_p,private_q)
    r,s=0,0
    r=find_sqr(private_p,ciphertext)
    s=find_sqr(private_q,ciphertext)
    gcd,c,d=egcd(private_p,private_q)

    x = (r * d * private_q + s * c * private_p) % public_key
    y = (r * d * private_q - s * c * private_p) % public_key
    lst = [x, public_key - x, y, public_key - y]
    plaintext = choose(lst)
    string = bin(plaintext)
    string = string[:-16]
    plaintext = int(string, 2)
    return plaintext

def delete_space(string):
    lst = string.split(' ')
    output = ''
    for i in lst:
        output += i
    return output

def add_space(string):
    string = string[::-1]
    string = ' '.join(string[i:i + 8] for i in range(0, len(string), 8))
    return string[::-1]

if __name__=='__main__':
    print('<Miller-Rabin>')
    print(add_space(format(generate_prime(256,20), 'x')))

    print('\n<Rabin Encryption>')
    p = int(delete_space(input('p = ')), 16)  # p = daaefe652cad1614f17e87f2cd80973f
    q = int(delete_space(input('q = ')), 16)  # q = f99988626723eef2a54ed484dfa735c7
    public_key=pub_key_gen(p,q)
    print('n = pq =', add_space(format(public_key, 'x')))
    # plaintext = be000badbebadbadbad00debdeadfacedeafbeefadd00addbed00bed
    plaintext = int(delete_space(input('Plaintext = ')),16)
    ciphertext = encryption(plaintext, public_key)
    print('Ciphertext =', add_space(format(ciphertext, 'x')))

    print('\n<Rabin Decryption>')
    ciphertext = int(delete_space(input('Ciphertext = ')), 16)
    print('Private Keys :')
    p = int(delete_space(input('p = ')), 16)  # 0xd5e68b2b5855059ad1a80dd6c5dc03eb
    q = int(delete_space(input('q = ')), 16)  # 0xc96c6afc57ce0f53396d3b32049fe2d3
    plaintext = decryption(ciphertext, p, q)
    print('Plaintext =', add_space(format(plaintext, 'x').zfill(226 // 4)))









