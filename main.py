from flask import Flask, request
import requests, rsa, threading, json, logging

#simple rsa functions
def generate_keys():
    public_key, private_key = rsa.newkeys(1024)
    return [public_key,private_key]
def encrypt(message, public_key):
    return rsa.encrypt(message.encode(), public_key)
def decrypt(message, private_key):
    return rsa.decrypt(message, private_key).decode()

app = Flask(__name__)


def main():
    choice = input("generate new keyset? (y/n):")
    
    if choice.lower() == "y":
        #create new keyset
        keys = generate_keys()
        with open("public.pem", "wb") as file:
            file.write(keys[0].save_pkcs1("PEM"))
            file.close()
        with open("private.pem", "wb") as file:
            file.write(keys[1].save_pkcs1("PEM"))
            file.close()

    #read the keys from the files
    with open("public.pem", "rb") as file:
        public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    with open("private.pem", "rb") as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())
        file.close()

    server = input("url or ip of the recieving client:")
    while True:
        #get your private key
        with open("private.pem", "rb") as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read())
            file.close()

        #get the message from the user
        message = input("message to send:")
        public_key = rsa.PublicKey.load_pkcs1(requests.get(server + "/getKey").text)
       
        #create and save the signature
        signature = rsa.sign(message.encode(), private_key, 'SHA-512')
        with open("signature", "wb") as file:
            file.write(signature)
            file.close()

        #save encrypted message
        message = encrypt(message, public_key)
        with open("message", "wb") as file:
            file.write(message)
            file.close()

        
        
        
        files = {
                'message': open('message','rb'),
                'signature': open('signature','rb'),
                'public key': open('public.pem','rb')
                }
        requests.post(server + "/recv", files=files)

        


main = threading.Thread(target=main)
main.start()


@app.route('/getKey')
def getKey():
    with open("public.pem", "rb") as file:
        public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    return public_key.save_pkcs1("PEM")

@app.route('/recv', methods=["POST"])
def recv():
    #save the files
    messageFile = request.files["message"]
    signatureFile = request.files["signature"]
    pubKeyFile = request.files["public key"]
    messageFile.save("message")
    signatureFile.save("signature")
    pubKeyFile.save("recv-public.pem")

    #decrypt the message
    with open("private.pem", "rb") as file:
        private_key = rsa.PrivateKey.load_pkcs1(file.read())
        file.close()
    with open("message", "rb") as file:
        message = decrypt(file.read(), private_key)
        file.close()

    #check the signature
    with open("signature", "rb") as file:
        signature = file.read()
        file.close()
    with open("recv-public.pem", "rb") as file:
        recieved_public_key = rsa.PublicKey.load_pkcs1(file.read())
        file.close()
    if rsa.verify(message.encode(), signature, recieved_public_key) == "SHA-512":
        #write the message to messages.log
        with open("messages.log", "a") as file:
            file.write(message + "\n")
            file.close()
        return "success"
    else:
        print("fail")
        return "fail"

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=80)
